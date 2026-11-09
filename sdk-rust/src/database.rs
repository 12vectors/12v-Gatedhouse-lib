// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Where Gatedhouse gets its database connections.
//!
//! Mirrors the Java `Database`. Gatedhouse borrows one connection per
//! operation, never holds two at once, and drops the handle when the
//! operation ends, which returns the connection to the host's pool.
//!
//! Ways to provide one, in order of preference for production:
//!
//! 1. Your application's `r2d2` pool, with the `r2d2` cargo feature:
//!    `Arc::new(pool.clone())` is a [`Database`]. Gatedhouse then opens no
//!    connections of its own.
//! 2. Any other pool, through [`from_fn`]: a closure that borrows a
//!    connection and returns its handle boxed as a [`PooledClient`].
//! 3. [`PooledDatabase::from_url`] (`r2d2` feature): Gatedhouse runs its own
//!    pool. Recommended for development and staging.
//!
//! Whatever the source, Gatedhouse commits or rolls back its own work.
//! `postgres`'s API cannot lend out a `Client` that is mid-transaction (a
//! `Transaction` borrows the client and rolls back when dropped), so the
//! "never someone else's transaction" rule of the Java and Python SDKs holds
//! by construction, unless a host issues a raw `BEGIN` and returns the
//! client to its pool, which nothing can detect.

use std::error::Error as StdError;
use std::ops::{Deref, DerefMut};

use postgres::Client;

/// A borrowed connection: anything that dereferences to a `Client`, such
/// as a pool's handle. Dropping it gives the connection back.
pub type PooledClient = Box<dyn DerefMut<Target = Client> + Send>;

/// Why no connection could be borrowed (pool timeout, database
/// unreachable, ...). Reported as [`DatabaseErrorKind::Unavailable`].
///
/// [`DatabaseErrorKind::Unavailable`]: crate::DatabaseErrorKind::Unavailable
pub type ConnectionError = Box<dyn StdError + Send + Sync>;

/// Connection source used by every Gatedhouse manager. Implementations
/// must be safe to share across threads.
pub trait Database: Send + Sync {
    /// Borrow a connection for one unit of work. Gatedhouse drops the
    /// handle when the unit of work ends. Must not hand the same connection
    /// to two callers at the same time.
    fn connection(&self) -> Result<PooledClient, ConnectionError>;
}

/// A `Client` the caller owns outright, as a [`PooledClient`]. Dropping it
/// closes the connection.
pub struct OwnedClient(pub Client);

impl Deref for OwnedClient {
    type Target = Client;
    fn deref(&self) -> &Client {
        &self.0
    }
}

impl DerefMut for OwnedClient {
    fn deref_mut(&mut self) -> &mut Client {
        &mut self.0
    }
}

/// A [`Database`] backed by a closure, for pools without built-in support:
///
/// ```ignore
/// let db = gatedhouse::database::from_fn(move || {
///     let handle = my_pool.get()?;          // derefs to postgres::Client
///     Ok(Box::new(handle) as PooledClient)
/// });
/// ```
pub fn from_fn<F>(f: F) -> FnDatabase<F>
where
    F: Fn() -> Result<PooledClient, ConnectionError> + Send + Sync,
{
    FnDatabase(f)
}

/// See [`from_fn`].
pub struct FnDatabase<F>(F);

impl<F> Database for FnDatabase<F>
where
    F: Fn() -> Result<PooledClient, ConnectionError> + Send + Sync,
{
    fn connection(&self) -> Result<PooledClient, ConnectionError> {
        (self.0)()
    }
}

#[cfg(feature = "r2d2")]
pub use self::pooled::{PoolSettings, PooledDatabase};

#[cfg(feature = "r2d2")]
mod pooled {
    use std::time::Duration;

    use postgres::tls::{MakeTlsConnect, TlsConnect};
    use postgres::{NoTls, Socket};
    use r2d2_postgres::PostgresConnectionManager;

    use super::{ConnectionError, Database, PooledClient};
    use crate::GatedhouseError;

    /// The host's `r2d2` pool is a [`Database`]: `Arc::new(pool.clone())`.
    impl<T> Database for r2d2::Pool<PostgresConnectionManager<T>>
    where
        T: MakeTlsConnect<Socket> + Clone + 'static + Sync + Send,
        T::TlsConnect: Send,
        T::Stream: Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        fn connection(&self) -> Result<PooledClient, ConnectionError> {
            Ok(Box::new(self.get()?))
        }
    }

    /// Settings for [`PooledDatabase`]. Every value has a default.
    #[derive(Debug, Clone)]
    pub struct PoolSettings {
        max_size: u32,
        connection_timeout: Duration,
        max_lifetime: Duration,
    }

    impl PoolSettings {
        /// Default [`max_size`](Self::max_size): 10 connections.
        pub const DEFAULT_MAX_SIZE: u32 = 10;
        /// Default [`connection_timeout`](Self::connection_timeout): 10 seconds.
        pub const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
        /// Default [`max_lifetime`](Self::max_lifetime): 30 minutes.
        pub const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);

        /// Most connections the pool opens.
        ///
        /// # Panics
        /// If `size` is zero.
        pub fn with_max_size(mut self, size: u32) -> Self {
            assert!(size >= 1, "max_size must be at least 1");
            self.max_size = size;
            self
        }

        /// Longest an operation waits for a free connection before failing
        /// with [`DatabaseErrorKind::Unavailable`](crate::DatabaseErrorKind::Unavailable).
        ///
        /// # Panics
        /// If `timeout` is under 250 ms.
        pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
            assert!(
                timeout >= Duration::from_millis(250),
                "connection_timeout must be at least 250 ms"
            );
            self.connection_timeout = timeout;
            self
        }

        /// Connections older than this are retired and replaced.
        ///
        /// # Panics
        /// If `lifetime` is under 30 seconds.
        pub fn with_max_lifetime(mut self, lifetime: Duration) -> Self {
            assert!(
                lifetime >= Duration::from_secs(30),
                "max_lifetime must be at least 30 seconds"
            );
            self.max_lifetime = lifetime;
            self
        }

        pub fn max_size(&self) -> u32 {
            self.max_size
        }

        pub fn connection_timeout(&self) -> Duration {
            self.connection_timeout
        }

        pub fn max_lifetime(&self) -> Duration {
            self.max_lifetime
        }
    }

    impl Default for PoolSettings {
        fn default() -> Self {
            Self {
                max_size: Self::DEFAULT_MAX_SIZE,
                connection_timeout: Self::DEFAULT_CONNECTION_TIMEOUT,
                max_lifetime: Self::DEFAULT_MAX_LIFETIME,
            }
        }
    }

    /// A connection pool owned by Gatedhouse (`r2d2`). Recommended for
    /// development and staging; in production, prefer your application's
    /// own pool, so one pool is sized and monitored against the database's
    /// connection limit.
    ///
    /// The pool closes when the last handle to it is dropped. Gatedhouse
    /// holds it through the config's `Arc<dyn Database>`.
    pub struct PooledDatabase {
        pool: Box<dyn Database>,
    }

    impl PooledDatabase {
        /// A pool with [`PoolSettings::default`] and no TLS.
        pub fn from_url(conninfo: &str) -> Result<Self, GatedhouseError> {
            Self::from_url_with(conninfo, PoolSettings::default())
        }

        /// A pool with explicit settings and no TLS.
        pub fn from_url_with(conninfo: &str, settings: PoolSettings) -> Result<Self, GatedhouseError> {
            Self::from_url_with_tls(conninfo, NoTls, settings)
        }

        /// A pool connecting through the given TLS connector (for example
        /// `postgres-native-tls` or `postgres-openssl`, added by the host).
        pub fn from_url_with_tls<T>(
            conninfo: &str,
            tls: T,
            settings: PoolSettings,
        ) -> Result<Self, GatedhouseError>
        where
            T: MakeTlsConnect<Socket> + Clone + 'static + Sync + Send,
            T::TlsConnect: Send,
            T::Stream: Send,
            <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
        {
            let config: postgres::Config = conninfo.parse().map_err(|e| {
                GatedhouseError::Initialization(format!("invalid connection string: {e}"))
            })?;
            let manager = PostgresConnectionManager::new(config, tls);
            // build_unchecked: creating the pool must not fail just because
            // the database is briefly unreachable; the first operation
            // reports it.
            let pool = r2d2::Pool::builder()
                .max_size(settings.max_size)
                .min_idle(Some(1))
                .connection_timeout(settings.connection_timeout)
                .max_lifetime(Some(settings.max_lifetime))
                .test_on_check_out(true)
                .error_handler(Box::new(r2d2::NopErrorHandler))
                .build_unchecked(manager);
            Ok(Self { pool: Box::new(pool) })
        }
    }

    impl Database for PooledDatabase {
        fn connection(&self) -> Result<PooledClient, ConnectionError> {
            self.pool.connection()
        }
    }
}
