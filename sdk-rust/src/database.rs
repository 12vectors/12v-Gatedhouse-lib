//! Database access abstraction.
//!
//! Mirrors the Java `Database` functional interface: a single method
//! that returns a fresh connection. The library does not bundle a
//! connection pool; hosts plug their own (e.g. `r2d2-postgres`,
//! `deadpool-postgres`) by implementing this trait.

use postgres::{Client, Error, NoTls};

/// Connection factory used by every Gatedhouse manager. Implementations
/// must be safe to share across threads.
pub trait Database: Send + Sync {
    /// Return a fresh connection, ready to use. Callers consume the
    /// `Client` for one unit of work and drop it when done.
    fn connection(&self) -> Result<Client, Error>;
}

/// Convenience implementation: each call to `connection()` opens a
/// fresh psql connection using the supplied conninfo string with
/// `NoTls`. Suitable for scripts and tests; production hosts that need
/// pooling or TLS plug their own implementation.
pub struct ConninfoDatabase {
    conninfo: String,
}

impl ConninfoDatabase {
    pub fn new(conninfo: impl Into<String>) -> Self {
        Self {
            conninfo: conninfo.into(),
        }
    }
}

impl Database for ConninfoDatabase {
    fn connection(&self) -> Result<Client, Error> {
        Client::connect(&self.conninfo, NoTls)
    }
}
