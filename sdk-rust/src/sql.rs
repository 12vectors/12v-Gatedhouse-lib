// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! The only way library code touches the database. Mirrors the Java `Sql`
//! helper: every operation borrows exactly one connection through here, so
//! the connection contract holds in one place.
//!
//! * **Borrow and return.** The handle is dropped on every path, which
//!   returns the connection.
//! * **We own our commits.** Writes run in one explicit transaction that
//!   commits only if the work completes; dropping it on any error rolls
//!   back.
//! * **Typed failures.** A failed borrow is
//!   [`DatabaseErrorKind::Unavailable`].
//!
//! Library code never holds two connections at once, so a pool of size 1
//! cannot deadlock.

use postgres::{IsolationLevel, Transaction};

use crate::database::{Database, PooledClient};
use crate::error::{DatabaseErrorKind, GatedhouseError};

/// Borrows a connection for read-only work. `postgres` clients always run
/// in autocommit, so reads need no transaction.
pub(crate) fn borrow(database: &dyn Database, op: &str) -> Result<PooledClient, GatedhouseError> {
    database
        .connection()
        .map_err(|e| GatedhouseError::Database {
            kind: DatabaseErrorKind::Unavailable,
            message: format!("{op} failed: could not obtain a database connection: {e}"),
        })
}

/// Runs work in one explicit READ COMMITTED transaction that commits only if
/// the work completes. Locking in library code (row locks, advisory locks)
/// is reasoned about under READ COMMITTED, so the level is set explicitly
/// rather than inherited from the session default.
pub(crate) fn write<T>(
    database: &dyn Database,
    op: &str,
    work: impl FnOnce(&mut Transaction<'_>) -> Result<T, GatedhouseError>,
) -> Result<T, GatedhouseError> {
    let mut conn = borrow(database, op)?;
    let mut tx = conn
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()?;
    let result = work(&mut tx)?; // on error, dropping `tx` rolls back
    tx.commit()?;
    Ok(result)
}
