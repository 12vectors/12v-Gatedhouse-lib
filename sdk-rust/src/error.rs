// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Error types. One enum per concern, plus a top-level `GatedhouseError`
//! aggregating the unified runtime failures.

use std::fmt;

/// Top-level error for any Gatedhouse-raised failure that isn't a
/// token-verification failure (those carry their own [`Reason`] enum).
#[derive(Debug)]
pub enum GatedhouseError {
    /// Construction of a Gatedhouse instance failed (schema check,
    /// GroupSource startup, etc.).
    Initialization(String),

    /// A database operation failed. [`kind`](DatabaseErrorKind) says how,
    /// so a host can tell "the database is unavailable, try again later"
    /// ([`DatabaseErrorKind::Unavailable`], typically answered with HTTP
    /// 503) apart from a statement the database refused
    /// ([`DatabaseErrorKind::Query`]).
    ///
    /// An authorization check that ends in this error has not granted
    /// anything: callers must treat it as a failure, never as "allowed".
    Database {
        kind: DatabaseErrorKind,
        message: String,
    },

    /// The target database has no `gatedhouse` schema. Run the migration.
    SchemaNotInitialized,

    /// The schema is at a version older than this library expects.
    SchemaOutOfDate {
        current_version: i32,
        expected_version: i32,
    },
    /// The requested change is not allowed from the current state, e.g.
    /// suspending a removed membership. The analog of Java's
    /// `IllegalStateException`.
    InvalidTransition(String),
    /// The arguments describe a change the model forbids, e.g. a role
    /// inheritance edge that would create a cycle. The analog of Java's
    /// `IllegalArgumentException`.
    InvalidArgument(String),
}

impl fmt::Display for GatedhouseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatedhouseError::Initialization(msg) => {
                write!(f, "Gatedhouse initialization failed: {msg}")
            }
            GatedhouseError::Database { message, .. } => {
                write!(f, "Gatedhouse database error: {message}")
            }
            GatedhouseError::InvalidTransition(msg) => write!(f, "Invalid transition: {msg}"),
            GatedhouseError::InvalidArgument(msg) => write!(f, "Invalid argument: {msg}"),
            GatedhouseError::SchemaNotInitialized => write!(
                f,
                "Gatedhouse schema is not initialized in the target database.\n\n\
                 Run the migration tool against the same database, e.g.:\n\
                 \x20   cargo run --bin gatedhouse-migrate -- <conninfo>\n\n\
                 Or, from your application's bootstrap:\n\
                 \x20   GatedhouseFactory::migrate(&config)?;"
            ),
            GatedhouseError::SchemaOutOfDate {
                current_version,
                expected_version,
            } => write!(
                f,
                "Gatedhouse schema is at version {current_version} but this \
                 library requires version {expected_version}.\n\n\
                 Run the migration tool to upgrade:\n\
                 \x20   cargo run --bin gatedhouse-migrate -- <conninfo>\n\n\
                 Or, from your application's bootstrap:\n\
                 \x20   GatedhouseFactory::migrate(&config)?;"
            ),
        }
    }
}

impl std::error::Error for GatedhouseError {}

/// How a database operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatabaseErrorKind {
    /// No usable connection: the pool timed out handing one out, the
    /// database could not be reached, or the connection was lost or shut
    /// down mid-operation.
    Unavailable,
    /// The database was reached, but refused or failed the statement.
    Query,
}

impl GatedhouseError {
    /// A [`DatabaseErrorKind::Query`] failure with this message.
    pub(crate) fn query(message: impl Into<String>) -> Self {
        GatedhouseError::Database {
            kind: DatabaseErrorKind::Query,
            message: message.into(),
        }
    }

    /// The database error's kind, if this is a database error.
    pub fn database_kind(&self) -> Option<DatabaseErrorKind> {
        match self {
            GatedhouseError::Database { kind, .. } => Some(*kind),
            _ => None,
        }
    }
}

/// Classifies a `postgres::Error`. Transient conditions are `Unavailable`:
/// SQLSTATE class 08 (connection exception), class 53 (insufficient
/// resources), 57014 (statement timeout or cancellation), 57P01-57P03 (server
/// shut down), and a client-side failure with no SQLSTATE that closed the
/// connection or came from the socket. Anything else is the statement
/// failing. The message keeps the SQLSTATE and the server's text.
impl From<postgres::Error> for GatedhouseError {
    fn from(e: postgres::Error) -> Self {
        let unavailable = match e.code() {
            Some(code) => {
                let code = code.code();
                code.starts_with("08")
                    || code.starts_with("53")
                    || matches!(code, "57014" | "57P01" | "57P02" | "57P03")
            }
            None => {
                e.is_closed()
                    || std::error::Error::source(&e)
                        .is_some_and(|s| s.downcast_ref::<std::io::Error>().is_some())
            }
        };
        let message = match e.as_db_error() {
            Some(db) => format!("{} ({}): {}", e, db.code().code(), db.message()),
            None => e.to_string(),
        };
        GatedhouseError::Database {
            kind: if unavailable {
                DatabaseErrorKind::Unavailable
            } else {
                DatabaseErrorKind::Query
            },
            message,
        }
    }
}

/// Reasons a JWT verification can fail. Surface this to the caller so
/// they can branch — token expired (refresh) vs. forged (reject) vs.
/// JWKS unreachable (retry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenVerificationReason {
    /// `exp` is in the past, or absent. Caller should refresh or
    /// redirect the user back to SSO.
    Expired,

    /// `nbf` is in the future. Token not valid yet — clock skew?
    NotYetValid,

    /// Cryptographic signature did not verify. Token was tampered with
    /// or signed by an unknown party. Reject and log.
    InvalidSignature,

    /// `iss` did not match the configured issuer. Wrong source.
    InvalidIssuer,

    /// `aud` did not include the configured audience. Token was not
    /// issued for this application.
    InvalidAudience,

    /// Token is structurally malformed.
    Malformed,

    /// Header `kid` did not match any key in the issuer's JWKS, even
    /// after a refresh.
    UnknownKey,

    /// Could not reach the JWKS endpoint. Transient infra error.
    JwksUnavailable,

    /// Verification failed for an unexpected reason; see message.
    Other,
}

impl TokenVerificationReason {
    /// The stable code sent to clients (`"expired"`, `"invalid_signature"`,
    /// ...), identical to the Java and Python SDKs.
    pub fn code(&self) -> &'static str {
        match self {
            TokenVerificationReason::Expired => "expired",
            TokenVerificationReason::NotYetValid => "not_yet_valid",
            TokenVerificationReason::InvalidSignature => "invalid_signature",
            TokenVerificationReason::InvalidIssuer => "invalid_issuer",
            TokenVerificationReason::InvalidAudience => "invalid_audience",
            TokenVerificationReason::Malformed => "malformed",
            TokenVerificationReason::UnknownKey => "unknown_key",
            TokenVerificationReason::JwksUnavailable => "jwks_unavailable",
            TokenVerificationReason::Other => "other",
        }
    }
}

#[derive(Debug)]
pub struct TokenVerificationError {
    pub reason: TokenVerificationReason,
    pub message: String,
}

impl TokenVerificationError {
    pub(crate) fn new(reason: TokenVerificationReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

impl fmt::Display for TokenVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenVerification[{:?}]: {}", self.reason, self.message)
    }
}

impl std::error::Error for TokenVerificationError {}
