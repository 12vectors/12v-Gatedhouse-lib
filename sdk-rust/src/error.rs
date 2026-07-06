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

    /// Wraps a `postgres::Error` raised during a Gatedhouse method.
    Database(String),

    /// The target database has no `gatedhouse` schema. Run the migration.
    SchemaNotInitialized,

    /// The schema is at a version older than this library expects.
    SchemaOutOfDate {
        current_version: i32,
        expected_version: i32,
    },
}

impl fmt::Display for GatedhouseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatedhouseError::Initialization(msg) => {
                write!(f, "Gatedhouse initialization failed: {msg}")
            }
            GatedhouseError::Database(msg) => write!(f, "Gatedhouse database error: {msg}"),
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

impl From<postgres::Error> for GatedhouseError {
    fn from(e: postgres::Error) -> Self {
        GatedhouseError::Database(e.to_string())
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

/// Failure of a Sphinx OAuth call (see `SphinxClient`).
#[derive(Debug)]
pub enum SphinxError {
    /// Transport/network failure reaching Sphinx.
    Http(String),
    /// A non-200 response. `oauth_error` is only the standardized OAuth
    /// `error` code — never the raw body (which may carry tokens).
    Status { status: u16, oauth_error: String },
    /// The 200 response body could not be parsed.
    Parse(String),
}

impl fmt::Display for SphinxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SphinxError::Http(m) => write!(f, "Sphinx request failed: {m}"),
            SphinxError::Status { status, oauth_error } => {
                write!(f, "Sphinx request failed ({status}): {oauth_error}")
            }
            SphinxError::Parse(m) => write!(f, "Sphinx response parse failed: {m}"),
        }
    }
}

impl std::error::Error for SphinxError {}

/// The callback could not be tied to the browser that started the login
/// (missing/forged PKCE cookie, or a missing authorization code). Mirrors the
/// Java `LoginCsrfException` — the injected foreign code is rejected before any
/// identity is adopted.
#[derive(Debug)]
pub struct LoginCsrfError {
    pub message: String,
}

impl fmt::Display for LoginCsrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "login CSRF check failed: {}", self.message)
    }
}

impl std::error::Error for LoginCsrfError {}

/// Failure of `LoginFlow::complete_login`: either the browser-binding check
/// failed ([`LoginCsrfError`]) or the underlying code exchange did ([`SphinxError`]).
#[derive(Debug)]
pub enum LoginError {
    Csrf(LoginCsrfError),
    Exchange(SphinxError),
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginError::Csrf(e) => write!(f, "{e}"),
            LoginError::Exchange(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LoginError {}
