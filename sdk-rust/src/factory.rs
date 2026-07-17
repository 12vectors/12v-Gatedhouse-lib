//! Static factory mirroring Java's `GatedhouseFactory`.

use std::sync::Arc;

use crate::config::GatedhouseConfig;
use crate::error::GatedhouseError;
use crate::gatedhouse::{DefaultGatedhouse, Gatedhouse};
use crate::just_token_verifier::JustTokenVerifierGatedhouse;
use crate::migrator;
use crate::schema_check;
use crate::token_verifier::TokenVerifierConfig;

pub struct GatedhouseFactory;

impl GatedhouseFactory {
    /// Verify the schema is current and construct a [`Gatedhouse`].
    /// Returns an `Arc<dyn Gatedhouse>` so the host can clone it across
    /// threads without thinking about lifetimes.
    pub fn create(config: GatedhouseConfig) -> Result<Arc<dyn Gatedhouse>, GatedhouseError> {
        schema_check::verify(config.database.as_ref())?;

        let group_source = config.group_source.clone();
        let gatedhouse = Arc::new(DefaultGatedhouse::new(config));
        // GroupSource may want to capture a reference to Gatedhouse; pass
        // the trait object so it has the public surface.
        group_source.start(gatedhouse.as_ref() as &dyn Gatedhouse);

        Ok(gatedhouse as Arc<dyn Gatedhouse>)
    }

    /// Creates a lightweight Gatedhouse instance that only supports token
    /// verification and requires no database backend.
    ///
    /// Every database-backed method on the returned handle panics with
    /// "Database operations not supported on token-verifier-only
    /// instance" — the analog of Java's `UnsupportedOperationException`.
    pub fn create_just_token_verifier(config: TokenVerifierConfig) -> Arc<dyn Gatedhouse> {
        Arc::new(JustTokenVerifierGatedhouse::new(&config))
    }

    /// Run any pending migrations against the configured database. Safe
    /// to invoke concurrently from multiple processes — the runner takes
    /// a Postgres advisory lock.
    pub fn migrate(config: &GatedhouseConfig) -> Result<(), GatedhouseError> {
        migrator::migrate(config.database.as_ref())
    }
}
