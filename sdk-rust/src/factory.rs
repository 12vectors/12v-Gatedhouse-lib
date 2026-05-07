//! Static factory mirroring Java's `GatedhouseFactory`.

use std::sync::Arc;

use crate::config::GatedhouseConfig;
use crate::error::GatedhouseError;
use crate::gatedhouse::{DefaultGatedhouse, Gatedhouse};
use crate::migrator;
use crate::schema_check;

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

    /// Run any pending migrations against the configured database. Safe
    /// to invoke concurrently from multiple processes — the runner takes
    /// a Postgres advisory lock.
    pub fn migrate(config: &GatedhouseConfig) -> Result<(), GatedhouseError> {
        migrator::migrate(config.database.as_ref())
    }
}
