//! Schema-version check executed by `GatedhouseFactory::create`.

use crate::database::Database;
use crate::error::GatedhouseError;

pub(crate) const EXPECTED_VERSION: i32 = 1;

pub(crate) fn verify(database: &dyn Database) -> Result<(), GatedhouseError> {
    let mut conn = database.connection()?;
    let row = conn.query_opt(
        "SELECT 1 FROM information_schema.tables \
         WHERE table_schema = 'gatedhouse' AND table_name = 'schema_versions'",
        &[],
    )?;
    if row.is_none() {
        return Err(GatedhouseError::SchemaNotInitialized);
    }
    let row = conn.query_one(
        "SELECT COALESCE(MAX(version), 0) FROM gatedhouse.schema_versions",
        &[],
    )?;
    let current: i32 = row.get(0);
    if current < EXPECTED_VERSION {
        return Err(GatedhouseError::SchemaOutOfDate {
            current_version: current,
            expected_version: EXPECTED_VERSION,
        });
    }
    Ok(())
}
