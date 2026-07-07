//! Standalone migration runner.
//!
//! Usage:
//!     DATABASE_URL='host=... user=... password=... dbname=...' \
//!         cargo run --bin gatedhouse-migrate

use std::process::ExitCode;
use std::sync::Arc;

use gatedhouse::{ConninfoDatabase, Database, GatedhouseConfig, GatedhouseFactory};

fn main() -> ExitCode {
    let conninfo = match std::env::var("DATABASE_URL") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!(
                "Set DATABASE_URL to the Postgres conninfo, e.g. \
                 DATABASE_URL='host=... user=... password=... dbname=...'"
            );
            return ExitCode::from(2);
        }
    };

    let database: Arc<dyn Database> = Arc::new(ConninfoDatabase::new(&conninfo));
    let config = GatedhouseConfig::builder(database).build();

    match GatedhouseFactory::migrate(&config) {
        Ok(()) => {
            println!("Gatedhouse migration completed successfully.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Gatedhouse migration failed: {e}");
            ExitCode::FAILURE
        }
    }
}
