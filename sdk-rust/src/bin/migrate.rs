// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Standalone migration runner.
//!
//! Usage:
//!     cargo run --bin gatedhouse-migrate -- <conninfo>

use std::process::ExitCode;
use std::sync::Arc;

use gatedhouse::{ConninfoDatabase, Database, GatedhouseConfig, GatedhouseFactory};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        eprintln!(
            "Usage: gatedhouse-migrate <conninfo>\n\n\
             Example:\n\
             \x20   gatedhouse-migrate 'host=localhost user=postgres password=secret dbname=mydb'"
        );
        return ExitCode::from(2);
    }

    let database: Arc<dyn Database> = Arc::new(ConninfoDatabase::new(&args[0]));
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
