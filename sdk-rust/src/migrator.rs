//! Tiny migration runner. Reads V###__name.sql files embedded at compile
//! time, tracks applied versions in `gatedhouse.schema_versions`, applies
//! pending migrations under a Postgres advisory lock so concurrent
//! instances don't race.

use std::collections::HashSet;

use postgres::Client;

use crate::database::Database;
use crate::error::GatedhouseError;

// Stable but arbitrary; matches the Java side so the lock is shared if
// both languages are pointed at the same database.
const ADVISORY_LOCK_KEY: i64 = 0x6761746564686F75; // 'gatedhou'

const MIGRATIONS_INDEX: &str = include_str!("migrations/migrations.txt");
const V001_SQL: &str = include_str!("migrations/V001__init.sql");

struct Migration {
    version: i32,
    name: &'static str,
    sql: &'static str,
    checksum: String,
}

pub fn migrate(database: &dyn Database) -> Result<(), GatedhouseError> {
    let migrations = available_migrations()?;

    let mut conn = database.connection()?;
    acquire_lock(&mut conn)?;
    let lock_result = (|| -> Result<(), GatedhouseError> {
        ensure_bookkeeping(&mut conn)?;
        let applied = applied_versions(&mut conn)?;
        for migration in migrations {
            if applied.contains(&migration.version) {
                continue;
            }
            apply(&mut conn, &migration)?;
        }
        Ok(())
    })();
    let release_result = release_lock(&mut conn);
    lock_result?;
    release_result?;
    Ok(())
}

fn available_migrations() -> Result<Vec<Migration>, GatedhouseError> {
    let mut out: Vec<Migration> = Vec::new();
    for raw in MIGRATIONS_INDEX.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (version, name, sql) = match line {
            "V001__init.sql" => (1, "init", V001_SQL),
            other => {
                return Err(GatedhouseError::Initialization(format!(
                    "Unknown migration filename in index: {other:?}. \
                     Add it as an `include_str!` constant in src/migrator.rs."
                )));
            }
        };
        let checksum = fnv1a_hex(sql);
        out.push(Migration {
            version,
            name,
            sql,
            checksum,
        });
    }
    out.sort_by_key(|m| m.version);
    Ok(out)
}

fn acquire_lock(conn: &mut Client) -> Result<(), GatedhouseError> {
    conn.execute("SELECT pg_advisory_lock($1)", &[&ADVISORY_LOCK_KEY])?;
    Ok(())
}

fn release_lock(conn: &mut Client) -> Result<(), GatedhouseError> {
    conn.execute("SELECT pg_advisory_unlock($1)", &[&ADVISORY_LOCK_KEY])?;
    Ok(())
}

fn ensure_bookkeeping(conn: &mut Client) -> Result<(), GatedhouseError> {
    conn.batch_execute(
        "CREATE SCHEMA IF NOT EXISTS gatedhouse; \
         CREATE TABLE IF NOT EXISTS gatedhouse.schema_versions ( \
             version    INTEGER PRIMARY KEY, \
             name       TEXT NOT NULL, \
             checksum   TEXT NOT NULL, \
             applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW() \
         );",
    )?;
    Ok(())
}

fn applied_versions(conn: &mut Client) -> Result<HashSet<i32>, GatedhouseError> {
    let rows = conn.query("SELECT version FROM gatedhouse.schema_versions", &[])?;
    Ok(rows.into_iter().map(|r| r.get::<_, i32>(0)).collect())
}

fn apply(conn: &mut Client, migration: &Migration) -> Result<(), GatedhouseError> {
    let mut tx = conn.transaction()?;
    tx.batch_execute(migration.sql)?;
    tx.execute(
        "INSERT INTO gatedhouse.schema_versions (version, name, checksum) \
         VALUES ($1, $2, $3)",
        &[&migration.version, &migration.name, &migration.checksum],
    )?;
    tx.commit()?;
    Ok(())
}

// Tiny hand-rolled SHA-256 hex via the `sha2` crate would add another
// dep; instead, lean on jsonwebtoken's transitive `ring` to avoid
// adding anything. ring exposes `digest::SHA256`. But that's a
// fragile assumption — easier and dep-free to use a minimal hash.
//
// For the migration runner the checksum is recorded for human / future
// diagnostic use, not enforced cryptographically against tampering.
// A non-cryptographic FxHash would be enough; we use a simple hex of
// FNV-1a 64-bit to avoid any extra dep.
fn fnv1a_hex(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{h:016x}")
}
