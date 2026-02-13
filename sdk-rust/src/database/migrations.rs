//! Database migration runner.

use std::path::Path;
use tracing::info;

use crate::database::connection::DatabaseConnection;

pub struct MigrationRunner<'a> {
    db: &'a DatabaseConnection,
    table: String,
}

impl<'a> MigrationRunner<'a> {
    pub fn new(db: &'a DatabaseConnection, table: &str) -> Self {
        Self {
            db,
            table: table.to_string(),
        }
    }

    pub async fn ensure_table(&self) -> Result<(), sqlx::Error> {
        let query = format!(
            "CREATE TABLE IF NOT EXISTS {} (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                applied_at TIMESTAMPTZ DEFAULT NOW()
            )",
            self.table
        );
        sqlx::query(&query).execute(self.db.pool()).await?;
        Ok(())
    }

    pub async fn up(&self, migrations_dir: &Path) -> Result<Vec<String>, sqlx::Error> {
        self.ensure_table().await?;

        let query = format!("SELECT name FROM {}", self.table);
        let applied: Vec<String> = sqlx::query_scalar(&query)
            .fetch_all(self.db.pool())
            .await?;
        let applied_set: std::collections::HashSet<_> = applied.into_iter().collect();

        let mut result = Vec::new();

        if let Ok(entries) = std::fs::read_dir(migrations_dir) {
            let mut files: Vec<_> = entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    name.ends_with(".sql") && !name.ends_with("_down.sql")
                })
                .collect();
            files.sort_by_key(|e| e.file_name());

            for entry in files {
                let name = entry.file_name().to_string_lossy().to_string();
                if applied_set.contains(&name) {
                    continue;
                }

                let sql = std::fs::read_to_string(entry.path()).unwrap();
                info!("Applying migration: {}", name);
                sqlx::query(&sql).execute(self.db.pool()).await?;

                let insert = format!("INSERT INTO {} (name) VALUES ($1)", self.table);
                sqlx::query(&insert).bind(&name).execute(self.db.pool()).await?;
                result.push(name);
            }
        }

        Ok(result)
    }
}
