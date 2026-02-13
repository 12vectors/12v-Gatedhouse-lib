//! PostgreSQL connection pool wrapper.

use sqlx::postgres::{PgPool, PgPoolOptions};
use tracing::info;

use crate::config::ResolvedConfig;

pub struct DatabaseConnection {
    pool: PgPool,
}

impl DatabaseConnection {
    pub async fn connect(config: &ResolvedConfig) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .min_connections(config.database.pool_min)
            .max_connections(config.database.pool_max)
            .connect(&config.database.connection_string)
            .await?;

        info!("Database connection pool initialized");
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn health_check(&self) -> bool {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .is_ok()
    }

    pub async fn close(&self) {
        self.pool.close().await;
        info!("Database connection pool closed");
    }
}
