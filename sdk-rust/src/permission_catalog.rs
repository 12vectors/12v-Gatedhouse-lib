//! Permission catalog (services / resources / actions) — the
//! application vocabulary. Mirrors the Java `PermissionCatalog`
//! interface and `DefaultPermissionCatalog` impl.

use std::sync::Arc;

use crate::database::Database;
use crate::error::GatedhouseError;
use crate::permission_cache::PermissionCache;

pub trait PermissionCatalog: Send + Sync {
    // ---- services ---------------------------------------------------------

    fn add_service(&self, service: &str, description: Option<&str>) -> Result<(), GatedhouseError>;
    fn remove_service(&self, service: &str) -> Result<(), GatedhouseError>;
    fn has_service(&self, service: &str) -> Result<bool, GatedhouseError>;
    fn list_services(&self) -> Result<Vec<String>, GatedhouseError>;

    // ---- resources --------------------------------------------------------

    fn add_resource(
        &self,
        service: &str,
        resource: &str,
        description: Option<&str>,
    ) -> Result<(), GatedhouseError>;
    fn remove_resource(&self, service: &str, resource: &str) -> Result<(), GatedhouseError>;
    fn has_resource(&self, service: &str, resource: &str) -> Result<bool, GatedhouseError>;
    fn list_resources(&self, service: &str) -> Result<Vec<String>, GatedhouseError>;

    // ---- actions ----------------------------------------------------------

    fn add_action(
        &self,
        service: &str,
        resource: &str,
        action: &str,
        description: Option<&str>,
    ) -> Result<(), GatedhouseError>;
    fn remove_action(
        &self,
        service: &str,
        resource: &str,
        action: &str,
    ) -> Result<(), GatedhouseError>;
    fn has_action(
        &self,
        service: &str,
        resource: &str,
        action: &str,
    ) -> Result<bool, GatedhouseError>;
    fn list_actions(&self, service: &str, resource: &str) -> Result<Vec<String>, GatedhouseError>;
}

pub(crate) struct DefaultPermissionCatalog {
    database: Arc<dyn Database>,
    cache: Arc<dyn PermissionCache>,
}

impl DefaultPermissionCatalog {
    pub(crate) fn new(database: Arc<dyn Database>, cache: Arc<dyn PermissionCache>) -> Self {
        Self { database, cache }
    }
}

impl PermissionCatalog for DefaultPermissionCatalog {
    // ---- services ---------------------------------------------------------

    fn add_service(&self, service: &str, description: Option<&str>) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "INSERT INTO gatedhouse.services (service, description) VALUES ($1, $2)",
            &[&service, &description],
        )?;
        Ok(())
    }

    fn remove_service(&self, service: &str) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "DELETE FROM gatedhouse.services WHERE service = $1",
            &[&service],
        )?;
        // Cascade dropped resources, actions, and any role_permissions
        // referencing them. Affected identity set is wide.
        self.cache.invalidate_all();
        Ok(())
    }

    fn has_service(&self, service: &str) -> Result<bool, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let row = conn.query_opt(
            "SELECT 1 FROM gatedhouse.services WHERE service = $1",
            &[&service],
        )?;
        Ok(row.is_some())
    }

    fn list_services(&self) -> Result<Vec<String>, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let rows = conn.query(
            "SELECT service FROM gatedhouse.services ORDER BY service",
            &[],
        )?;
        Ok(rows.into_iter().map(|r| r.get::<_, String>(0)).collect())
    }

    // ---- resources --------------------------------------------------------

    fn add_resource(
        &self,
        service: &str,
        resource: &str,
        description: Option<&str>,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "INSERT INTO gatedhouse.resources (service, resource, description) \
             VALUES ($1, $2, $3)",
            &[&service, &resource, &description],
        )?;
        Ok(())
    }

    fn remove_resource(&self, service: &str, resource: &str) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "DELETE FROM gatedhouse.resources WHERE service = $1 AND resource = $2",
            &[&service, &resource],
        )?;
        self.cache.invalidate_all();
        Ok(())
    }

    fn has_resource(&self, service: &str, resource: &str) -> Result<bool, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let row = conn.query_opt(
            "SELECT 1 FROM gatedhouse.resources WHERE service = $1 AND resource = $2",
            &[&service, &resource],
        )?;
        Ok(row.is_some())
    }

    fn list_resources(&self, service: &str) -> Result<Vec<String>, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let rows = conn.query(
            "SELECT resource FROM gatedhouse.resources \
             WHERE service = $1 ORDER BY resource",
            &[&service],
        )?;
        Ok(rows.into_iter().map(|r| r.get::<_, String>(0)).collect())
    }

    // ---- actions ----------------------------------------------------------

    fn add_action(
        &self,
        service: &str,
        resource: &str,
        action: &str,
        description: Option<&str>,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "INSERT INTO gatedhouse.actions \
             (service, resource, action, description) VALUES ($1, $2, $3, $4)",
            &[&service, &resource, &action, &description],
        )?;
        Ok(())
    }

    fn remove_action(
        &self,
        service: &str,
        resource: &str,
        action: &str,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "DELETE FROM gatedhouse.actions \
             WHERE service = $1 AND resource = $2 AND action = $3",
            &[&service, &resource, &action],
        )?;
        self.cache.invalidate_all();
        Ok(())
    }

    fn has_action(
        &self,
        service: &str,
        resource: &str,
        action: &str,
    ) -> Result<bool, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let row = conn.query_opt(
            "SELECT 1 FROM gatedhouse.actions \
             WHERE service = $1 AND resource = $2 AND action = $3",
            &[&service, &resource, &action],
        )?;
        Ok(row.is_some())
    }

    fn list_actions(&self, service: &str, resource: &str) -> Result<Vec<String>, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let rows = conn.query(
            "SELECT action FROM gatedhouse.actions \
             WHERE service = $1 AND resource = $2 ORDER BY action",
            &[&service, &resource],
        )?;
        Ok(rows.into_iter().map(|r| r.get::<_, String>(0)).collect())
    }
}
