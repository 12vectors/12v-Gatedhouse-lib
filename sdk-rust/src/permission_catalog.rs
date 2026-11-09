// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Permission catalog (services / resources / actions) — the
//! application vocabulary. Mirrors the Java `PermissionCatalog`
//! interface and `DefaultPermissionCatalog` impl.

use std::sync::Arc;

use crate::database::Database;
use crate::error::GatedhouseError;
use crate::permission_cache::PermissionCache;
use crate::sql;

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
        sql::write(&*self.database, "PermissionCatalog.add_service", |tx| {
            tx.execute(
                "INSERT INTO gatedhouse.services (service, description) VALUES ($1, $2)",
                &[&service, &description],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    fn remove_service(&self, service: &str) -> Result<(), GatedhouseError> {
        sql::write(&*self.database, "PermissionCatalog.remove_service", |tx| {
            tx.execute(
                "DELETE FROM gatedhouse.services WHERE service = $1",
                &[&service],
            )?;
            Ok(())
        })?;
        // Cascade dropped resources, actions, and any role_permissions
        // referencing them. Affected identity set is wide.
        self.cache.invalidate_all();
        Ok(())
    }

    fn has_service(&self, service: &str) -> Result<bool, GatedhouseError> {
        let mut conn = sql::borrow(&*self.database, "PermissionCatalog.has_service")?;
        let row = conn.query_opt(
            "SELECT 1 FROM gatedhouse.services WHERE service = $1",
            &[&service],
        )?;
        Ok(row.is_some())
    }

    fn list_services(&self) -> Result<Vec<String>, GatedhouseError> {
        let mut conn = sql::borrow(&*self.database, "PermissionCatalog.list_services")?;
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
        sql::write(&*self.database, "PermissionCatalog.add_resource", |tx| {
            tx.execute(
                "INSERT INTO gatedhouse.resources (service, resource, description) \
                 VALUES ($1, $2, $3)",
                &[&service, &resource, &description],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    fn remove_resource(&self, service: &str, resource: &str) -> Result<(), GatedhouseError> {
        sql::write(&*self.database, "PermissionCatalog.remove_resource", |tx| {
            tx.execute(
                "DELETE FROM gatedhouse.resources WHERE service = $1 AND resource = $2",
                &[&service, &resource],
            )?;
            Ok(())
        })?;
        self.cache.invalidate_all();
        Ok(())
    }

    fn has_resource(&self, service: &str, resource: &str) -> Result<bool, GatedhouseError> {
        let mut conn = sql::borrow(&*self.database, "PermissionCatalog.has_resource")?;
        let row = conn.query_opt(
            "SELECT 1 FROM gatedhouse.resources WHERE service = $1 AND resource = $2",
            &[&service, &resource],
        )?;
        Ok(row.is_some())
    }

    fn list_resources(&self, service: &str) -> Result<Vec<String>, GatedhouseError> {
        let mut conn = sql::borrow(&*self.database, "PermissionCatalog.list_resources")?;
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
        sql::write(&*self.database, "PermissionCatalog.add_action", |tx| {
            tx.execute(
                "INSERT INTO gatedhouse.actions \
                 (service, resource, action, description) VALUES ($1, $2, $3, $4)",
                &[&service, &resource, &action, &description],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    fn remove_action(
        &self,
        service: &str,
        resource: &str,
        action: &str,
    ) -> Result<(), GatedhouseError> {
        sql::write(&*self.database, "PermissionCatalog.remove_action", |tx| {
            tx.execute(
                "DELETE FROM gatedhouse.actions \
                 WHERE service = $1 AND resource = $2 AND action = $3",
                &[&service, &resource, &action],
            )?;
            Ok(())
        })?;
        self.cache.invalidate_all();
        Ok(())
    }

    fn has_action(
        &self,
        service: &str,
        resource: &str,
        action: &str,
    ) -> Result<bool, GatedhouseError> {
        let mut conn = sql::borrow(&*self.database, "PermissionCatalog.has_action")?;
        let row = conn.query_opt(
            "SELECT 1 FROM gatedhouse.actions \
             WHERE service = $1 AND resource = $2 AND action = $3",
            &[&service, &resource, &action],
        )?;
        Ok(row.is_some())
    }

    fn list_actions(&self, service: &str, resource: &str) -> Result<Vec<String>, GatedhouseError> {
        let mut conn = sql::borrow(&*self.database, "PermissionCatalog.list_actions")?;
        let rows = conn.query(
            "SELECT action FROM gatedhouse.actions \
             WHERE service = $1 AND resource = $2 ORDER BY action",
            &[&service, &resource],
        )?;
        Ok(rows.into_iter().map(|r| r.get::<_, String>(0)).collect())
    }
}
