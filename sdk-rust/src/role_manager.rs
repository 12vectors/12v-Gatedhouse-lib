//! Role definitions, permission grants, inheritance, and role
//! assignments.

use std::sync::Arc;

use uuid::Uuid;

use crate::database::Database;
use crate::error::GatedhouseError;
use crate::permission_cache::PermissionCache;

pub trait RoleManager: Send + Sync {
    // ---- role definitions -------------------------------------------------

    fn create_role(
        &self,
        key: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<(), GatedhouseError>;
    fn delete_role(&self, key: &str) -> Result<(), GatedhouseError>;
    fn has_role(&self, key: &str) -> Result<bool, GatedhouseError>;
    fn list_roles(&self) -> Result<Vec<String>, GatedhouseError>;

    // ---- permission grants on a role -------------------------------------
    // service / resource / action may be None to denote a wildcard at
    // that level. (None, None, None) grants superuser-equivalent.

    fn grant_permission(
        &self,
        role_key: &str,
        service: Option<&str>,
        resource: Option<&str>,
        action: Option<&str>,
    ) -> Result<(), GatedhouseError>;
    fn revoke_permission(
        &self,
        role_key: &str,
        service: Option<&str>,
        resource: Option<&str>,
        action: Option<&str>,
    ) -> Result<(), GatedhouseError>;

    // ---- role inheritance -------------------------------------------------

    fn add_parent_role(&self, child_key: &str, parent_key: &str) -> Result<(), GatedhouseError>;
    fn remove_parent_role(&self, child_key: &str, parent_key: &str) -> Result<(), GatedhouseError>;
    fn get_parent_roles(&self, child_key: &str) -> Result<Vec<String>, GatedhouseError>;

    // ---- assignments to identities ---------------------------------------

    fn assign_to_identity(
        &self,
        identity_id: &str,
        org_id: &str,
        role_key: &str,
    ) -> Result<(), GatedhouseError>;
    fn revoke_from_identity(
        &self,
        identity_id: &str,
        org_id: &str,
        role_key: &str,
    ) -> Result<(), GatedhouseError>;
    fn get_identity_roles(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<Vec<String>, GatedhouseError>;

    // ---- assignments to groups -------------------------------------------

    fn assign_to_group(
        &self,
        group_id: &str,
        org_id: &str,
        role_key: &str,
    ) -> Result<(), GatedhouseError>;
    fn revoke_from_group(
        &self,
        group_id: &str,
        org_id: &str,
        role_key: &str,
    ) -> Result<(), GatedhouseError>;
    fn get_group_roles(&self, group_id: &str, org_id: &str) -> Result<Vec<String>, GatedhouseError>;
}

pub(crate) struct DefaultRoleManager {
    database: Arc<dyn Database>,
    cache: Arc<dyn PermissionCache>,
}

impl DefaultRoleManager {
    pub(crate) fn new(database: Arc<dyn Database>, cache: Arc<dyn PermissionCache>) -> Self {
        Self { database, cache }
    }
}

impl RoleManager for DefaultRoleManager {
    // ---- role definitions -------------------------------------------------

    fn create_role(
        &self,
        key: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "INSERT INTO gatedhouse.roles (key, name, description, is_system) \
             VALUES ($1, $2, $3, FALSE)",
            &[&key, &name, &description],
        )?;
        Ok(())
    }

    fn delete_role(&self, key: &str) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "DELETE FROM gatedhouse.roles WHERE key = $1 AND is_system = FALSE",
            &[&key],
        )?;
        // Cascade dropped every assignment of this role.
        self.cache.invalidate_all();
        Ok(())
    }

    fn has_role(&self, key: &str) -> Result<bool, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let row = conn.query_opt("SELECT 1 FROM gatedhouse.roles WHERE key = $1", &[&key])?;
        Ok(row.is_some())
    }

    fn list_roles(&self) -> Result<Vec<String>, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let rows = conn.query("SELECT key FROM gatedhouse.roles ORDER BY key", &[])?;
        Ok(rows.into_iter().map(|r| r.get::<_, String>(0)).collect())
    }

    // ---- permission grants ------------------------------------------------

    fn grant_permission(
        &self,
        role_key: &str,
        service: Option<&str>,
        resource: Option<&str>,
        action: Option<&str>,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        let id = Uuid::new_v4();
        conn.execute(
            "INSERT INTO gatedhouse.role_permissions \
             (id, role_key, service, resource, action) VALUES ($1, $2, $3, $4, $5)",
            &[&id, &role_key, &service, &resource, &action],
        )?;
        // Affects every identity holding this role (directly, via group,
        // or via inheritance).
        self.cache.invalidate_all();
        Ok(())
    }

    fn revoke_permission(
        &self,
        role_key: &str,
        service: Option<&str>,
        resource: Option<&str>,
        action: Option<&str>,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        // Match on COALESCE so NULLs (wildcards) compare correctly.
        conn.execute(
            "DELETE FROM gatedhouse.role_permissions \
             WHERE role_key = $1 \
               AND COALESCE(service,  '') = COALESCE($2, '') \
               AND COALESCE(resource, '') = COALESCE($3, '') \
               AND COALESCE(action,   '') = COALESCE($4, '')",
            &[&role_key, &service, &resource, &action],
        )?;
        self.cache.invalidate_all();
        Ok(())
    }

    // ---- role inheritance -------------------------------------------------

    fn add_parent_role(&self, child_key: &str, parent_key: &str) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "INSERT INTO gatedhouse.role_inherits (child_key, parent_key) \
             VALUES ($1, $2)",
            &[&child_key, &parent_key],
        )?;
        self.cache.invalidate_all();
        Ok(())
    }

    fn remove_parent_role(&self, child_key: &str, parent_key: &str) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "DELETE FROM gatedhouse.role_inherits \
             WHERE child_key = $1 AND parent_key = $2",
            &[&child_key, &parent_key],
        )?;
        self.cache.invalidate_all();
        Ok(())
    }

    fn get_parent_roles(&self, child_key: &str) -> Result<Vec<String>, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let rows = conn.query(
            "SELECT parent_key FROM gatedhouse.role_inherits \
             WHERE child_key = $1 ORDER BY parent_key",
            &[&child_key],
        )?;
        Ok(rows.into_iter().map(|r| r.get::<_, String>(0)).collect())
    }

    // ---- assignments to identities ---------------------------------------

    fn assign_to_identity(
        &self,
        identity_id: &str,
        org_id: &str,
        role_key: &str,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        let id = Uuid::new_v4();
        conn.execute(
            "INSERT INTO gatedhouse.role_assignments \
             (id, identity_id, org_id, role_key) VALUES ($1, $2, $3, $4)",
            &[&id, &identity_id, &org_id, &role_key],
        )?;
        self.cache.invalidate(identity_id, org_id);
        Ok(())
    }

    fn revoke_from_identity(
        &self,
        identity_id: &str,
        org_id: &str,
        role_key: &str,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "DELETE FROM gatedhouse.role_assignments \
             WHERE identity_id = $1 AND org_id = $2 AND role_key = $3",
            &[&identity_id, &org_id, &role_key],
        )?;
        self.cache.invalidate(identity_id, org_id);
        Ok(())
    }

    fn get_identity_roles(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<Vec<String>, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let rows = conn.query(
            "SELECT role_key FROM gatedhouse.role_assignments \
             WHERE identity_id = $1 AND org_id = $2 ORDER BY role_key",
            &[&identity_id, &org_id],
        )?;
        Ok(rows.into_iter().map(|r| r.get::<_, String>(0)).collect())
    }

    // ---- assignments to groups -------------------------------------------

    fn assign_to_group(
        &self,
        group_id: &str,
        org_id: &str,
        role_key: &str,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "INSERT INTO gatedhouse.group_roles (group_id, org_id, role_key) \
             VALUES ($1, $2, $3)",
            &[&group_id, &org_id, &role_key],
        )?;
        // Affects every member of the group; cache doesn't index by
        // group membership, so wholesale invalidate.
        self.cache.invalidate_all();
        Ok(())
    }

    fn revoke_from_group(
        &self,
        group_id: &str,
        org_id: &str,
        role_key: &str,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "DELETE FROM gatedhouse.group_roles \
             WHERE group_id = $1 AND org_id = $2 AND role_key = $3",
            &[&group_id, &org_id, &role_key],
        )?;
        self.cache.invalidate_all();
        Ok(())
    }

    fn get_group_roles(&self, group_id: &str, org_id: &str) -> Result<Vec<String>, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let rows = conn.query(
            "SELECT role_key FROM gatedhouse.group_roles \
             WHERE group_id = $1 AND org_id = $2 ORDER BY role_key",
            &[&group_id, &org_id],
        )?;
        Ok(rows.into_iter().map(|r| r.get::<_, String>(0)).collect())
    }
}
