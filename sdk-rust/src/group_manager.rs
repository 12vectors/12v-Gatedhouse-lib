// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Group definitions and group↔identity membership.

use std::sync::Arc;

use crate::database::Database;
use crate::error::GatedhouseError;
use crate::permission_cache::PermissionCache;

pub trait GroupManager: Send + Sync {
    // ---- group definitions (per org) -------------------------------------

    fn create_group(
        &self,
        group_id: &str,
        org_id: &str,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<(), GatedhouseError>;
    fn delete_group(&self, group_id: &str, org_id: &str) -> Result<(), GatedhouseError>;
    fn has_group(&self, group_id: &str, org_id: &str) -> Result<bool, GatedhouseError>;
    fn list_groups(&self, org_id: &str) -> Result<Vec<String>, GatedhouseError>;

    // ---- group membership -------------------------------------------------

    fn add_identity_to_group(
        &self,
        group_id: &str,
        org_id: &str,
        identity_id: &str,
    ) -> Result<(), GatedhouseError>;
    fn remove_identity_from_group(
        &self,
        group_id: &str,
        org_id: &str,
        identity_id: &str,
    ) -> Result<(), GatedhouseError>;
    fn get_group_members(
        &self,
        group_id: &str,
        org_id: &str,
    ) -> Result<Vec<String>, GatedhouseError>;
    fn get_identity_groups(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<Vec<String>, GatedhouseError>;
}

pub(crate) struct DefaultGroupManager {
    database: Arc<dyn Database>,
    cache: Arc<dyn PermissionCache>,
}

impl DefaultGroupManager {
    pub(crate) fn new(database: Arc<dyn Database>, cache: Arc<dyn PermissionCache>) -> Self {
        Self { database, cache }
    }
}

impl GroupManager for DefaultGroupManager {
    // ---- group definitions -----------------------------------------------

    fn create_group(
        &self,
        group_id: &str,
        org_id: &str,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "INSERT INTO gatedhouse.groups (id, org_id, name, description) \
             VALUES ($1, $2, $3, $4)",
            &[&group_id, &org_id, &name, &description],
        )?;
        Ok(())
    }

    fn delete_group(&self, group_id: &str, org_id: &str) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "DELETE FROM gatedhouse.groups WHERE id = $1 AND org_id = $2",
            &[&group_id, &org_id],
        )?;
        // Cascade dropped group_memberships and group_roles for every member.
        self.cache.invalidate_all();
        Ok(())
    }

    fn has_group(&self, group_id: &str, org_id: &str) -> Result<bool, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let row = conn.query_opt(
            "SELECT 1 FROM gatedhouse.groups WHERE id = $1 AND org_id = $2",
            &[&group_id, &org_id],
        )?;
        Ok(row.is_some())
    }

    fn list_groups(&self, org_id: &str) -> Result<Vec<String>, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let rows = conn.query(
            "SELECT id FROM gatedhouse.groups WHERE org_id = $1 ORDER BY id",
            &[&org_id],
        )?;
        Ok(rows.into_iter().map(|r| r.get::<_, String>(0)).collect())
    }

    // ---- group membership -------------------------------------------------

    fn add_identity_to_group(
        &self,
        group_id: &str,
        org_id: &str,
        identity_id: &str,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "INSERT INTO gatedhouse.group_memberships \
             (group_id, org_id, identity_id) VALUES ($1, $2, $3)",
            &[&group_id, &org_id, &identity_id],
        )?;
        self.cache.invalidate(identity_id, org_id);
        Ok(())
    }

    fn remove_identity_from_group(
        &self,
        group_id: &str,
        org_id: &str,
        identity_id: &str,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "DELETE FROM gatedhouse.group_memberships \
             WHERE group_id = $1 AND org_id = $2 AND identity_id = $3",
            &[&group_id, &org_id, &identity_id],
        )?;
        self.cache.invalidate(identity_id, org_id);
        Ok(())
    }

    fn get_group_members(
        &self,
        group_id: &str,
        org_id: &str,
    ) -> Result<Vec<String>, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let rows = conn.query(
            "SELECT identity_id FROM gatedhouse.group_memberships \
             WHERE group_id = $1 AND org_id = $2 ORDER BY identity_id",
            &[&group_id, &org_id],
        )?;
        Ok(rows.into_iter().map(|r| r.get::<_, String>(0)).collect())
    }

    fn get_identity_groups(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<Vec<String>, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let rows = conn.query(
            "SELECT group_id FROM gatedhouse.group_memberships \
             WHERE identity_id = $1 AND org_id = $2 ORDER BY group_id",
            &[&identity_id, &org_id],
        )?;
        Ok(rows.into_iter().map(|r| r.get::<_, String>(0)).collect())
    }
}
