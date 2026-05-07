//! Library-owned identity↔org memberships.

use std::sync::Arc;

use uuid::Uuid;

use crate::database::Database;
use crate::enums::{EntityType, MembershipStatus};
use crate::error::GatedhouseError;
use crate::permission_cache::PermissionCache;

pub trait MembershipManager: Send + Sync {
    fn create_membership(
        &self,
        identity_id: &str,
        org_id: &str,
        entity_type: EntityType,
    ) -> Result<(), GatedhouseError>;
    fn delete_membership(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<(), GatedhouseError>;
    fn has_membership(&self, identity_id: &str, org_id: &str) -> Result<bool, GatedhouseError>;
    fn set_status(
        &self,
        identity_id: &str,
        org_id: &str,
        status: MembershipStatus,
    ) -> Result<(), GatedhouseError>;
    fn get_status(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<Option<MembershipStatus>, GatedhouseError>;
    fn get_entity_type(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<Option<EntityType>, GatedhouseError>;
}

pub(crate) struct DefaultMembershipManager {
    database: Arc<dyn Database>,
    cache: Arc<dyn PermissionCache>,
}

impl DefaultMembershipManager {
    pub(crate) fn new(database: Arc<dyn Database>, cache: Arc<dyn PermissionCache>) -> Self {
        Self { database, cache }
    }
}

impl MembershipManager for DefaultMembershipManager {
    fn create_membership(
        &self,
        identity_id: &str,
        org_id: &str,
        entity_type: EntityType,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        let id = Uuid::new_v4();
        let entity_type_str = entity_type.db_value();
        conn.execute(
            "INSERT INTO gatedhouse.memberships \
             (id, identity_id, org_id, entity_type, status) \
             VALUES ($1, $2, $3, $4::gatedhouse.entity_type, \
                     'active'::gatedhouse.membership_status)",
            &[&id, &identity_id, &org_id, &entity_type_str],
        )?;
        self.cache.invalidate(identity_id, org_id);
        Ok(())
    }

    fn delete_membership(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        conn.execute(
            "DELETE FROM gatedhouse.memberships \
             WHERE identity_id = $1 AND org_id = $2",
            &[&identity_id, &org_id],
        )?;
        self.cache.invalidate(identity_id, org_id);
        Ok(())
    }

    fn has_membership(&self, identity_id: &str, org_id: &str) -> Result<bool, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let row = conn.query_opt(
            "SELECT 1 FROM gatedhouse.memberships \
             WHERE identity_id = $1 AND org_id = $2",
            &[&identity_id, &org_id],
        )?;
        Ok(row.is_some())
    }

    fn set_status(
        &self,
        identity_id: &str,
        org_id: &str,
        status: MembershipStatus,
    ) -> Result<(), GatedhouseError> {
        let mut conn = self.database.connection()?;
        let status_str = status.db_value();
        conn.execute(
            "UPDATE gatedhouse.memberships \
             SET status = $1::gatedhouse.membership_status, updated_at = NOW() \
             WHERE identity_id = $2 AND org_id = $3",
            &[&status_str, &identity_id, &org_id],
        )?;
        self.cache.invalidate(identity_id, org_id);
        Ok(())
    }

    fn get_status(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<Option<MembershipStatus>, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let row = conn.query_opt(
            "SELECT status::TEXT FROM gatedhouse.memberships \
             WHERE identity_id = $1 AND org_id = $2",
            &[&identity_id, &org_id],
        )?;
        match row {
            None => Ok(None),
            Some(r) => {
                let value: String = r.get(0);
                MembershipStatus::from_db_value(&value)
                    .map(Some)
                    .map_err(|e| GatedhouseError::Database(e.to_string()))
            }
        }
    }

    fn get_entity_type(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<Option<EntityType>, GatedhouseError> {
        let mut conn = self.database.connection()?;
        let row = conn.query_opt(
            "SELECT entity_type::TEXT FROM gatedhouse.memberships \
             WHERE identity_id = $1 AND org_id = $2",
            &[&identity_id, &org_id],
        )?;
        match row {
            None => Ok(None),
            Some(r) => {
                let value: String = r.get(0);
                EntityType::from_db_value(&value)
                    .map(Some)
                    .map_err(|e| GatedhouseError::Database(e.to_string()))
            }
        }
    }
}
