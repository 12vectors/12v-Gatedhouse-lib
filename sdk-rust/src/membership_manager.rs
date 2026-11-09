// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Library-owned identity↔org memberships.
//!
//! Memberships are never deleted. Every lifecycle transition runs in a single
//! transaction that first row-locks the membership, so a removal and the
//! revocation of its grants commit together, and concurrent transitions on
//! the same membership serialize. See docs/MODEL.md, "The membership
//! lifecycle".

use std::sync::Arc;

use postgres::Transaction;
use uuid::Uuid;

use crate::database::Database;
use crate::enums::{EntityType, MembershipStatus};
use crate::error::GatedhouseError;
use crate::permission_cache::PermissionCache;
use crate::sql;

/// Manages an identity's membership of an org: the gate that lets its
/// grants in that org count.
pub trait MembershipManager: Send + Sync {
    /// Creates an [`Active`](MembershipStatus::Active) membership.
    ///
    /// If the identity has a [`Removed`](MembershipStatus::Removed)
    /// membership in the org, it is revived instead: any grants left in that
    /// org are cleared, then the same row becomes `Active` with the given
    /// entity type. If a membership in any other status exists, the insert
    /// fails with [`GatedhouseError::Database`].
    fn create_membership(
        &self,
        identity_id: &str,
        org_id: &str,
        entity_type: EntityType,
    ) -> Result<(), GatedhouseError>;

    /// Removes the identity from the org: in one transaction, sets the
    /// status to [`Removed`](MembershipStatus::Removed) and revokes the
    /// identity's direct role assignments and group memberships in that org.
    /// The membership row is kept as history.
    ///
    /// If no membership exists, grants the identity holds in the org are
    /// still revoked, so afterwards it holds nothing there.
    fn remove_membership(&self, identity_id: &str, org_id: &str) -> Result<(), GatedhouseError>;

    /// True if the identity is a member of the org in any status other than
    /// [`Removed`](MembershipStatus::Removed).
    fn has_membership(&self, identity_id: &str, org_id: &str) -> Result<bool, GatedhouseError>;

    /// Changes the membership's status. Does nothing if no membership exists
    /// (except for `Removed`, which behaves as
    /// [`remove_membership`](Self::remove_membership)).
    ///
    /// - To `Removed`: same as `remove_membership`.
    /// - From `Removed` to `Active` or `Pending`: revives the membership,
    ///   clearing any grants left in the org first.
    /// - From `Removed` to `Suspended`: rejected with
    ///   [`GatedhouseError::InvalidTransition`]; a removed identity has
    ///   nothing to suspend.
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
        sql::write(&*self.database, "MembershipManager.create_membership", |tx| {
            let entity_type_str = entity_type.db_value();
            if lock_status(tx, identity_id, org_id)? == Some(MembershipStatus::Removed) {
                // Rejoin: same row, clean slate.
                clear_grants(tx, identity_id, org_id)?;
                tx.execute(
                    "UPDATE gatedhouse.memberships \
                     SET status = 'active'::gatedhouse.membership_status, \
                         entity_type = $1::text::gatedhouse.entity_type, updated_at = NOW() \
                     WHERE identity_id = $2 AND org_id = $3",
                    &[&entity_type_str, &identity_id, &org_id],
                )?;
            } else {
                // No row, or a live one: a live row makes this insert fail with
                // the unique violation, exactly as before.
                let id = Uuid::new_v4();
                tx.execute(
                    "INSERT INTO gatedhouse.memberships \
                     (id, identity_id, org_id, entity_type, status) \
                     VALUES ($1, $2, $3, $4::text::gatedhouse.entity_type, \
                             'active'::gatedhouse.membership_status)",
                    &[&id, &identity_id, &org_id, &entity_type_str],
                )?;
            }
            Ok(())
        })?;
        self.cache.invalidate(identity_id, org_id);
        Ok(())
    }

    fn remove_membership(&self, identity_id: &str, org_id: &str) -> Result<(), GatedhouseError> {
        sql::write(&*self.database, "MembershipManager.remove_membership", |tx| {
            match lock_status(tx, identity_id, org_id)? {
                Some(current) if current != MembershipStatus::Removed => {
                    update_status(tx, identity_id, org_id, MembershipStatus::Removed)?;
                }
                _ => {}
            }
            // Also when already Removed or absent: clears grants that arrived
            // after an earlier removal.
            clear_grants(tx, identity_id, org_id)?;
            Ok(())
        })?;
        self.cache.invalidate(identity_id, org_id);
        Ok(())
    }

    fn has_membership(&self, identity_id: &str, org_id: &str) -> Result<bool, GatedhouseError> {
        let mut conn = sql::borrow(&*self.database, "MembershipManager.has_membership")?;
        let row = conn.query_opt(
            "SELECT 1 FROM gatedhouse.memberships \
             WHERE identity_id = $1 AND org_id = $2 AND status <> 'removed'",
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
        if status == MembershipStatus::Removed {
            return self.remove_membership(identity_id, org_id);
        }
        sql::write(&*self.database, "MembershipManager.set_status", |tx| {
            match lock_status(tx, identity_id, org_id)? {
                None => return Ok(()),
                Some(MembershipStatus::Removed) => {
                    if status == MembershipStatus::Suspended {
                        // Returning an error rolls the transaction back, releasing the lock.
                        return Err(GatedhouseError::InvalidTransition(format!(
                            "cannot suspend removed membership ({identity_id}, {org_id}); \
                             revive it as Active or Pending instead"
                        )));
                    }
                    // Rejoin: clean slate.
                    clear_grants(tx, identity_id, org_id)?;
                }
                Some(_) => {}
            }
            update_status(tx, identity_id, org_id, status)?;
            Ok(())
        })?;
        self.cache.invalidate(identity_id, org_id);
        Ok(())
    }

    fn get_status(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<Option<MembershipStatus>, GatedhouseError> {
        let mut conn = sql::borrow(&*self.database, "MembershipManager.get_status")?;
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
                    .map_err(|e| GatedhouseError::query(e.to_string()))
            }
        }
    }

    fn get_entity_type(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<Option<EntityType>, GatedhouseError> {
        let mut conn = sql::borrow(&*self.database, "MembershipManager.get_entity_type")?;
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
                    .map_err(|e| GatedhouseError::query(e.to_string()))
            }
        }
    }
}

// ---- transaction helpers ---------------------------------------------------

fn lock_status(
    tx: &mut Transaction<'_>,
    identity_id: &str,
    org_id: &str,
) -> Result<Option<MembershipStatus>, GatedhouseError> {
    let row = tx.query_opt(
        "SELECT status::TEXT FROM gatedhouse.memberships \
         WHERE identity_id = $1 AND org_id = $2 FOR UPDATE",
        &[&identity_id, &org_id],
    )?;
    match row {
        None => Ok(None),
        Some(r) => {
            let value: String = r.get(0);
            MembershipStatus::from_db_value(&value)
                .map(Some)
                .map_err(|e| GatedhouseError::query(e.to_string()))
        }
    }
}

fn update_status(
    tx: &mut Transaction<'_>,
    identity_id: &str,
    org_id: &str,
    status: MembershipStatus,
) -> Result<(), GatedhouseError> {
    let status_str = status.db_value();
    tx.execute(
        "UPDATE gatedhouse.memberships \
         SET status = $1::text::gatedhouse.membership_status, updated_at = NOW() \
         WHERE identity_id = $2 AND org_id = $3",
        &[&status_str, &identity_id, &org_id],
    )?;
    Ok(())
}

/// Revokes the identity's direct roles and group memberships in the org.
fn clear_grants(
    tx: &mut Transaction<'_>,
    identity_id: &str,
    org_id: &str,
) -> Result<(), GatedhouseError> {
    for sql in [
        "DELETE FROM gatedhouse.role_assignments WHERE identity_id = $1 AND org_id = $2",
        "DELETE FROM gatedhouse.group_memberships WHERE identity_id = $1 AND org_id = $2",
    ] {
        tx.execute(sql, &[&identity_id, &org_id])?;
    }
    Ok(())
}
