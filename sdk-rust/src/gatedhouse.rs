// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Top-level Gatedhouse trait and the default implementation that
//! wires everything together (managers, cache, JWT verifier).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::config::GatedhouseConfig;
use crate::database::Database;
use crate::enums::MembershipStatus;
use crate::error::{GatedhouseError, TokenVerificationError, TokenVerificationReason};
use crate::group_manager::{DefaultGroupManager, GroupManager};
use crate::group_source::GroupSource;
use crate::jwt_verification::JwtVerification;
use crate::membership_manager::{DefaultMembershipManager, MembershipManager};
use crate::permission_cache::PermissionCache;
use crate::permission_catalog::{DefaultPermissionCatalog, PermissionCatalog};
use crate::role_manager::{DefaultRoleManager, RoleManager};
use crate::sql;
use crate::types::{
    AuthenticatedSubject, EffectivePermission, ExplanationOutcome, GrantPath, GrantSource,
    PermissionExplanation,
};

// One statement, so the status and the paths come from one snapshot. The path
// search mirrors LOAD_EFFECTIVE_PERMISSIONS_SQL (same sources, same
// inheritance climb, same column-wise wildcard rule as has_permission) but
// carries the role chain, and reports paths whatever the membership status is.
// $1 = identity, $2 = org, $3/$4/$5 = service/resource/action.
const EXPLAIN_PERMISSION_SQL: &str =
    "WITH RECURSIVE sources AS ( \
         SELECT 'DIRECT' AS source, NULL::TEXT AS group_id, role_key \
         FROM gatedhouse.role_assignments \
         WHERE identity_id = $1 AND org_id = $2 \
         UNION ALL \
         SELECT 'GROUP', gm.group_id, gr.role_key \
         FROM gatedhouse.group_memberships gm \
         JOIN gatedhouse.group_roles gr \
           ON gr.group_id = gm.group_id AND gr.org_id = gm.org_id \
         WHERE gm.identity_id = $1 AND gm.org_id = $2 \
     ), \
     chains AS ( \
         SELECT source, group_id, role_key AS at_role, ARRAY[role_key] AS chain \
         FROM sources \
         UNION ALL \
         SELECT c.source, c.group_id, ri.parent_key, c.chain || ri.parent_key \
         FROM chains c \
         JOIN gatedhouse.role_inherits ri ON ri.child_key = c.at_role \
         WHERE NOT (ri.parent_key = ANY (c.chain)) \
     ), \
     paths AS ( \
         SELECT c.source, c.group_id, c.chain, rp.service, rp.resource, rp.action \
         FROM chains c \
         JOIN gatedhouse.role_permissions rp ON rp.role_key = c.at_role \
         WHERE (rp.service  IS NULL OR rp.service  = $3) \
           AND (rp.resource IS NULL OR rp.resource = $4) \
           AND (rp.action   IS NULL OR rp.action   = $5) \
     ) \
     SELECT (SELECT status::TEXT FROM gatedhouse.memberships \
             WHERE identity_id = $1 AND org_id = $2) AS status, \
            p.source, p.group_id, p.chain, p.service, p.resource, p.action \
     FROM (SELECT 1) AS one \
     LEFT JOIN paths p ON TRUE \
     ORDER BY p.source, p.group_id NULLS FIRST, cardinality(p.chain), p.chain";

const LOAD_EFFECTIVE_PERMISSIONS_SQL: &str =
    "WITH RECURSIVE active_membership AS ( \
         SELECT 1 FROM gatedhouse.memberships \
         WHERE identity_id = $1 AND org_id = $2 AND status = 'active' \
     ), \
     direct_roles AS ( \
         SELECT role_key FROM gatedhouse.role_assignments \
         WHERE identity_id = $3 AND org_id = $4 \
         UNION \
         SELECT gr.role_key \
         FROM gatedhouse.group_memberships gm \
         JOIN gatedhouse.group_roles gr \
           ON gr.group_id = gm.group_id AND gr.org_id = gm.org_id \
         WHERE gm.identity_id = $5 AND gm.org_id = $6 \
     ), \
     all_roles AS ( \
         SELECT role_key FROM direct_roles \
         UNION \
         SELECT ri.parent_key \
         FROM gatedhouse.role_inherits ri \
         JOIN all_roles ar ON ar.role_key = ri.child_key \
     ) \
     SELECT DISTINCT rp.service, rp.resource, rp.action \
     FROM gatedhouse.role_permissions rp \
     WHERE rp.role_key IN (SELECT role_key FROM all_roles) \
       AND EXISTS (SELECT 1 FROM active_membership)";

/// Top-level Gatedhouse handle.
pub trait Gatedhouse: Send + Sync {
    // ---- administrative sub-interfaces -----------------------------------

    fn permission_catalog(&self) -> &dyn PermissionCatalog;
    fn role_manager(&self) -> &dyn RoleManager;
    fn membership_manager(&self) -> &dyn MembershipManager;
    fn group_manager(&self) -> &dyn GroupManager;

    // ---- the core authorization check ------------------------------------

    fn has_permission(
        &self,
        identity_id: &str,
        org_id: &str,
        service: &str,
        resource: &str,
        action: &str,
    ) -> Result<bool, GatedhouseError>;

    fn get_effective_permissions(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<Vec<EffectivePermission>, GatedhouseError>;

    /// Explains the decision [`has_permission`](Self::has_permission) makes
    /// for the same inputs: the identity's membership status, and every path
    /// through which it holds the permission (direct or via a group, through
    /// role inheritance, to the matching grant). Paths are reported even when
    /// the decision is a denial.
    ///
    /// A diagnostic, not a hot-path check: it bypasses the permission cache
    /// and always reads the database.
    fn explain_permission(
        &self,
        identity_id: &str,
        org_id: &str,
        service: &str,
        resource: &str,
        action: &str,
    ) -> Result<PermissionExplanation, GatedhouseError>;

    fn get_roles(&self, identity_id: &str, org_id: &str) -> Result<Vec<String>, GatedhouseError>;
    fn get_groups(&self, identity_id: &str, org_id: &str) -> Result<Vec<String>, GatedhouseError>;

    // ---- JWT verification helper -----------------------------------------

    fn verify_token(&self, jwt_token: &str) -> Result<AuthenticatedSubject, TokenVerificationError>;

    // ---- cache control ----------------------------------------------------

    fn invalidate_cache(&self, identity_id: &str, org_id: &str);
    fn invalidate_all_cache(&self);
    /// Runtime switch for the permission cache. Caching is opt-in: it is
    /// active only when a cache was configured via
    /// `GatedhouseConfigBuilder::permission_cache` — with no cache
    /// configured (the default) this method is a no-op and
    /// [`is_cache_enabled`](Self::is_cache_enabled) stays `false`.
    ///
    /// A configured cache starts enabled; setting `false` is the runtime
    /// kill switch (reads skip the cache entirely and do not populate
    /// it; writes still invalidate so the cache stays consistent if
    /// re-enabled).
    fn set_cache_enabled(&self, enabled: bool);

    /// `true` if a cache is configured and caching is currently enabled.
    fn is_cache_enabled(&self) -> bool;
}

pub(crate) struct DefaultGatedhouse {
    database: Arc<dyn Database>,
    // The configured cache, or a no-op stand-in when caching is off. The
    // stand-in keeps the managers' write-path invalidation unconditional;
    // the read path never touches it (guarded by cache_enabled below).
    cache: Arc<dyn PermissionCache>,
    cache_configured: bool,
    permission_catalog: DefaultPermissionCatalog,
    role_manager: DefaultRoleManager,
    membership_manager: DefaultMembershipManager,
    group_manager: DefaultGroupManager,
    jwt: Option<JwtVerification>,
    group_source: Arc<dyn GroupSource>,
    cache_enabled: AtomicBool,
}

impl DefaultGatedhouse {
    pub(crate) fn new(config: GatedhouseConfig) -> Self {
        let database = config.database.clone();
        let cache_configured = config.permission_cache.is_some();
        let cache: Arc<dyn PermissionCache> = config
            .permission_cache
            .clone()
            .unwrap_or_else(|| Arc::new(NoOpCache));
        let permission_catalog = DefaultPermissionCatalog::new(database.clone(), cache.clone());
        let role_manager = DefaultRoleManager::new(database.clone(), cache.clone());
        let membership_manager = DefaultMembershipManager::new(database.clone(), cache.clone());
        let group_manager = DefaultGroupManager::new(database.clone(), cache.clone());
        let jwt = config.token_verifier.as_ref().map(JwtVerification::new);

        Self {
            database,
            cache,
            cache_configured,
            permission_catalog,
            role_manager,
            membership_manager,
            group_manager,
            jwt,
            group_source: config.group_source,
            cache_enabled: AtomicBool::new(cache_configured),
        }
    }

    fn effective_permissions_cached(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<Vec<EffectivePermission>, GatedhouseError> {
        if !self.cache_enabled.load(Ordering::Relaxed) {
            // No cache configured, or caching switched off at runtime:
            // skip the cache entirely on reads and do not populate it.
            return self.load_effective_permissions(identity_id, org_id);
        }
        if let Some(hit) = self.cache.get(identity_id, org_id) {
            return Ok(hit);
        }
        let fresh = self.load_effective_permissions(identity_id, org_id)?;
        self.cache.put(identity_id, org_id, fresh.clone());
        Ok(fresh)
    }

    fn load_effective_permissions(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<Vec<EffectivePermission>, GatedhouseError> {
        let mut conn = sql::borrow(&*self.database, "load_effective_permissions")?;
        let rows = conn.query(
            LOAD_EFFECTIVE_PERMISSIONS_SQL,
            &[
                &identity_id, &org_id, // active_membership
                &identity_id, &org_id, // direct_roles part 1
                &identity_id, &org_id, // direct_roles part 2 (groups)
            ],
        )?;
        Ok(rows
            .into_iter()
            .map(|r| {
                EffectivePermission::new(
                    r.get::<_, Option<String>>(0),
                    r.get::<_, Option<String>>(1),
                    r.get::<_, Option<String>>(2),
                )
            })
            .collect())
    }
}

impl Gatedhouse for DefaultGatedhouse {
    fn permission_catalog(&self) -> &dyn PermissionCatalog {
        &self.permission_catalog
    }

    fn role_manager(&self) -> &dyn RoleManager {
        &self.role_manager
    }

    fn membership_manager(&self) -> &dyn MembershipManager {
        &self.membership_manager
    }

    fn group_manager(&self) -> &dyn GroupManager {
        &self.group_manager
    }

    fn has_permission(
        &self,
        identity_id: &str,
        org_id: &str,
        service: &str,
        resource: &str,
        action: &str,
    ) -> Result<bool, GatedhouseError> {
        let effective = self.effective_permissions_cached(identity_id, org_id)?;
        for grant in effective.iter() {
            let svc_ok = grant
                .service
                .as_deref()
                .map(|s| s == service)
                .unwrap_or(true);
            let res_ok = grant
                .resource
                .as_deref()
                .map(|r| r == resource)
                .unwrap_or(true);
            let act_ok = grant
                .action
                .as_deref()
                .map(|a| a == action)
                .unwrap_or(true);
            if svc_ok && res_ok && act_ok {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn get_effective_permissions(
        &self,
        identity_id: &str,
        org_id: &str,
    ) -> Result<Vec<EffectivePermission>, GatedhouseError> {
        self.effective_permissions_cached(identity_id, org_id)
    }

    fn explain_permission(
        &self,
        identity_id: &str,
        org_id: &str,
        service: &str,
        resource: &str,
        action: &str,
    ) -> Result<PermissionExplanation, GatedhouseError> {
        let mut conn = sql::borrow(&*self.database, "explain_permission")?;
        let rows = conn.query(
            EXPLAIN_PERMISSION_SQL,
            &[&identity_id, &org_id, &service, &resource, &action],
        )?;
        let mut membership_status = None;
        let mut paths = Vec::new();
        for r in rows {
            if let Some(value) = r.get::<_, Option<String>>("status") {
                membership_status = Some(
                    MembershipStatus::from_db_value(&value)
                        .map_err(|e| GatedhouseError::query(e.to_string()))?,
                );
            }
            // The LEFT JOIN's placeholder row (no paths) has a NULL source.
            let Some(source) = r.get::<_, Option<String>>("source") else {
                continue;
            };
            let source = match source.as_str() {
                "DIRECT" => GrantSource::Direct,
                "GROUP" => GrantSource::Group,
                other => {
                    return Err(GatedhouseError::query(format!(
                        "unexpected grant source in explain query: {other:?}"
                    )))
                }
            };
            paths.push(GrantPath {
                source,
                group_id: r.get("group_id"),
                role_chain: r.get("chain"),
                grant: EffectivePermission::new(r.get("service"), r.get("resource"), r.get("action")),
            });
        }
        let outcome = match membership_status {
            None => ExplanationOutcome::NoMembership,
            Some(MembershipStatus::Active) if paths.is_empty() => ExplanationOutcome::NoMatchingGrant,
            Some(MembershipStatus::Active) => ExplanationOutcome::Allowed,
            Some(_) => ExplanationOutcome::MembershipNotActive,
        };
        Ok(PermissionExplanation {
            outcome,
            membership_status,
            paths,
        })
    }

    fn get_roles(&self, identity_id: &str, org_id: &str) -> Result<Vec<String>, GatedhouseError> {
        self.role_manager.get_identity_roles(identity_id, org_id)
    }

    fn get_groups(&self, identity_id: &str, org_id: &str) -> Result<Vec<String>, GatedhouseError> {
        self.group_manager.get_identity_groups(identity_id, org_id)
    }

    fn verify_token(&self, jwt_token: &str) -> Result<AuthenticatedSubject, TokenVerificationError> {
        match &self.jwt {
            Some(jwt) => jwt.verify(jwt_token),
            None => Err(TokenVerificationError::new(
                TokenVerificationReason::Other,
                "verify_token was called but no TokenVerifierConfig was supplied. \
                 Configure via GatedhouseConfig::builder(db).token_verifier(...).build().",
            )),
        }
    }

    fn invalidate_cache(&self, identity_id: &str, org_id: &str) {
        self.cache.invalidate(identity_id, org_id);
    }

    fn invalidate_all_cache(&self) {
        self.cache.invalidate_all();
    }

    fn set_cache_enabled(&self, enabled: bool) {
        self.cache_enabled
            .store(enabled && self.cache_configured, Ordering::Relaxed);
    }

    fn is_cache_enabled(&self) -> bool {
        self.cache_enabled.load(Ordering::Relaxed)
    }
}

/// Stand-in used when no cache is configured; every method is a no-op.
struct NoOpCache;

impl PermissionCache for NoOpCache {
    fn get(&self, _identity_id: &str, _org_id: &str) -> Option<Vec<EffectivePermission>> {
        None
    }

    fn put(&self, _identity_id: &str, _org_id: &str, _permissions: Vec<EffectivePermission>) {}

    fn invalidate(&self, _identity_id: &str, _org_id: &str) {}

    fn invalidate_all(&self) {}
}

impl Drop for DefaultGatedhouse {
    fn drop(&mut self) {
        self.group_source.close();
    }
}
