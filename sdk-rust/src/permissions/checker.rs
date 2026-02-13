//! Permission checker — the core authorization decision point.
//!
//! Evaluates whether a GatedContext has a required permission,
//! respecting identity type, delegation constraints, and wildcards.

use chrono::Utc;
use tracing::debug;

use crate::types::{GatedContext, PermissionCheckResult};
use crate::permissions::matcher::{has_permission, intersect_permissions};

/// Core authorization decision engine.
pub struct PermissionChecker;

impl PermissionChecker {
    pub fn new() -> Self {
        Self
    }

    /// Check a single permission against the context.
    pub fn check(&self, ctx: &GatedContext, required: &str) -> PermissionCheckResult {
        // Suspended memberships always fail
        if ctx.membership.status == "suspended" {
            return PermissionCheckResult { allowed: false, source: None };
        }

        // Delegated agent: three-way intersection
        if let Some(ref delegation) = ctx.delegation {
            return self.check_delegated(ctx, delegation, required);
        }

        // Scoped identity (API key or client credentials): intersect with scopes
        if let Some(ref scopes) = ctx.scopes {
            if !scopes.is_empty() {
                return self.check_scoped(ctx, scopes, required);
            }
        }

        // Standard RBAC check
        self.check_standard(ctx, required)
    }

    /// Check multiple permissions, returning a map of results.
    pub fn check_many(
        &self,
        ctx: &GatedContext,
        required: &[String],
    ) -> Vec<(String, PermissionCheckResult)> {
        required
            .iter()
            .map(|perm| (perm.clone(), self.check(ctx, perm)))
            .collect()
    }

    /// Check that all required permissions are satisfied.
    pub fn check_all(&self, ctx: &GatedContext, required: &[String]) -> bool {
        required.iter().all(|perm| self.check(ctx, perm).allowed)
    }

    /// Check that any of the required permissions are satisfied.
    pub fn check_any(&self, ctx: &GatedContext, required: &[String]) -> bool {
        required.iter().any(|perm| self.check(ctx, perm).allowed)
    }

    fn check_standard(&self, ctx: &GatedContext, required: &str) -> PermissionCheckResult {
        if has_permission(&ctx.permissions, required) {
            let source = self.find_source(&ctx.permissions, required);
            PermissionCheckResult { allowed: true, source: Some(source) }
        } else {
            PermissionCheckResult { allowed: false, source: None }
        }
    }

    fn check_scoped(
        &self,
        ctx: &GatedContext,
        scopes: &[String],
        required: &str,
    ) -> PermissionCheckResult {
        let effective = intersect_permissions(&ctx.permissions, scopes);
        if has_permission(&effective, required) {
            PermissionCheckResult { allowed: true, source: Some("scoped".into()) }
        } else {
            PermissionCheckResult { allowed: false, source: None }
        }
    }

    fn check_delegated(
        &self,
        ctx: &GatedContext,
        delegation: &crate::types::DelegationContext,
        required: &str,
    ) -> PermissionCheckResult {
        // Check delegation expiry
        if let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(&delegation.expires_at) {
            if expires_at < Utc::now() {
                debug!(delegation_id = %delegation.id, "Delegation expired");
                return PermissionCheckResult { allowed: false, source: None };
            }
        } else {
            // Try ISO 8601 with timezone offset
            if let Ok(expires_at) = delegation.expires_at.parse::<chrono::DateTime<chrono::FixedOffset>>() {
                if expires_at < Utc::now() {
                    debug!(delegation_id = %delegation.id, "Delegation expired");
                    return PermissionCheckResult { allowed: false, source: None };
                }
            }
        }

        // Check uses remaining
        if let Some(uses_remaining) = delegation.uses_remaining {
            if uses_remaining <= 0 {
                debug!(delegation_id = %delegation.id, "Delegation uses exhausted");
                return PermissionCheckResult { allowed: false, source: None };
            }
        }

        // Three-way intersection:
        // Effective = DelegationScopes ∩ AgentPermissions(ctx.permissions)
        let effective = intersect_permissions(&delegation.scopes, &ctx.permissions);

        if has_permission(&effective, required) {
            PermissionCheckResult {
                allowed: true,
                source: Some(format!("delegation:{}", delegation.id)),
            }
        } else {
            PermissionCheckResult { allowed: false, source: None }
        }
    }

    fn find_source(&self, permissions: &[String], required: &str) -> String {
        for perm in permissions {
            if perm == required {
                return format!("permission:{}", perm);
            }
        }
        "wildcard".into()
    }
}

impl Default for PermissionChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn make_ctx(
        permissions: Vec<String>,
        status: &str,
        scopes: Option<Vec<String>>,
        delegation: Option<DelegationContext>,
    ) -> GatedContext {
        GatedContext {
            identity: Identity {
                id: "per_test".into(),
                identity_type: IdentityType::Human,
                auth_method: AuthMethod::Password,
                email: None,
                name: None,
                mfa_verified: None,
            },
            org: OrgContext { id: "org_test".into() },
            membership: MembershipContext {
                id: "mbr_test".into(),
                entity_type: EntityType::Person,
                is_owner: false,
                status: status.into(),
                groups: vec![],
            },
            roles: vec![],
            permissions,
            scopes,
            delegation,
        }
    }

    #[test]
    fn test_standard_allow() {
        let checker = PermissionChecker::new();
        let ctx = make_ctx(vec!["files:documents:read".into()], "active", None, None);
        assert!(checker.check(&ctx, "files:documents:read").allowed);
    }

    #[test]
    fn test_standard_deny() {
        let checker = PermissionChecker::new();
        let ctx = make_ctx(vec!["files:documents:read".into()], "active", None, None);
        assert!(!checker.check(&ctx, "files:documents:delete").allowed);
    }

    #[test]
    fn test_suspended_deny() {
        let checker = PermissionChecker::new();
        let ctx = make_ctx(vec!["*:*:*".into()], "suspended", None, None);
        assert!(!checker.check(&ctx, "files:documents:read").allowed);
    }

    #[test]
    fn test_wildcard_allow() {
        let checker = PermissionChecker::new();
        let ctx = make_ctx(vec!["files:*:*".into()], "active", None, None);
        assert!(checker.check(&ctx, "files:documents:delete").allowed);
    }

    #[test]
    fn test_scoped_deny() {
        let checker = PermissionChecker::new();
        let ctx = make_ctx(
            vec!["files:documents:read".into(), "files:documents:write".into()],
            "active",
            Some(vec!["files:documents:read".into()]),
            None,
        );
        assert!(!checker.check(&ctx, "files:documents:write").allowed);
    }
}
