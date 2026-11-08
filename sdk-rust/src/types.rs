// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Immutable value types used across the public API.

use std::collections::HashMap;
use std::time::SystemTime;

use serde_json::Value;

use crate::enums::MembershipStatus;

/// A single permission tuple as it appears on a role grant. Any of the
/// three components may be `None`, denoting a wildcard at that level.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EffectivePermission {
    pub service: Option<String>,
    pub resource: Option<String>,
    pub action: Option<String>,
}

impl EffectivePermission {
    pub fn new(
        service: Option<String>,
        resource: Option<String>,
        action: Option<String>,
    ) -> Self {
        Self {
            service,
            resource,
            action,
        }
    }
}

/// Composite key used by `PermissionCache` implementations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PermissionCacheKey {
    pub identity_id: String,
    pub org_id: String,
}

impl PermissionCacheKey {
    pub fn new(identity_id: impl Into<String>, org_id: impl Into<String>) -> Self {
        Self {
            identity_id: identity_id.into(),
            org_id: org_id.into(),
        }
    }
}

/// Trusted output of a successful `Gatedhouse::verify_token` call. The
/// `id` is the JWT `sub` claim — pass it to `Gatedhouse::has_permission`
/// as the authenticated identity.
#[derive(Debug, Clone)]
pub struct AuthenticatedSubject {
    pub id: String,
    pub issuer: String,
    pub audience: String,
    pub issued_at: Option<SystemTime>,
    pub expires_at: SystemTime,
    pub token_type: Option<String>,
    pub claims: HashMap<String, Value>,
}

// ---- permission explanations (docs/MODEL.md, "Explaining a decision") ----

/// Where the first role in a [`GrantPath`] comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantSource {
    /// Assigned directly to the identity.
    Direct,
    /// Assigned to a group the identity belongs to.
    Group,
}

/// The decision a [`PermissionExplanation`] reports, and for a denial, why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExplanationOutcome {
    /// An active membership and at least one granting path.
    Allowed,
    /// No membership in the org. Any paths are grants with no effect.
    NoMembership,
    /// The membership is not active. The paths show what would apply if it were.
    MembershipNotActive,
    /// An active membership, but nothing grants the permission.
    NoMatchingGrant,
}

/// One path through which an identity holds a permission, as reported by
/// [`Gatedhouse::explain_permission`](crate::Gatedhouse::explain_permission).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantPath {
    /// Whether the first role in the chain is assigned directly or to a group.
    pub source: GrantSource,
    /// The group the role is assigned to; `None` for [`GrantSource::Direct`].
    pub group_id: Option<String>,
    /// The assigned role first, then each inherited parent, ending with the
    /// role that holds `grant`. Never empty.
    pub role_chain: Vec<String>,
    /// The matching grant held by the last role; components may be `None`
    /// (wildcards).
    pub grant: EffectivePermission,
}

impl GrantPath {
    /// The role assigned to the identity, or to its group.
    pub fn assigned_role(&self) -> &str {
        &self.role_chain[0]
    }

    /// The role that holds the matching grant.
    pub fn granting_role(&self) -> &str {
        &self.role_chain[self.role_chain.len() - 1]
    }
}

/// Why a permission is granted or denied, as reported by
/// [`Gatedhouse::explain_permission`](crate::Gatedhouse::explain_permission).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionExplanation {
    /// The decision and its reason.
    pub outcome: ExplanationOutcome,
    /// The membership status in the org; `None` if there is no membership.
    pub membership_status: Option<MembershipStatus>,
    /// Every path that would grant the permission, reported even when the
    /// decision is a denial.
    pub paths: Vec<GrantPath>,
}

impl PermissionExplanation {
    /// True iff the permission is granted; agrees with
    /// [`Gatedhouse::has_permission`](crate::Gatedhouse::has_permission).
    pub fn allowed(&self) -> bool {
        self.outcome == ExplanationOutcome::Allowed
    }
}
