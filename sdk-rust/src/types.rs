// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Immutable value types used across the public API.

use std::collections::HashMap;
use std::time::SystemTime;

use serde_json::Value;

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
