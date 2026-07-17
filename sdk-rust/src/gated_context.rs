// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Type-safe view over a verified Sphinx token's claims.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::types::AuthenticatedSubject;

/// Representation of a verified Sphinx token's request context.
///
/// A type-safe wrapper around the generic authenticated subject and its
/// claims. Mirrors the Java `GatedContext` record.
#[derive(Debug, Clone)]
pub struct GatedContext {
    pub person_id: String,
    pub email: Option<String>,
    pub role: Option<String>,
    /// Defaults to `"human"` when the `person_type` claim is absent.
    pub identity_type: String,
    pub auth_method: Option<String>,
    pub mfa_verified: bool,
    pub email_verified: bool,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub delegation_id: Option<String>,
    pub actor_claims: Option<Map<String, Value>>,
    pub raw_claims: HashMap<String, Value>,
}

impl GatedContext {
    /// True if the role is `"admin"`.
    pub fn is_admin(&self) -> bool {
        self.role.as_deref() == Some("admin")
    }

    /// True if the identity type is `"human"`.
    pub fn is_human(&self) -> bool {
        self.identity_type == "human"
    }

    /// True if a delegation ID is present.
    pub fn is_delegated(&self) -> bool {
        self.delegation_id.is_some()
    }

    /// True if the token's space-separated scope list contains
    /// `required_scope`.
    pub fn has_scope(&self, required_scope: &str) -> bool {
        self.scope
            .as_deref()
            .map(|s| s.split_whitespace().any(|part| part == required_scope))
            .unwrap_or(false)
    }

    /// Construct a `GatedContext` from an [`AuthenticatedSubject`].
    pub fn from_subject(subject: &AuthenticatedSubject) -> Self {
        let claims = &subject.claims;
        let str_claim = |name: &str| claims.get(name).and_then(Value::as_str).map(str::to_string);
        let bool_claim = |name: &str| claims.get(name).and_then(Value::as_bool) == Some(true);
        Self {
            person_id: subject.id.clone(),
            email: str_claim("email"),
            role: str_claim("role"),
            identity_type: str_claim("person_type").unwrap_or_else(|| "human".to_string()),
            auth_method: str_claim("auth_method"),
            mfa_verified: bool_claim("mfa_verified"),
            email_verified: bool_claim("email_verified"),
            client_id: str_claim("client_id"),
            scope: str_claim("scope"),
            delegation_id: str_claim("delegation_id"),
            actor_claims: claims.get("act").and_then(Value::as_object).cloned(),
            raw_claims: claims.clone(),
        }
    }
}
