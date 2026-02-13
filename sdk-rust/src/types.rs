//! Core type definitions for the Gatedhouse authorization library.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Identity Types ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityType {
    Human,
    Agent,
    Machine,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    Sso,
    Passkey,
    ClientCredentials,
    ApiKey,
    Workload,
    TokenExchange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    #[serde(rename = "type")]
    pub identity_type: IdentityType,
    pub auth_method: AuthMethod,
    pub email: Option<String>,
    pub name: Option<String>,
    pub mfa_verified: Option<bool>,
}

// ─── Organization ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgContext {
    pub id: String,
}

// ─── Membership ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Person,
    Agent,
    ServiceAccount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipContext {
    pub id: String,
    pub entity_type: EntityType,
    pub is_owner: bool,
    pub status: String,
    pub groups: Vec<String>,
}

// ─── Delegation ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationContext {
    pub id: String,
    pub delegator_id: String,
    pub delegator_membership_id: String,
    pub scopes: Vec<String>,
    pub constraints: HashMap<String, serde_json::Value>,
    pub expires_at: String,
    pub uses_remaining: Option<i64>,
}

// ─── GatedContext ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatedContext {
    pub identity: Identity,
    pub org: OrgContext,
    pub membership: MembershipContext,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub scopes: Option<Vec<String>>,
    pub delegation: Option<DelegationContext>,
}

// ─── Role Definition ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDefinition {
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    #[serde(default)]
    pub inherits: Vec<String>,
    #[serde(default)]
    pub is_system: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRole {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub inherits: Vec<String>,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Permission Check Result ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCheckResult {
    pub allowed: bool,
    pub source: Option<String>,
}

// ─── Events ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatehouseEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub timestamp: String,
    pub data: HashMap<String, serde_json::Value>,
}

// ─── Cached Types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedMembership {
    pub membership_id: String,
    pub org_id: String,
    pub entity_type: EntityType,
    pub entity_id: String,
    pub is_owner: bool,
    pub status: String,
    pub groups: Vec<String>,
    pub synced_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDelegation {
    pub delegation_id: String,
    pub agent_id: String,
    pub delegator_id: String,
    pub delegator_membership_id: String,
    pub org_id: String,
    pub scopes: Vec<String>,
    pub constraints: HashMap<String, serde_json::Value>,
    pub max_uses: Option<i64>,
    pub use_count: i64,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub synced_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedPermission {
    pub membership_id: String,
    pub permission: String,
    pub source: String,
}

// ─── Audit ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub action: String,
    pub result: String, // "allowed" or "denied"
    pub ctx: GatedContext,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub reason: Option<String>,
}
