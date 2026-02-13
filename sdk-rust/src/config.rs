//! Gatedhouse configuration types and validation.

use crate::types::RoleDefinition;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Gatedhouse: jwks_url is required")]
    MissingJwksUrl,
    #[error("Gatedhouse: database.connection_string is required")]
    MissingConnectionString,
    #[error("Gatedhouse: service name is required")]
    MissingService,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub connection_string: String,
    #[serde(default = "default_migrations_table")]
    pub migrations_table: String,
    #[serde(default = "default_table_prefix")]
    pub table_prefix: String,
    #[serde(default = "default_pool_min")]
    pub pool_min: u32,
    #[serde(default = "default_pool_max")]
    pub pool_max: u32,
}

fn default_migrations_table() -> String { "gatedhouse_migrations".into() }
fn default_table_prefix() -> String { "gatedhouse_".into() }
fn default_pool_min() -> u32 { 2 }
fn default_pool_max() -> u32 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBusConfig {
    #[serde(default = "default_adapter")]
    pub adapter: String,
    pub topics: Option<Vec<String>>,
    pub brokers: Option<Vec<String>>,
    pub group_id: Option<String>,
    pub url: Option<String>,
    pub exchange: Option<String>,
}

fn default_adapter() -> String { "noop".into() }

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            adapter: default_adapter(),
            topics: None,
            brokers: None,
            group_id: None,
            url: None,
            exchange: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub log_denied: bool,
    #[serde(default)]
    pub log_allowed: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self { enabled: true, log_denied: true, log_allowed: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_60")]
    pub cache_ttl: u64,
    #[serde(default)]
    pub validate_live: bool,
    #[serde(default = "default_identity_types")]
    pub allowed_identity_types: Vec<String>,
}

impl Default for DelegationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_ttl: 60,
            validate_live: false,
            allowed_identity_types: default_identity_types(),
        }
    }
}

fn default_true() -> bool { true }
fn default_60() -> u64 { 60 }
fn default_identity_types() -> Vec<String> {
    vec!["human".into(), "agent".into(), "machine".into()]
}

fn default_base_roles() -> Vec<RoleDefinition> {
    vec![
        RoleDefinition {
            key: "owner".into(),
            name: "Owner".into(),
            description: Some("Organization owner with full access".into()),
            permissions: vec!["*:*:*".into()],
            inherits: vec![],
            is_system: true,
        },
        RoleDefinition {
            key: "admin".into(),
            name: "Administrator".into(),
            description: Some("Organization administrator".into()),
            permissions: vec!["*:*:*".into()],
            inherits: vec![],
            is_system: true,
        },
        RoleDefinition {
            key: "member".into(),
            name: "Member".into(),
            description: Some("Regular organization member".into()),
            permissions: vec![],
            inherits: vec![],
            is_system: true,
        },
        RoleDefinition {
            key: "viewer".into(),
            name: "Viewer".into(),
            description: Some("Read-only access".into()),
            permissions: vec![],
            inherits: vec![],
            is_system: true,
        },
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatehouseConfig {
    pub jwks_url: String,
    pub database: DatabaseConfig,
    pub service: String,
    #[serde(default = "default_3600")]
    pub jwks_cache_ttl: u64,
    pub event_bus: Option<EventBusConfig>,
    #[serde(default = "default_org_header")]
    pub org_header: String,
    #[serde(default = "default_true")]
    pub org_required: bool,
    #[serde(default = "default_cache_miss_strategy")]
    pub cache_miss_strategy: String,
    #[serde(default = "default_60")]
    pub cache_miss_ttl: u64,
    #[serde(default = "default_300")]
    pub resolved_permissions_cache_ttl: u64,
    pub audit: Option<AuditConfig>,
    pub base_roles: Option<Vec<RoleDefinition>>,
    #[serde(default = "default_member")]
    pub default_role: String,
    pub citadel_base_url: Option<String>,
    pub delegation: Option<DelegationConfig>,
}

fn default_3600() -> u64 { 3600 }
fn default_300() -> u64 { 300 }
fn default_org_header() -> String { "X-Org-Id".into() }
fn default_cache_miss_strategy() -> String { "fetch".into() }
fn default_member() -> String { "member".into() }

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub jwks_url: String,
    pub jwks_cache_ttl: u64,
    pub database: DatabaseConfig,
    pub event_bus: EventBusConfig,
    pub service: String,
    pub org_header: String,
    pub org_required: bool,
    pub cache_miss_strategy: String,
    pub cache_miss_ttl: u64,
    pub resolved_permissions_cache_ttl: u64,
    pub audit: AuditConfig,
    pub base_roles: Vec<RoleDefinition>,
    pub default_role: String,
    pub citadel_base_url: Option<String>,
    pub delegation: DelegationConfig,
}

pub fn resolve_config(config: GatehouseConfig) -> Result<ResolvedConfig, ConfigError> {
    if config.jwks_url.is_empty() {
        return Err(ConfigError::MissingJwksUrl);
    }
    if config.database.connection_string.is_empty() {
        return Err(ConfigError::MissingConnectionString);
    }
    if config.service.is_empty() {
        return Err(ConfigError::MissingService);
    }

    Ok(ResolvedConfig {
        jwks_url: config.jwks_url,
        jwks_cache_ttl: config.jwks_cache_ttl,
        database: config.database,
        event_bus: config.event_bus.unwrap_or_default(),
        service: config.service,
        org_header: config.org_header,
        org_required: config.org_required,
        cache_miss_strategy: config.cache_miss_strategy,
        cache_miss_ttl: config.cache_miss_ttl,
        resolved_permissions_cache_ttl: config.resolved_permissions_cache_ttl,
        audit: config.audit.unwrap_or_default(),
        base_roles: config.base_roles.unwrap_or_else(default_base_roles),
        default_role: config.default_role,
        citadel_base_url: config.citadel_base_url,
        delegation: config.delegation.unwrap_or_default(),
    })
}
