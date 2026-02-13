//! Role repository — CRUD for role definitions with org + system scoping.

use crate::types::{RoleDefinition, StoredRole};
use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RoleError {
    #[error("Role not found: {0}")]
    NotFound(String),
    #[error("Database error: {0}")]
    Database(String),
}

#[async_trait]
pub trait RoleRepositoryTrait: Send + Sync {
    async fn seed_base_roles(&self, org_id: &str, roles: &[RoleDefinition]) -> Result<(), RoleError>;
    async fn create(&self, org_id: &str, role: &RoleDefinition) -> Result<StoredRole, RoleError>;
    async fn find_by_id(&self, org_id: &str, role_id: &str) -> Result<Option<StoredRole>, RoleError>;
    async fn resolve(&self, org_id: &str, role_id: &str) -> Result<Option<StoredRole>, RoleError>;
    async fn list_for_org(&self, org_id: &str) -> Result<Vec<StoredRole>, RoleError>;
    async fn update(&self, org_id: &str, role_id: &str, role: &RoleDefinition) -> Result<Option<StoredRole>, RoleError>;
    async fn delete(&self, org_id: &str, role_id: &str) -> Result<bool, RoleError>;
    async fn delete_all_for_org(&self, org_id: &str) -> Result<(), RoleError>;
}
