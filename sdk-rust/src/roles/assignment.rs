//! Role assignment manager — assign/revoke roles to memberships and groups.

use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AssignmentError {
    #[error("Database error: {0}")]
    Database(String),
}

#[async_trait]
pub trait RoleAssignmentTrait: Send + Sync {
    async fn assign(&self, membership_id: &str, role_id: &str, org_id: &str, assigned_by: Option<&str>) -> Result<(), AssignmentError>;
    async fn revoke(&self, membership_id: &str, role_id: &str) -> Result<(), AssignmentError>;
    async fn get_role_ids(&self, membership_id: &str) -> Result<Vec<String>, AssignmentError>;
    async fn assign_to_group(&self, group_id: &str, role_id: &str, org_id: &str, assigned_by: Option<&str>) -> Result<(), AssignmentError>;
    async fn revoke_from_group(&self, group_id: &str, role_id: &str) -> Result<(), AssignmentError>;
    async fn get_role_ids_for_groups(&self, group_ids: &[String]) -> Result<Vec<String>, AssignmentError>;
    async fn delete_all_for_membership(&self, membership_id: &str) -> Result<(), AssignmentError>;
    async fn delete_all_for_org(&self, org_id: &str) -> Result<(), AssignmentError>;
    async fn delete_all_group_roles_for_org(&self, org_id: &str) -> Result<(), AssignmentError>;
    async fn delete_all_for_group(&self, group_id: &str) -> Result<(), AssignmentError>;
}
