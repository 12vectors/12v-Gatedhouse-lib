//! Membership cache — trait for PostgreSQL-backed cache.

use async_trait::async_trait;
use crate::types::CachedMembership;

#[async_trait]
pub trait MembershipCacheTrait: Send + Sync {
    async fn upsert(&self, membership: &CachedMembership) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn find_by_id(&self, membership_id: &str) -> Result<Option<CachedMembership>, Box<dyn std::error::Error + Send + Sync>>;
    async fn update_status(&self, membership_id: &str, status: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn add_group(&self, membership_id: &str, group_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn remove_group(&self, membership_id: &str, group_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn remove_group_from_all(&self, group_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn remove(&self, membership_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn remove_all_for_org(&self, org_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn suspend_all_for_org(&self, org_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn reactivate_all_for_org(&self, org_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn list_by_org(&self, org_id: &str) -> Result<Vec<CachedMembership>, Box<dyn std::error::Error + Send + Sync>>;
}
