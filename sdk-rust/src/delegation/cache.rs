//! Delegation cache — trait for PostgreSQL-backed cache.

use async_trait::async_trait;
use crate::types::CachedDelegation;

#[async_trait]
pub trait DelegationCacheTrait: Send + Sync {
    async fn upsert(&self, delegation: &CachedDelegation) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn find_active(&self, delegation_id: &str) -> Result<Option<CachedDelegation>, Box<dyn std::error::Error + Send + Sync>>;
    async fn update_status(&self, delegation_id: &str, status: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn revoke_all_for_agent(&self, agent_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn remove_all_for_org(&self, org_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}
