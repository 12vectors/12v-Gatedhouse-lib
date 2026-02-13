//! Membership resolver — cache lookup with optional API fallback.

use crate::membership::cache::MembershipCacheTrait;
use crate::types::MembershipContext;

pub struct MembershipResolver<C: MembershipCacheTrait> {
    cache: C,
}

impl<C: MembershipCacheTrait> MembershipResolver<C> {
    pub fn new(cache: C) -> Self {
        Self { cache }
    }

    pub async fn resolve(&self, membership_id: &str) -> Option<MembershipContext> {
        match self.cache.find_by_id(membership_id).await {
            Ok(Some(cached)) => Some(MembershipContext {
                id: cached.membership_id,
                entity_type: cached.entity_type,
                is_owner: cached.is_owner,
                status: cached.status,
                groups: cached.groups,
            }),
            _ => None,
        }
    }
}
