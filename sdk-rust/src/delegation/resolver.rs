//! Delegation resolver — validates delegation and returns DelegationContext.

use chrono::Utc;
use tracing::debug;

use crate::delegation::cache::DelegationCacheTrait;
use crate::types::DelegationContext;

pub struct DelegationResolver<C: DelegationCacheTrait> {
    cache: C,
}

impl<C: DelegationCacheTrait> DelegationResolver<C> {
    pub fn new(cache: C) -> Self {
        Self { cache }
    }

    pub async fn resolve(&self, delegation_id: &str) -> Option<DelegationContext> {
        let cached = match self.cache.find_active(delegation_id).await {
            Ok(Some(c)) => c,
            _ => return None,
        };

        if cached.expires_at < Utc::now() {
            debug!(delegation_id, "Delegation expired");
            let _ = self.cache.update_status(delegation_id, "expired").await;
            return None;
        }

        if let Some(max_uses) = cached.max_uses {
            if cached.use_count >= max_uses {
                debug!(delegation_id, "Delegation exhausted");
                let _ = self.cache.update_status(delegation_id, "exhausted").await;
                return None;
            }
        }

        let uses_remaining = cached.max_uses.map(|max| max - cached.use_count);

        Some(DelegationContext {
            id: cached.delegation_id,
            delegator_id: cached.delegator_id,
            delegator_membership_id: cached.delegator_membership_id,
            scopes: cached.scopes,
            constraints: cached.constraints,
            expires_at: cached.expires_at.to_rfc3339(),
            uses_remaining,
        })
    }
}
