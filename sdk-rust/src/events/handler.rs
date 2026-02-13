//! Event handler — processes Citadel and Sphinx events to keep local caches in sync.

use tracing::{info, debug};

use crate::types::GatehouseEvent;
use crate::events::types as ET;

/// Dispatches events to the appropriate handler.
/// In a full implementation, this would hold references to caches,
/// repositories, and resolvers. For now it defines the dispatch logic.
pub struct EventHandlerRegistry;

impl EventHandlerRegistry {
    pub fn new() -> Self {
        Self
    }

    /// Process an incoming event. Idempotent by design.
    pub async fn handle(&self, event: &GatehouseEvent) {
        match event.event_type.as_str() {
            ET::ORG_CREATED => info!("Handling org.created"),
            ET::ORG_DELETED => info!("Handling org.deleted"),
            ET::ORG_SUSPENDED => info!("Handling org.suspended"),
            ET::ORG_REACTIVATED => info!("Handling org.reactivated"),
            ET::MEMBERSHIP_CREATED => info!("Handling membership.created"),
            ET::MEMBERSHIP_UPDATED => info!("Handling membership.updated"),
            ET::MEMBERSHIP_SUSPENDED => info!("Handling membership.suspended"),
            ET::MEMBERSHIP_REACTIVATED => info!("Handling membership.reactivated"),
            ET::MEMBERSHIP_REMOVED => info!("Handling membership.removed"),
            ET::GROUP_MEMBER_ADDED => info!("Handling group.member.added"),
            ET::GROUP_MEMBER_REMOVED => info!("Handling group.member.removed"),
            ET::GROUP_DELETED => info!("Handling group.deleted"),
            ET::DELEGATION_CREATED => info!("Handling delegation.created"),
            ET::DELEGATION_REVOKED => info!("Handling delegation.revoked"),
            ET::DELEGATION_EXPIRED => info!("Handling delegation.expired"),
            ET::DELEGATION_EXHAUSTED => info!("Handling delegation.exhausted"),
            ET::AGENT_DEACTIVATED => info!("Handling agent.deactivated"),
            _ => debug!(event_type = %event.event_type, "Unknown event type, ignoring"),
        }
    }
}

impl Default for EventHandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}
