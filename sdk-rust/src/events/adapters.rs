//! Event bus adapters.

use async_trait::async_trait;
use crate::types::GatehouseEvent;

#[async_trait]
pub trait EventBusAdapter: Send + Sync {
    async fn subscribe(&self, topics: &[String], handler: fn(&GatehouseEvent)) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn publish(&self, topic: &str, event: &GatehouseEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn disconnect(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// In-memory event bus for testing and development.
pub struct InMemoryEventBus;

#[async_trait]
impl EventBusAdapter for InMemoryEventBus {
    async fn subscribe(&self, _topics: &[String], _handler: fn(&GatehouseEvent)) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn publish(&self, _topic: &str, _event: &GatehouseEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn disconnect(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

/// No-op event bus that silently discards events.
pub struct NoopEventBus;

#[async_trait]
impl EventBusAdapter for NoopEventBus {
    async fn subscribe(&self, _topics: &[String], _handler: fn(&GatehouseEvent)) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn publish(&self, _topic: &str, _event: &GatehouseEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn disconnect(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}
