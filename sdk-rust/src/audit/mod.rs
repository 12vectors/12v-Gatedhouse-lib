//! Audit logger — publishes authorization decision events.

use crate::config::ResolvedConfig;
use crate::types::AuditEntry;

pub struct AuditLogger {
    config: ResolvedConfig,
}

impl AuditLogger {
    pub fn new(config: ResolvedConfig) -> Self {
        Self { config }
    }

    pub fn log(&self, entry: &AuditEntry) {
        if !self.config.audit.enabled {
            return;
        }

        if entry.result == "denied" && !self.config.audit.log_denied {
            return;
        }
        if entry.result == "allowed" && !self.config.audit.log_allowed {
            return;
        }

        tracing::info!(
            action = %entry.action,
            result = %entry.result,
            identity_id = %entry.ctx.identity.id,
            org_id = %entry.ctx.org.id,
            "Authorization decision"
        );
    }
}
