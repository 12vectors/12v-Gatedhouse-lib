"""Audit logger — publishes authorization decision events."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from gatedhouse.core.config import ResolvedConfig
from gatedhouse.core.types import AuditEntry, GatehouseEvent
from gatedhouse.events.adapters import EventBusAdapter

logger = logging.getLogger("gatedhouse.audit")


class AuditLogger:
    """Publishes audit events for authorization decisions."""

    def __init__(self, config: ResolvedConfig, event_bus: EventBusAdapter) -> None:
        self._config = config
        self._event_bus = event_bus

    async def log(self, entry: AuditEntry) -> None:
        """Log an authorization decision."""
        if not self._config.audit.enabled:
            return

        if entry.result == "denied" and not self._config.audit.log_denied:
            return
        if entry.result == "allowed" and not self._config.audit.log_allowed:
            return

        event = GatehouseEvent(
            type="gatedhouse.permission.checked",
            timestamp=datetime.now(timezone.utc).isoformat(),
            data={
                "action": entry.action,
                "result": entry.result,
                "identity_id": entry.ctx.identity.id,
                "identity_type": entry.ctx.identity.type,
                "org_id": entry.ctx.org.id,
                "membership_id": entry.ctx.membership.id,
                "resource_type": entry.resource_type,
                "resource_id": entry.resource_id,
                "reason": entry.reason,
            },
        )

        try:
            await self._event_bus.publish("gatedhouse.audit", event)
        except Exception:
            logger.exception("Failed to publish audit event")
