"""Delegation resolver — validates delegation and returns DelegationContext."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from gatedhouse.core.types import DelegationContext
from gatedhouse.core.delegation.cache import DelegationCache

logger = logging.getLogger("gatedhouse.delegation.resolver")


class DelegationResolver:
    """Resolves active delegations from cache."""

    def __init__(self, cache: DelegationCache) -> None:
        self._cache = cache

    async def resolve(self, delegation_id: str) -> DelegationContext | None:
        """Resolve a delegation, validating expiry and use count."""
        cached = await self._cache.find_active(delegation_id)
        if not cached:
            return None

        # Check expiry
        if cached.expires_at < datetime.now(timezone.utc):
            logger.debug("Delegation %s expired", delegation_id)
            await self._cache.update_status(delegation_id, "expired")
            return None

        # Check use count
        if cached.max_uses is not None and cached.use_count >= cached.max_uses:
            logger.debug("Delegation %s exhausted", delegation_id)
            await self._cache.update_status(delegation_id, "exhausted")
            return None

        return DelegationContext(
            id=cached.delegation_id,
            delegator_id=cached.delegator_id,
            delegator_membership_id=cached.delegator_membership_id,
            scopes=tuple(cached.scopes),
            constraints=cached.constraints,
            expires_at=cached.expires_at.isoformat(),
            uses_remaining=(
                cached.max_uses - cached.use_count if cached.max_uses is not None else None
            ),
        )
