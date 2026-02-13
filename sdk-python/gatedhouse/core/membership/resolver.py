"""Membership resolver — cache lookup with Citadel API fallback."""

from __future__ import annotations

import logging
from typing import Any

from gatedhouse.core.types import MembershipContext
from gatedhouse.core.membership.cache import MembershipCache

logger = logging.getLogger("gatedhouse.membership.resolver")


class MembershipResolver:
    """Resolves membership context from cache, with optional Citadel fallback."""

    def __init__(self, cache: MembershipCache) -> None:
        self._cache = cache

    async def resolve(self, membership_id: str) -> MembershipContext | None:
        """Resolve a membership context from cache."""
        cached = await self._cache.find_by_id(membership_id)
        if not cached:
            return None

        return MembershipContext(
            id=cached.membership_id,
            entity_type=cached.entity_type,
            is_owner=cached.is_owner,
            status=cached.status,
            groups=tuple(cached.groups),
        )
