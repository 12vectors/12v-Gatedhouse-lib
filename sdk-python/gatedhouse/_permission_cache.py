# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Pluggable cache for the per-identity effective permission set."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Callable

from ._types import EffectivePermission, PermissionCacheKey


class PermissionCache(ABC):
    """Sits in front of the recursive-CTE permission-resolution query.

    The library ships an :class:`InMemoryPermissionCache` default. Hosts
    that need a shared cache (Redis, Memcached, etc.) implement this
    interface against their cache client and pass it to
    ``GatedhouseConfig(permission_cache=...)``.

    Implementations must be safe for concurrent use by multiple threads.
    """

    @abstractmethod
    def get(self, identity_id: str, org_id: str) -> list[EffectivePermission] | None:
        """Return the cached list for ``(identity_id, org_id)``, or
        ``None`` on miss / expiry."""

    @abstractmethod
    def put(self, identity_id: str, org_id: str,
            permissions: list[EffectivePermission]) -> None:
        """Cache the effective-permission list. Implementations should
        treat the supplied list as immutable (copy if needed)."""

    @abstractmethod
    def invalidate(self, identity_id: str, org_id: str) -> None:
        """Drop the cache entry for one identity in one org."""

    @abstractmethod
    def invalidate_all(self) -> None:
        """Drop every cached entry."""


class InMemoryPermissionCache(PermissionCache):
    """Default :class:`PermissionCache`: thread-safe, in-process,
    TTL-expiring dict. Lazy eviction on read.

    Exposes counters for hits, misses, puts, and invalidations as
    runtime observability — and to let tests prove caching behaviour,
    not just outcomes.
    """

    DEFAULT_TTL = timedelta(seconds=60)

    def __init__(
        self,
        ttl: timedelta = DEFAULT_TTL,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._ttl = ttl
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._entries: dict[PermissionCacheKey, _Entry] = {}
        self._lock = Lock()
        self._hits = 0
        self._misses = 0
        self._puts = 0
        self._targeted_invalidations = 0
        self._wholesale_invalidations = 0

    # ---- PermissionCache --------------------------------------------------

    def get(self, identity_id: str, org_id: str) -> list[EffectivePermission] | None:
        key = PermissionCacheKey(identity_id, org_id)
        now = self._clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._misses += 1
                return None
            if now > entry.expires_at:
                self._entries.pop(key, None)
                self._misses += 1
                return None
            self._hits += 1
            return entry.permissions

    def put(self, identity_id: str, org_id: str,
            permissions: list[EffectivePermission]) -> None:
        key = PermissionCacheKey(identity_id, org_id)
        expires_at = self._clock() + self._ttl
        # Defensive copy so a later mutation by the caller can't poison
        # the cache.
        snapshot = list(permissions)
        with self._lock:
            self._entries[key] = _Entry(snapshot, expires_at)
            self._puts += 1

    def invalidate(self, identity_id: str, org_id: str) -> None:
        key = PermissionCacheKey(identity_id, org_id)
        with self._lock:
            if self._entries.pop(key, None) is not None:
                self._targeted_invalidations += 1

    def invalidate_all(self) -> None:
        with self._lock:
            self._entries.clear()
            self._wholesale_invalidations += 1

    # ---- observability ----------------------------------------------------

    def hit_count(self) -> int:
        with self._lock:
            return self._hits

    def miss_count(self) -> int:
        with self._lock:
            return self._misses

    def put_count(self) -> int:
        with self._lock:
            return self._puts

    def targeted_invalidation_count(self) -> int:
        with self._lock:
            return self._targeted_invalidations

    def wholesale_invalidation_count(self) -> int:
        with self._lock:
            return self._wholesale_invalidations

    def size(self) -> int:
        with self._lock:
            return len(self._entries)

    def reset_stats(self) -> None:
        """Reset all counters to zero. Does not touch cached entries."""
        with self._lock:
            self._hits = 0
            self._misses = 0
            self._puts = 0
            self._targeted_invalidations = 0
            self._wholesale_invalidations = 0


class _Entry:

    __slots__ = ("permissions", "expires_at")

    def __init__(self, permissions: list[EffectivePermission], expires_at: datetime) -> None:
        self.permissions = permissions
        self.expires_at = expires_at
