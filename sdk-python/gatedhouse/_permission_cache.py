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
    TTL-expiring dict, bounded to ``max_entries`` entries. Expired entries
    are dropped when read, and swept whenever the cache reaches its bound;
    if it is still full of live entries, the oldest tenth is evicted. The
    bound matters because the org ID of a check often comes from the
    request, so callers could otherwise grow the cache without limit.

    Exposes counters for hits, misses, puts, and invalidations as
    runtime observability — and to let tests prove caching behaviour,
    not just outcomes.
    """

    DEFAULT_TTL = timedelta(seconds=60)
    #: Default bound on cached (identity, org) entries.
    DEFAULT_MAX_ENTRIES = 10_000

    def __init__(
        self,
        ttl: timedelta = DEFAULT_TTL,
        clock: Callable[[], datetime] | None = None,
        *,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError(f"max_entries must be an integer >= 1, got {max_entries!r}")
        self._ttl = ttl
        self._max_entries = max_entries
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._entries: dict[PermissionCacheKey, _Entry] = {}
        self._lock = Lock()
        self._hits = 0
        self._misses = 0
        self._puts = 0
        self._targeted_invalidations = 0
        self._wholesale_invalidations = 0
        self._evictions = 0

    @property
    def max_entries(self) -> int:
        """Most (identity, org) entries held at once."""
        return self._max_entries

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
            if len(self._entries) >= self._max_entries and key not in self._entries:
                self._make_room(expires_at - self._ttl)
            self._entries.pop(key, None)  # re-insert so the order stays oldest-first
            self._entries[key] = _Entry(snapshot, expires_at)
            self._puts += 1

    def _make_room(self, now: datetime) -> None:
        """Drops expired entries; if still full, evicts the oldest tenth.
        Called with the lock held."""
        before = len(self._entries)
        for k in [k for k, e in self._entries.items() if now > e.expires_at]:
            del self._entries[k]
        excess = len(self._entries) - self._max_entries + max(1, self._max_entries // 10)
        for k in list(self._entries)[:max(0, excess)]:
            del self._entries[k]
        self._evictions += before - len(self._entries)

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

    def eviction_count(self) -> int:
        """Entries removed to stay within ``max_entries``."""
        with self._lock:
            return self._evictions

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
            self._evictions = 0
            self._wholesale_invalidations = 0


class _Entry:

    __slots__ = ("permissions", "expires_at")

    def __init__(self, permissions: list[EffectivePermission], expires_at: datetime) -> None:
        self.permissions = permissions
        self.expires_at = expires_at
