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
    def get_or_load(
        self,
        identity_id: str,
        org_id: str,
        loader: Callable[[], list[EffectivePermission]],
    ) -> list[EffectivePermission]:
        """Atomic read-through: return the cached list for ``(identity_id,
        org_id)``, or call *loader* and cache its result. This is the *only*
        read path — there is no separate get/put pair, precisely so a caller
        cannot reintroduce the stale-repopulate race below.

        **Revocation-safety contract:** an implementation must not cache a value
        produced by a *loader* run that a concurrent :meth:`invalidate` /
        :meth:`invalidate_all` overlapped — otherwise a load that observed a
        pre-revocation snapshot can be stored after the invalidation and serve a
        revoked permission for the full TTL. :class:`InMemoryPermissionCache`
        enforces this with a generation fence.
        """

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
        # Monotonic version bumped on every invalidation; get_or_load refuses to
        # store a result loaded across a bump (the H1 stale-repopulate race).
        self._generation = 0
        self._hits = 0
        self._misses = 0
        self._puts = 0
        self._targeted_invalidations = 0
        self._wholesale_invalidations = 0

    # ---- PermissionCache --------------------------------------------------

    def get_or_load(
        self,
        identity_id: str,
        org_id: str,
        loader: Callable[[], list[EffectivePermission]],
    ) -> list[EffectivePermission]:
        key = PermissionCacheKey(identity_id, org_id)
        now = self._clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and now <= entry.expires_at:
                self._hits += 1
                return entry.permissions
            if entry is not None:
                self._entries.pop(key, None)  # expired
            self._misses += 1
            gen_at_load = self._generation

        # Load OUTSIDE the lock — the DB round-trip must not block other callers.
        fresh = list(loader())
        expires_at = self._clock() + self._ttl

        with self._lock:
            # Store only if no invalidation raced the load; else a stale value
            # could outlive a revoke. The next read simply reloads.
            if self._generation == gen_at_load:
                self._entries[key] = _Entry(fresh, expires_at)
                self._puts += 1
        return fresh

    def invalidate(self, identity_id: str, org_id: str) -> None:
        key = PermissionCacheKey(identity_id, org_id)
        with self._lock:
            # Bump the generation first so any in-flight get_or_load refuses to
            # cache its (now potentially stale) result.
            self._generation += 1
            if self._entries.pop(key, None) is not None:
                self._targeted_invalidations += 1

    def invalidate_all(self) -> None:
        with self._lock:
            self._generation += 1
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
