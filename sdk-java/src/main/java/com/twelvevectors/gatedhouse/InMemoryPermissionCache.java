package com.twelvevectors.gatedhouse;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Default {@link PermissionCache}: a thread-safe, in-process,
 * TTL-expiring map. Backed by {@link ConcurrentHashMap}; lazy eviction
 * on read. Suitable for a single-instance application; for multiple
 * application instances that need a coherent shared view of cached
 * permissions, plug in a network cache (Memcached, Redis, etc.) by
 * implementing {@link PermissionCache} directly.
 *
 * <p>Exposes counters for hits, misses, puts, and invalidations as
 * runtime observability (and to let tests prove caching behavior, not
 * just outcomes).
 */
public final class InMemoryPermissionCache implements PermissionCache {

    /** Conservative default — covers brief bursts of activity for an
     *  identity while keeping the window for stale data after an
     *  out-of-band schema edit short. */
    public static final Duration DEFAULT_TTL = Duration.ofSeconds(60);

    private final Duration ttl;
    private final Clock clock;
    private final ConcurrentMap<Key, Entry> entries = new ConcurrentHashMap<>();

    private final AtomicLong hits   = new AtomicLong();
    private final AtomicLong misses = new AtomicLong();
    private final AtomicLong puts   = new AtomicLong();
    private final AtomicLong targetedInvalidations  = new AtomicLong();
    private final AtomicLong wholesaleInvalidations = new AtomicLong();

    public InMemoryPermissionCache() {
        this(DEFAULT_TTL, Clock.systemUTC());
    }

    public InMemoryPermissionCache(Duration ttl) {
        this(ttl, Clock.systemUTC());
    }

    InMemoryPermissionCache(Duration ttl, Clock clock) {
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public Optional<List<EffectivePermission>> get(String identityId, String orgId) {
        Key key = new Key(identityId, orgId);
        Entry entry = entries.get(key);
        if (entry == null) {
            misses.incrementAndGet();
            return Optional.empty();
        }
        if (clock.instant().isAfter(entry.expiresAt)) {
            entries.remove(key, entry);
            misses.incrementAndGet();
            return Optional.empty();
        }
        hits.incrementAndGet();
        return Optional.of(entry.permissions);
    }

    @Override
    public void put(String identityId, String orgId, List<EffectivePermission> permissions) {
        Instant expiresAt = clock.instant().plus(ttl);
        entries.put(
            new Key(identityId, orgId),
            new Entry(List.copyOf(permissions), expiresAt));
        puts.incrementAndGet();
    }

    @Override
    public void invalidate(String identityId, String orgId) {
        if (entries.remove(new Key(identityId, orgId)) != null) {
            targetedInvalidations.incrementAndGet();
        }
    }

    @Override
    public void invalidateAll() {
        entries.clear();
        wholesaleInvalidations.incrementAndGet();
    }

    // ---- observability ----------------------------------------------------

    /** Cumulative cache hits since instantiation (or last {@link #resetStats}). */
    public long hitCount() {
        return hits.get();
    }

    /** Cumulative cache misses since instantiation (or last {@link #resetStats}). */
    public long missCount() {
        return misses.get();
    }

    /** Cumulative {@code put} calls (each cold-read populates one entry). */
    public long putCount() {
        return puts.get();
    }

    /** Cumulative targeted invalidations that actually evicted a value. */
    public long targetedInvalidationCount() {
        return targetedInvalidations.get();
    }

    /** Cumulative wholesale {@code invalidateAll} calls. */
    public long wholesaleInvalidationCount() {
        return wholesaleInvalidations.get();
    }

    /** Current number of entries in the cache (including expired-but-not-yet-evicted). */
    public int size() {
        return entries.size();
    }

    /**
     * Resets all counters to zero. Does not touch cached entries.
     * Intended for diagnostic use and test harnesses.
     */
    public void resetStats() {
        hits.set(0);
        misses.set(0);
        puts.set(0);
        targetedInvalidations.set(0);
        wholesaleInvalidations.set(0);
    }

    private record Key(String identityId, String orgId) {
    }

    private record Entry(List<EffectivePermission> permissions, Instant expiresAt) {
    }
}
