// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

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
 * TTL-expiring map, bounded to {@link #maxEntries()} entries. Backed by
 * {@link ConcurrentHashMap}. Expired entries are dropped when read, and swept
 * whenever the cache reaches its bound; if it is still full of live entries,
 * an arbitrary tenth is evicted. The bound matters because the org ID of a
 * check often comes from the request, so callers could otherwise grow the
 * cache without limit. Suitable for a single-instance application; for multiple
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

    /** Default bound on cached (identity, org) entries. */
    public static final int DEFAULT_MAX_ENTRIES = 10_000;

    private final Duration ttl;
    private final int maxEntries;
    private final Clock clock;
    private final ConcurrentMap<Key, Entry> entries = new ConcurrentHashMap<>();

    private final AtomicLong hits   = new AtomicLong();
    private final AtomicLong misses = new AtomicLong();
    private final AtomicLong puts   = new AtomicLong();
    private final AtomicLong targetedInvalidations  = new AtomicLong();
    private final AtomicLong wholesaleInvalidations = new AtomicLong();
    private final AtomicLong evictions = new AtomicLong();

    public InMemoryPermissionCache() {
        this(DEFAULT_TTL, DEFAULT_MAX_ENTRIES, Clock.systemUTC());
    }

    public InMemoryPermissionCache(Duration ttl) {
        this(ttl, DEFAULT_MAX_ENTRIES, Clock.systemUTC());
    }

    /**
     * @param maxEntries most (identity, org) entries held at once; at least 1
     */
    public InMemoryPermissionCache(Duration ttl, int maxEntries) {
        this(ttl, maxEntries, Clock.systemUTC());
    }

    InMemoryPermissionCache(Duration ttl, Clock clock) {
        this(ttl, DEFAULT_MAX_ENTRIES, clock);
    }

    InMemoryPermissionCache(Duration ttl, int maxEntries, Clock clock) {
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be at least 1");
        }
        this.maxEntries = maxEntries;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Most (identity, org) entries held at once. */
    public int maxEntries() {
        return maxEntries;
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
        Instant now = clock.instant();
        Key key = new Key(identityId, orgId);
        if (entries.size() >= maxEntries && !entries.containsKey(key)) {
            makeRoom(now);
        }
        Instant expiresAt = now.plus(ttl);
        entries.put(
            key,
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

    /** Drops expired entries; if still full, evicts an arbitrary tenth. */
    private void makeRoom(Instant now) {
        int before = entries.size();
        entries.values().removeIf(e -> now.isAfter(e.expiresAt));
        int toEvict = entries.size() - maxEntries + Math.max(1, maxEntries / 10);
        var it = entries.keySet().iterator();
        while (toEvict-- > 0 && it.hasNext()) {
            it.next();
            it.remove();
        }
        evictions.addAndGet(Math.max(0, before - entries.size()));
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

    /** Cumulative entries removed to stay within {@link #maxEntries()}. */
    public long evictionCount() {
        return evictions.get();
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
        evictions.set(0);
    }

    private record Key(String identityId, String orgId) {
    }

    private record Entry(List<EffectivePermission> permissions, Instant expiresAt) {
    }
}
