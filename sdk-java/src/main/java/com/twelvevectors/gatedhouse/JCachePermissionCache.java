package com.twelvevectors.gatedhouse;

import javax.cache.Cache;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Adapts any JSR 107 {@link Cache} to the library's {@link PermissionCache}
 * contract. Lets the host bring their own JCache provider (Ehcache 3,
 * Hazelcast, Redisson for Redis, Caffeine via its JCache adapter, …)
 * without writing glue code.
 *
 * <p>The host is responsible for the JCache lifecycle — configuration,
 * {@code CacheManager} ownership, expiry policy, statistics, and close.
 * This adapter is a thin pass-through; it does not own the cache.
 *
 * <p>Thread-safety: JCache caches are required to be safe for concurrent
 * access by spec, and this adapter holds no mutable state of its own.
 *
 * <h2>Example</h2>
 * <pre>{@code
 * CachingProvider provider = Caching.getCachingProvider();
 * CacheManager mgr = provider.getCacheManager();
 *
 * MutableConfiguration<PermissionCacheKey, List<EffectivePermission>> cfg =
 *     new MutableConfiguration<PermissionCacheKey, List<EffectivePermission>>()
 *         .setTypes(PermissionCacheKey.class,
 *                   (Class<List<EffectivePermission>>)(Class<?>) List.class)
 *         .setExpiryPolicyFactory(
 *             CreatedExpiryPolicy.factoryOf(new Duration(SECONDS, 60)))
 *         .setStatisticsEnabled(true);
 *
 * Cache<PermissionCacheKey, List<EffectivePermission>> jcache =
 *     mgr.createCache("gatedhouse-perms", cfg);
 *
 * GatedhouseConfig config = GatedhouseConfig.builder()
 *     .database(db)
 *     .permissionCache(new JCachePermissionCache(jcache))
 *     .build();
 * }</pre>
 */
public final class JCachePermissionCache implements PermissionCache {

    private final Cache<PermissionCacheKey, List<EffectivePermission>> cache;

    /**
     * Adapter-local revocation generation, bumped by {@link #invalidate}/{@link #invalidateAll} before
     * they touch the backing cache. {@link #getOrLoad} uses it to fence a load that a concurrent revoke
     * overlapped (the H1 stale-repopulate race), exactly like {@link InMemoryPermissionCache}. This
     * coordinates the <em>in-process</em> race; cross-node coherence for a distributed backing cache
     * (node A's invalidate vs node B's load) is inherently the provider's/host's concern.
     */
    private final java.util.concurrent.atomic.AtomicLong generation =
        new java.util.concurrent.atomic.AtomicLong();

    public JCachePermissionCache(Cache<PermissionCacheKey, List<EffectivePermission>> cache) {
        this.cache = Objects.requireNonNull(cache, "cache");
    }

    @Override
    public List<EffectivePermission> getOrLoad(
            String identityId, String orgId, Supplier<List<EffectivePermission>> loader) {
        PermissionCacheKey key = new PermissionCacheKey(identityId, orgId);
        List<EffectivePermission> cached = cache.get(key);
        if (cached != null) {
            return cached;
        }
        long genAtLoad = generation.get();
        // Defensive copy so a later mutation by the caller can't poison the cache (and so distributed
        // providers serialize a stable snapshot).
        List<EffectivePermission> fresh = List.copyOf(loader.get());
        // Fence: if a revoke bumped the generation while we were loading, this value may predate it —
        // don't cache it. The store-then-recheck-and-undo keeps this correct without a lock: a revoke
        // increments the generation BEFORE its remove, so either our recheck sees the bump and we undo,
        // or the revoke's remove runs after our put and clears it. Either way no stale value survives.
        if (generation.get() != genAtLoad) {
            return fresh;
        }
        cache.put(key, fresh);
        if (generation.get() != genAtLoad) {
            cache.remove(key);
        }
        return fresh;
    }

    @Override
    public void invalidate(String identityId, String orgId) {
        generation.incrementAndGet();
        cache.remove(new PermissionCacheKey(identityId, orgId));
    }

    @Override
    public void invalidateAll() {
        generation.incrementAndGet();
        cache.clear();
    }
}
