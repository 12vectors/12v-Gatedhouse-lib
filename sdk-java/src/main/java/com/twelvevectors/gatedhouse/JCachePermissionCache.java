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

    public JCachePermissionCache(Cache<PermissionCacheKey, List<EffectivePermission>> cache) {
        this.cache = Objects.requireNonNull(cache, "cache");
    }

    /**
     * Read-through against the backing JSR-107 cache. This adapter does not own the cache internals,
     * so it cannot apply the single-node generation fence that {@link InMemoryPermissionCache} uses;
     * for a distributed JCache, coherence under concurrent revocation (including cross-node staleness)
     * is the provider's/host's responsibility — see the SDK's multi-instance caveat.
     */
    @Override
    public List<EffectivePermission> getOrLoad(
            String identityId, String orgId, Supplier<List<EffectivePermission>> loader) {
        PermissionCacheKey key = new PermissionCacheKey(identityId, orgId);
        List<EffectivePermission> cached = cache.get(key);
        if (cached != null) {
            return cached;
        }
        // Defensive copy so a later mutation by the caller can't poison the cache (and so distributed
        // providers serialize a stable snapshot).
        List<EffectivePermission> fresh = List.copyOf(loader.get());
        cache.put(key, fresh);
        return fresh;
    }

    @Override
    public void invalidate(String identityId, String orgId) {
        cache.remove(new PermissionCacheKey(identityId, orgId));
    }

    @Override
    public void invalidateAll() {
        cache.clear();
    }
}
