package com.twelvevectors.gatedhouse;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * H1 — the generation fence in {@link InMemoryPermissionCache#getOrLoad}: a value produced by a load
 * that a concurrent invalidation overlapped must NOT be cached, or a revoked ALLOW would survive to
 * the TTL. The race window is simulated deterministically by having the loader invalidate mid-load.
 */
class InMemoryPermissionCacheTest {

    private static final List<EffectivePermission> PERMS =
        List.of(new EffectivePermission("svc", "res", "act"));

    @Test
    void getOrLoadCachesWhenNoInvalidationRaces() {
        var cache = new InMemoryPermissionCache();
        var result = cache.getOrLoad("u", "o", () -> PERMS);

        assertEquals(PERMS, result, "caller gets the loaded value");
        assertEquals(1, cache.size(), "and it is cached"); // size() doesn't mutate hit/miss stats
        assertEquals(1, cache.missCount());
        assertEquals(1, cache.putCount());

        // A second read is served from cache (loader must not run).
        cache.getOrLoad("u", "o", () -> { throw new AssertionError("loader must not run on a hit"); });
        assertEquals(1, cache.hitCount());
    }

    @Test
    void getOrLoadDoesNotCacheWhenTargetedInvalidateRacesTheLoad() {
        var cache = new InMemoryPermissionCache();
        // The loader stands in for a slow DB read during which a concurrent revoke lands.
        var result = cache.getOrLoad("u", "o", () -> {
            cache.invalidate("u", "o");   // concurrent revoke, mid-load
            return PERMS;
        });

        assertEquals(PERMS, result, "the in-flight caller still gets its loaded value");
        assertEquals(0, cache.size(),
            "but the stale-relative-to-revoke value must NOT be cached (H1 fence)");
        assertEquals(0, cache.putCount(), "no store happened");
    }

    @Test
    void getOrLoadDoesNotCacheWhenInvalidateAllRacesTheLoad() {
        var cache = new InMemoryPermissionCache();
        var result = cache.getOrLoad("u", "o", () -> {
            cache.invalidateAll();        // broad revoke (grant/revokePermission path), mid-load
            return PERMS;
        });

        assertEquals(PERMS, result);
        assertEquals(0, cache.size(),
            "invalidateAll during the load must also defeat the re-populate (H1 fence)");
    }

    @Test
    void loadAfterInvalidationCachesNormally() {
        var cache = new InMemoryPermissionCache();
        cache.invalidateAll(); // bump generation once up front
        var result = cache.getOrLoad("u", "o", () -> PERMS);
        assertEquals(PERMS, result);
        assertEquals(1, cache.size(),
            "a load that starts AFTER the invalidation caches normally");
    }
}
