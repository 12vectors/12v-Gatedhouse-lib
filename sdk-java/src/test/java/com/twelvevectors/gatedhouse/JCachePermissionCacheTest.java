package com.twelvevectors.gatedhouse;

import org.junit.jupiter.api.Test;

import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.configuration.CacheEntryListenerConfiguration;
import javax.cache.configuration.Configuration;
import javax.cache.integration.CompletionListener;
import javax.cache.processor.EntryProcessor;
import javax.cache.processor.EntryProcessorResult;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * H1 for the JCache adapter: its {@link JCachePermissionCache#getOrLoad} must apply the same
 * in-process generation fence as the in-memory default — a value loaded across a concurrent revoke
 * must not survive in the cache. Driven deterministically with a minimal fake JSR-107 cache.
 */
class JCachePermissionCacheTest {

    private static final List<EffectivePermission> PERMS =
        List.of(new EffectivePermission("svc", "res", "act"));

    @Test
    void cachesWhenNoInvalidationRaces() {
        var backing = new FakeCache();
        var cache = new JCachePermissionCache(backing);

        var result = cache.getOrLoad("u", "o", () -> PERMS);
        assertEquals(PERMS, result);
        assertEquals(1, backing.map.size(), "value is cached in the backing store");
    }

    @Test
    void doesNotCacheWhenInvalidateRacesTheLoad() {
        var backing = new FakeCache();
        var cache = new JCachePermissionCache(backing);

        var result = cache.getOrLoad("u", "o", () -> {
            cache.invalidate("u", "o"); // concurrent revoke, mid-load
            return PERMS;
        });
        assertEquals(PERMS, result, "the in-flight caller still gets its value");
        assertEquals(0, backing.map.size(), "but the stale value must not survive in the cache");
    }

    @Test
    void doesNotCacheWhenInvalidateAllRacesTheLoad() {
        var backing = new FakeCache();
        var cache = new JCachePermissionCache(backing);

        cache.getOrLoad("u", "o", () -> {
            cache.invalidateAll();
            return PERMS;
        });
        assertEquals(0, backing.map.size(), "invalidateAll during the load must also defeat it");
    }

    /** Minimal {@link Cache} backed by a map — only get/put/remove(K)/clear are functional. */
    private static final class FakeCache
            implements Cache<PermissionCacheKey, List<EffectivePermission>> {

        final ConcurrentHashMap<PermissionCacheKey, List<EffectivePermission>> map =
            new ConcurrentHashMap<>();

        @Override public List<EffectivePermission> get(PermissionCacheKey key) { return map.get(key); }
        @Override public void put(PermissionCacheKey key, List<EffectivePermission> value) { map.put(key, value); }
        @Override public boolean remove(PermissionCacheKey key) { return map.remove(key) != null; }
        @Override public void clear() { map.clear(); }

        // ---- unused JSR-107 surface ----
        @Override public Map<PermissionCacheKey, List<EffectivePermission>> getAll(Set<? extends PermissionCacheKey> keys) { throw new UnsupportedOperationException(); }
        @Override public boolean containsKey(PermissionCacheKey key) { throw new UnsupportedOperationException(); }
        @Override public void loadAll(Set<? extends PermissionCacheKey> keys, boolean r, CompletionListener l) { throw new UnsupportedOperationException(); }
        @Override public List<EffectivePermission> getAndPut(PermissionCacheKey key, List<EffectivePermission> value) { throw new UnsupportedOperationException(); }
        @Override public void putAll(Map<? extends PermissionCacheKey, ? extends List<EffectivePermission>> m) { throw new UnsupportedOperationException(); }
        @Override public boolean putIfAbsent(PermissionCacheKey key, List<EffectivePermission> value) { throw new UnsupportedOperationException(); }
        @Override public boolean remove(PermissionCacheKey key, List<EffectivePermission> oldValue) { throw new UnsupportedOperationException(); }
        @Override public List<EffectivePermission> getAndRemove(PermissionCacheKey key) { throw new UnsupportedOperationException(); }
        @Override public boolean replace(PermissionCacheKey key, List<EffectivePermission> o, List<EffectivePermission> n) { throw new UnsupportedOperationException(); }
        @Override public boolean replace(PermissionCacheKey key, List<EffectivePermission> value) { throw new UnsupportedOperationException(); }
        @Override public List<EffectivePermission> getAndReplace(PermissionCacheKey key, List<EffectivePermission> value) { throw new UnsupportedOperationException(); }
        @Override public void removeAll(Set<? extends PermissionCacheKey> keys) { throw new UnsupportedOperationException(); }
        @Override public void removeAll() { throw new UnsupportedOperationException(); }
        @Override public <C extends Configuration<PermissionCacheKey, List<EffectivePermission>>> C getConfiguration(Class<C> c) { throw new UnsupportedOperationException(); }
        @Override public <T> T invoke(PermissionCacheKey key, EntryProcessor<PermissionCacheKey, List<EffectivePermission>, T> ep, Object... args) { throw new UnsupportedOperationException(); }
        @Override public <T> Map<PermissionCacheKey, EntryProcessorResult<T>> invokeAll(Set<? extends PermissionCacheKey> keys, EntryProcessor<PermissionCacheKey, List<EffectivePermission>, T> ep, Object... args) { throw new UnsupportedOperationException(); }
        @Override public String getName() { throw new UnsupportedOperationException(); }
        @Override public CacheManager getCacheManager() { throw new UnsupportedOperationException(); }
        @Override public void close() { throw new UnsupportedOperationException(); }
        @Override public boolean isClosed() { throw new UnsupportedOperationException(); }
        @Override public <T> T unwrap(Class<T> clazz) { throw new UnsupportedOperationException(); }
        @Override public void registerCacheEntryListener(CacheEntryListenerConfiguration<PermissionCacheKey, List<EffectivePermission>> c) { throw new UnsupportedOperationException(); }
        @Override public void deregisterCacheEntryListener(CacheEntryListenerConfiguration<PermissionCacheKey, List<EffectivePermission>> c) { throw new UnsupportedOperationException(); }
        @Override public Iterator<Entry<PermissionCacheKey, List<EffectivePermission>>> iterator() { throw new UnsupportedOperationException(); }
    }
}
