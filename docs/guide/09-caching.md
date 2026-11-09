# 9. Caching

Off by default. When configured, the cache stores per `(identity, org)` the
full list of effective grants; `hasPermission` and `getEffectivePermissions`
read it, `explainPermission` never does.

```java
GatedhouseConfig.builder().database(db).permissionCache(new InMemoryPermissionCache()).build();
```
```python
GatedhouseConfig(database=db, permission_cache=InMemoryPermissionCache())
```
```rust
GatedhouseConfig::builder(db).permission_cache(Arc::new(InMemoryPermissionCache::new())).build()
```

## InMemoryPermissionCache

| Setting | Default | Java | Python | Rust |
|---|---|---|---|---|
| TTL | 60 s | `new InMemoryPermissionCache(ttl)` | `InMemoryPermissionCache(ttl)` | `with_ttl(ttl)` |
| max entries | 10,000 | `new InMemoryPermissionCache(ttl, max)` | `InMemoryPermissionCache(ttl, max_entries=max)` | `with_ttl_and_max_entries(ttl, max)` |

At the bound, expired entries are swept; if still full, a tenth is evicted
(oldest first in Python and Rust, arbitrary in Java). Counters: `hitCount`,
`missCount`, `putCount`, `targetedInvalidationCount`,
`wholesaleInvalidationCount`, `evictionCount`, `size`, `resetStats`.

## Invalidation (automatic, same process only)

| Change | Invalidates |
|---|---|
| membership create / remove / status | `(identity, org)` |
| direct role assignment / revocation | `(identity, org)` |
| group member add / remove | `(identity, org)` |
| grants, inheritance, group roles, role or group deletion, catalog removal | all entries |

Changes made by other processes or by direct SQL are not seen until the
entry expires. Also within one process, a check that loads an entry while a
change commits can cache the pre-change result until expiry. Choose the TTL
as the maximum tolerated delay for a revocation to take effect.

| Multi-process option | Staleness |
|---|---|
| short TTL | ≤ TTL |
| shared cache (custom `PermissionCache` over Redis/Memcached; Java: `JCachePermissionCache` wrapping any JSR 107 provider) | none across processes |
| broadcast changes (e.g. `LISTEN`/`NOTIFY`) and call `invalidateCache` / `invalidateAllCache` | near real time |
| no cache | none |

## Custom PermissionCache

Methods: `get(identity, org)`, `put(identity, org, permissions)`,
`invalidate(identity, org)`, `invalidateAll()`. Must be thread-safe.
Exceptions from `get`/`put` fail the check, so a networked implementation
should return "absent" and ignore failed writes when its backend is down.

```java
Cache<PermissionCacheKey, List<EffectivePermission>> jcache = cacheManager.createCache("gatedhouse",
    new MutableConfiguration<PermissionCacheKey, List<EffectivePermission>>()
        .setExpiryPolicyFactory(CreatedExpiryPolicy.factoryOf(new javax.cache.expiry.Duration(SECONDS, 60))));
GatedhouseConfig.builder().database(db).permissionCache(new JCachePermissionCache(jcache)).build();
```

## Runtime control

| Java | Effect |
|---|---|
| `invalidateCache(id, org)`, `invalidateAllCache()` | manual invalidation, e.g. after direct SQL |
| `setCacheEnabled(false)` | bypass the cache; changes still invalidate it |
| `setCacheEnabled(true)` | resume (cache starts cold); no-op without a configured cache |
| `isCacheEnabled()` | `false` when no cache is configured |
