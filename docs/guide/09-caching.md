# 9. Caching

Caching is **off by default**: every check queries the database. Turn it on
to answer repeated checks for the same identity and org from memory.

## How it works

The cache stores, per `(identity, org)`, the identity's complete list of
effective grants in that org. The first check fills the entry with one
query; later checks for that identity and org, for **any** permission, are
answered from the entry until it expires or is invalidated.
`hasPermission` and `getEffectivePermissions` use the cache;
`explainPermission` always reads the database.

## Turning it on

```java
GatedhouseConfig config = GatedhouseConfig.builder()
    .database(db)
    .permissionCache(new InMemoryPermissionCache())                    // 60 s, 10,000 entries
    .build();
```

```python
config = GatedhouseConfig(database=db, permission_cache=InMemoryPermissionCache())
```

```rust
let config = GatedhouseConfig::builder(db)
    .permission_cache(Arc::new(InMemoryPermissionCache::new()))
    .build();
```

## The in-memory cache

`InMemoryPermissionCache` lives inside your process, is safe for concurrent
use, and has two settings:

| Setting | Default | Meaning |
|---|---|---|
| time to live | 60 s | how long an entry is used before it is reloaded |
| maximum entries | 10,000 | `(identity, org)` pairs held at once |

```java
new InMemoryPermissionCache(Duration.ofSeconds(30), 50_000);
```

```python
InMemoryPermissionCache(timedelta(seconds=30), max_entries=50_000)
```

```rust
InMemoryPermissionCache::with_ttl_and_max_entries(Duration::from_secs(30), 50_000)
```

When the cache is full, expired entries are swept first; if it is still full,
the oldest tenth is evicted (Java evicts an arbitrary tenth). The bound
matters because the org of a check usually comes from the request: without it,
requests naming many different orgs could grow the cache without limit.

It also exposes counters for monitoring: `hitCount`, `missCount`, `putCount`,
`targetedInvalidationCount`, `wholesaleInvalidationCount`, `evictionCount`,
`size` (snake_case in Python and Rust), and `resetStats`.

## Automatic invalidation

Every change made through Gatedhouse clears the affected entries **in the
same process**:

| Change | Cleared |
|---|---|
| membership create, remove, status change | that identity in that org |
| direct role assignment or revocation | that identity in that org |
| adding or removing a group member | that identity in that org |
| grants, inheritance, group roles, deleting a role or group, removing catalog entries | everything |

The broad clears look expensive, but those changes are rare. The frequent
changes (one person's access) clear one entry.

## Several processes: what to know

The in-memory cache is **per process**. If several processes use the same
database (several instances behind a load balancer, or a Java and a Python
service), a change made in one clears only that process's cache; the others
keep their entry until it expires. For up to the time to live, they may
answer with the old permissions. The same applies to changes made directly
in SQL.

Choose a strategy:

| Strategy | How | Staleness |
|---|---|---|
| Short time to live | e.g. 5 s | up to the TTL |
| Shared cache | implement `PermissionCache` over Redis or Memcached, or in Java wrap any JCache provider with `JCachePermissionCache` | none between processes |
| Broadcast invalidation | publish changes (PostgreSQL `LISTEN`/`NOTIFY`, a message bus) and call `invalidateCache` / `invalidateAllCache` on receipt | near real time |
| No cache | the default | none |

Pick the time to live from your tolerance for a revoked permission still
working briefly. For sensitive permissions (refunds, admin actions) a short
TTL or no cache is reasonable; the check without a cache is a single indexed
query.

There is also a narrow window **within one process**: if a check is loading
an entry at the very moment a change commits, it can store the answer from
just before the change, which then lives until the TTL. Size the TTL with
this in mind too.

## A shared cache

Java ships an adapter for any JSR 107 (JCache) provider: Ehcache, Hazelcast,
Redisson (Redis), Infinispan, Caffeine's JCache module.

```java
CacheManager manager = Caching.getCachingProvider().getCacheManager();
MutableConfiguration<PermissionCacheKey, List<EffectivePermission>> cfg =
    new MutableConfiguration<PermissionCacheKey, List<EffectivePermission>>()
        .setExpiryPolicyFactory(CreatedExpiryPolicy.factoryOf(
            new javax.cache.expiry.Duration(TimeUnit.SECONDS, 60)));
Cache<PermissionCacheKey, List<EffectivePermission>> jcache =
    manager.createCache("gatedhouse-permissions", cfg);

GatedhouseConfig.builder().database(db)
    .permissionCache(new JCachePermissionCache(jcache))
    .build();
```

In any SDK you can implement the four-method `PermissionCache` interface
yourself:

| Method | Called when |
|---|---|
| `get(identity, org)` | before a check; return the stored list or nothing |
| `put(identity, org, permissions)` | after a miss was loaded from the database |
| `invalidate(identity, org)` | after a change to that identity in that org |
| `invalidateAll()` | after a change that may affect many identities |

Implementations must be thread-safe, and must not fail checks when the cache
backend is down: return "nothing" from `get` and ignore failed `put`s, so
Gatedhouse falls back to the database.

## Manual control

```java
gh.invalidateCache("alice", "acme");   // after changing data outside Gatedhouse
gh.invalidateAllCache();
gh.setCacheEnabled(false);             // emergency switch: bypass the cache
gh.setCacheEnabled(true);              // resume; the cache starts cold
gh.isCacheEnabled();
```

Python and Rust use the snake_case names. While disabled, checks skip the
cache entirely, but changes still invalidate it, so it is consistent when
turned back on. With no cache configured, `isCacheEnabled()` is `false` and
enabling does nothing.
