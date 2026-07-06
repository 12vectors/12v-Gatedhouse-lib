package com.twelvevectors.gatedhouse;

import java.util.List;
import java.util.function.Supplier;

/**
 * Pluggable cache for the per-identity effective permission set. Sits in
 * front of the recursive-CTE permission-resolution query in
 * {@link Gatedhouse#hasPermission} and
 * {@link Gatedhouse#getEffectivePermissions}.
 *
 * <p>The library ships an {@link InMemoryPermissionCache} default. Hosts
 * that need a shared cache (Memcached, Redis, etc.) implement this
 * interface against their cache client and pass it to
 * {@link GatedhouseConfig.Builder#permissionCache}.
 *
 * <p><b>Thread-safety:</b> implementations <i>must</i> be safe for
 * concurrent use by multiple threads. The library calls {@link #getOrLoad},
 * {@link #invalidate}, and {@link #invalidateAll} from any thread that
 * touches Gatedhouse.
 *
 * <p><b>TTL and eviction:</b> the library does not pass a TTL. Implementations
 * decide their own freshness policy (typically a constructor-time TTL); the
 * library guarantees correctness by invalidating affected entries on every
 * write through its API.
 */
public interface PermissionCache {

    /**
     * Atomic read-through: return the cached list for {@code (identityId, orgId)}, or invoke
     * {@code loader} and cache its result. This is the <em>only</em> read path — there is no separate
     * get/put pair, precisely so a caller cannot reintroduce the stale-repopulate race below.
     *
     * <p><b>Revocation-safety contract:</b> an implementation <i>must not</i> cache a value produced by
     * a {@code loader} run that a concurrent {@link #invalidate}/{@link #invalidateAll} overlapped —
     * otherwise a load that observed a pre-revocation snapshot can be stored <i>after</i> the
     * invalidation and serve a revoked permission for the full TTL. The shipped
     * {@link InMemoryPermissionCache} enforces this with a generation fence; a custom single-node cache
     * should do the same (a version/generation check, or load under a per-key lock that
     * {@code invalidate} also takes). The supplied list should be treated as immutable.
     */
    List<EffectivePermission> getOrLoad(
        String identityId, String orgId, Supplier<List<EffectivePermission>> loader);

    /** Drop the cache entry for one identity in one org. */
    void invalidate(String identityId, String orgId);

    /**
     * Drop everything cached. Called by the library on broad auth-config
     * changes (role definition edits, inheritance changes, group↔role
     * assignments, catalog changes) whose targeted impact would be
     * expensive to enumerate.
     */
    void invalidateAll();
}
