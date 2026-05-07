package com.twelvevectors.gatedhouse;

import java.util.List;
import java.util.Optional;

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
 * concurrent use by multiple threads. The library calls {@link #get},
 * {@link #put}, {@link #invalidate}, and {@link #invalidateAll} from any
 * thread that touches Gatedhouse.
 *
 * <p><b>TTL and eviction:</b> the library does not pass a TTL on
 * {@link #put}. Implementations decide their own freshness policy
 * (typically a constructor-time TTL); the library guarantees correctness
 * by invalidating affected entries on every write through its API.
 */
public interface PermissionCache {

    /**
     * @return the cached effective-permission list for {@code (identityId,
     *     orgId)}, or {@link Optional#empty()} on miss / expiry. The
     *     returned list, if present, is treated as authoritative; the
     *     library will not consult the database.
     */
    Optional<List<EffectivePermission>> get(String identityId, String orgId);

    /**
     * Cache the effective-permission list for {@code (identityId, orgId)}.
     * Implementations should treat the supplied list as immutable
     * (defensive copy if needed).
     */
    void put(String identityId, String orgId, List<EffectivePermission> permissions);

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
