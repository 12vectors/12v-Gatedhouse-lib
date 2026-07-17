// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.util.List;

public interface Gatedhouse extends AutoCloseable {

    /**
     * Closes any resources owned by Gatedhouse — currently the configured
     * {@link GroupSource}. Idempotent. Does not close the {@link Database}
     * (the host owns that).
     */
    @Override
    void close();


    // ---- administrative sub-interfaces ------------------------------------

    PermissionCatalog permissionCatalog();

    RoleManager roleManager();

    MembershipManager membershipManager();

    GroupManager groupManager();

    /**
     * Verifies a JWT (typically issued by Sphinx) and returns the trusted
     * subject. Optional helper — only available if
     * {@link GatedhouseConfig.Builder#tokenVerifier} was configured.
     *
     * <p>Use the returned {@link AuthenticatedSubject#id} as the
     * {@code identityId} argument to {@link #hasPermission} on subsequent
     * calls. Independent of authorization: a host that doesn't use JWTs at
     * all can ignore this method and call {@code hasPermission} with any
     * trusted identity ID.
     *
     * <p>Thread-safe; the underlying Nimbus processor and JWKS cache are
     * shared across all calls.
     *
     * @throws TokenVerificationException if the token is invalid; inspect
     *     {@link TokenVerificationException#reason()} to decide whether to
     *     refresh, redirect to SSO, retry, or hard-reject
     * @throws IllegalStateException if no {@code TokenVerifierConfig} was
     *     supplied at factory time
     */
    AuthenticatedSubject verifyToken(String jwt);

    // ---- user-facing reads ------------------------------------------------

    /**
     * The core authorization check. Returns true iff the identity, in the
     * given org, has been granted the (service, resource, action) permission
     * — directly or by inheritance, via direct role assignment or group
     * membership — and the membership is active.
     *
     * <p>The required permission is always concrete; wildcards are only
     * meaningful in grants, not in checks.
     */
    boolean hasPermission(String identityId, String orgId,
                          String service, String resource, String action);

    /**
     * All permission tuples (service, resource, action) effectively granted
     * to the identity in the given org. Wildcard grants are returned as-is
     * (with nulls). Returns an empty list if the membership is missing or
     * not active.
     */
    List<EffectivePermission> getEffectivePermissions(String identityId, String orgId);

    /**
     * All role keys directly assigned to the identity in the given org
     * (does not include parent roles inherited via the DAG).
     */
    List<String> getRoles(String identityId, String orgId);

    /**
     * All group IDs the identity belongs to in the given org.
     */
    List<String> getGroups(String identityId, String orgId);

    // ---- cache control ----------------------------------------------------

    /**
     * Drops the cached effective-permission entry for one identity in one
     * org. Intended for hosts that mutate the schema outside this library
     * (raw SQL, sibling processes) and need to force a refresh on the next
     * permission read. The library's own write methods invalidate the
     * cache automatically — there is no need to call this in normal use.
     */
    void invalidateCache(String identityId, String orgId);

    /**
     * Drops every cached entry. Same intent as
     * {@link #invalidateCache(String, String)} but for cases where the
     * scope of out-of-band changes is broad.
     */
    void invalidateAllCache();

    /**
     * Runtime kill switch. When set to {@code true}, every
     * {@link #hasPermission} and {@link #getEffectivePermissions} call
     * skips the cache entirely — neither read from it nor populate it.
     * Each call goes straight to the database. Writes through the
     * library's manager APIs continue to invalidate cache entries, so
     * the cache stays consistent if and when the bypass is later cleared.
     *
     * <p>Intended for emergency operations and debugging — not normal use.
     * Defaults to {@code false}. Thread-safe: applies on the next read in
     * any thread once set.
     */
    void setCacheBypass(boolean bypass);

    /**
     * @return {@code true} if cache bypass is currently active
     */
    boolean isCacheBypassed();
}
