// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

final class DefaultGatedhouse implements Gatedhouse {

    private final GatedhouseConfig config;
    // The configured cache, or a no-op stand-in when caching is off. The
    // stand-in keeps the managers' write-path invalidation unconditional;
    // the read path never touches it (guarded by cacheEnabled below).
    private final PermissionCache cache;
    private final boolean cacheConfigured;
    private final PermissionCatalog permissionCatalog;
    private final RoleManager roleManager;
    private final MembershipManager membershipManager;
    private final GroupManager groupManager;
    private final JwtVerification jwtVerification;  // null if unconfigured
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean cacheEnabled;

    DefaultGatedhouse(GatedhouseConfig config) {
        this.config = config;
        this.cacheConfigured = config.permissionCache() != null;
        this.cache = cacheConfigured ? config.permissionCache() : NoOpCache.INSTANCE;
        this.cacheEnabled = new AtomicBoolean(cacheConfigured);
        this.permissionCatalog = new DefaultPermissionCatalog(config.database(), cache);
        this.roleManager = new DefaultRoleManager(config.database(), cache);
        this.membershipManager = new DefaultMembershipManager(config.database(), cache);
        this.groupManager = new DefaultGroupManager(config.database(), cache);
        this.jwtVerification = config.tokenVerifier() != null
            ? new JwtVerification(config.tokenVerifier())
            : null;
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            config.groupSource().close();
        }
    }

    // ---- accessors ---------------------------------------------------------

    @Override
    public PermissionCatalog permissionCatalog() {
        return permissionCatalog;
    }

    @Override
    public RoleManager roleManager() {
        return roleManager;
    }

    @Override
    public MembershipManager membershipManager() {
        return membershipManager;
    }

    @Override
    public GroupManager groupManager() {
        return groupManager;
    }

    @Override
    public AuthenticatedSubject verifyToken(String jwt) {
        if (jwtVerification == null) {
            throw new IllegalStateException(
                "verifyToken was called but no TokenVerifierConfig was supplied. "
                + "Configure via GatedhouseConfig.builder().tokenVerifier("
                + "TokenVerifierConfig.builder()...build()).");
        }
        return jwtVerification.verify(jwt);
    }

    // ---- the core authorization check -------------------------------------

    @Override
    public boolean hasPermission(String identityId, String orgId,
                                 String service, String resource, String action) {
        List<EffectivePermission> effective = effectivePermissionsCached(identityId, orgId);
        for (EffectivePermission grant : effective) {
            if (matches(grant, service, resource, action)) {
                return true;
            }
        }
        return false;
    }

    // ---- user-facing reads ------------------------------------------------

    @Override
    public List<EffectivePermission> getEffectivePermissions(String identityId, String orgId) {
        return effectivePermissionsCached(identityId, orgId);
    }

    @Override
    public List<String> getRoles(String identityId, String orgId) {
        return roleManager.getIdentityRoles(identityId, orgId);
    }

    @Override
    public List<String> getGroups(String identityId, String orgId) {
        return groupManager.getIdentityGroups(identityId, orgId);
    }

    @Override
    public PermissionExplanation explainPermission(String identityId, String orgId,
                                                   String service, String resource, String action) {
        // One statement, so the status and the paths come from one snapshot.
        // The path search mirrors loadEffectivePermissions (same sources, same
        // inheritance climb, same column-wise wildcard rule as matches()) but
        // carries the role chain, and reports paths whatever the status is.
        String sql =
            "WITH RECURSIVE sources AS ( "
            + "    SELECT 'DIRECT' AS source, NULL::TEXT AS group_id, role_key "
            + "    FROM gatedhouse.role_assignments "
            + "    WHERE identity_id = ? AND org_id = ? "
            + "    UNION ALL "
            + "    SELECT 'GROUP', gm.group_id, gr.role_key "
            + "    FROM gatedhouse.group_memberships gm "
            + "    JOIN gatedhouse.group_roles gr "
            + "      ON gr.group_id = gm.group_id AND gr.org_id = gm.org_id "
            + "    WHERE gm.identity_id = ? AND gm.org_id = ? "
            + "), "
            + "chains AS ( "
            + "    SELECT source, group_id, role_key AS at_role, ARRAY[role_key] AS chain "
            + "    FROM sources "
            + "    UNION ALL "
            + "    SELECT c.source, c.group_id, ri.parent_key, c.chain || ri.parent_key "
            + "    FROM chains c "
            + "    JOIN gatedhouse.role_inherits ri ON ri.child_key = c.at_role "
            + "    WHERE NOT (ri.parent_key = ANY (c.chain)) "
            + "), "
            + "paths AS ( "
            + "    SELECT c.source, c.group_id, c.chain, rp.service, rp.resource, rp.action "
            + "    FROM chains c "
            + "    JOIN gatedhouse.role_permissions rp ON rp.role_key = c.at_role "
            + "    WHERE (rp.service  IS NULL OR rp.service  = ?) "
            + "      AND (rp.resource IS NULL OR rp.resource = ?) "
            + "      AND (rp.action   IS NULL OR rp.action   = ?) "
            + ") "
            + "SELECT (SELECT status::TEXT FROM gatedhouse.memberships "
            + "        WHERE identity_id = ? AND org_id = ?) AS status, "
            + "       p.source, p.group_id, p.chain, p.service, p.resource, p.action "
            + "FROM (SELECT 1) AS one "
            + "LEFT JOIN paths p ON TRUE "
            + "ORDER BY p.source, p.group_id NULLS FIRST, cardinality(p.chain), p.chain";

        return Sql.read(config.database(), "explainPermission", conn -> {
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, identityId);
                ps.setString(2, orgId);
                ps.setString(3, identityId);
                ps.setString(4, orgId);
                ps.setString(5, service);
                ps.setString(6, resource);
                ps.setString(7, action);
                ps.setString(8, identityId);
                ps.setString(9, orgId);
                MembershipStatus status = null;
                List<GrantPath> paths = new ArrayList<>();
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        String statusValue = rs.getString("status");
                        status = statusValue == null ? null : MembershipStatus.fromDbValue(statusValue);
                        String source = rs.getString("source");
                        if (source == null) {
                            continue;  // the LEFT JOIN's placeholder row: no paths
                        }
                        String[] chain = (String[]) rs.getArray("chain").getArray();
                        paths.add(new GrantPath(
                            GrantPath.Source.valueOf(source),
                            rs.getString("group_id"),
                            List.of(chain),
                            new EffectivePermission(
                                rs.getString("service"), rs.getString("resource"), rs.getString("action"))));
                    }
                }
                PermissionExplanation.Outcome outcome;
                if (status == null) {
                    outcome = PermissionExplanation.Outcome.NO_MEMBERSHIP;
                } else if (status != MembershipStatus.ACTIVE) {
                    outcome = PermissionExplanation.Outcome.MEMBERSHIP_NOT_ACTIVE;
                } else if (paths.isEmpty()) {
                    outcome = PermissionExplanation.Outcome.NO_MATCHING_GRANT;
                } else {
                    outcome = PermissionExplanation.Outcome.ALLOWED;
                }
                return new PermissionExplanation(outcome, status, paths);
            }
        });
    }

    // ---- cache control ----------------------------------------------------

    @Override
    public void invalidateCache(String identityId, String orgId) {
        cache.invalidate(identityId, orgId);
    }

    @Override
    public void invalidateAllCache() {
        cache.invalidateAll();
    }

    @Override
    public void setCacheEnabled(boolean enabled) {
        cacheEnabled.set(enabled && cacheConfigured);
    }

    @Override
    public boolean isCacheEnabled() {
        return cacheEnabled.get();
    }

    // ---- internals --------------------------------------------------------

    private List<EffectivePermission> effectivePermissionsCached(
            String identityId, String orgId) {
        if (!cacheEnabled.get()) {
            // No cache configured, or caching switched off at runtime:
            // skip the cache entirely on reads. We don't populate it either
            // — when caching is re-enabled, the cache starts cold.
            return loadEffectivePermissions(identityId, orgId);
        }
        Optional<List<EffectivePermission>> hit = cache.get(identityId, orgId);
        if (hit.isPresent()) {
            return hit.get();
        }
        List<EffectivePermission> fresh = loadEffectivePermissions(identityId, orgId);
        cache.put(identityId, orgId, fresh);
        return fresh;
    }

    private List<EffectivePermission> loadEffectivePermissions(
            String identityId, String orgId) {
        // Recursive CTE: collects all effective roles (direct + via groups +
        // ancestors via inheritance), short-circuits to empty if membership
        // is missing or not active, returns DISTINCT permission tuples.
        String sql =
            "WITH RECURSIVE active_membership AS ( "
            + "    SELECT 1 FROM gatedhouse.memberships "
            + "    WHERE identity_id = ? AND org_id = ? AND status = 'active' "
            + "), "
            + "direct_roles AS ( "
            + "    SELECT role_key FROM gatedhouse.role_assignments "
            + "    WHERE identity_id = ? AND org_id = ? "
            + "    UNION "
            + "    SELECT gr.role_key "
            + "    FROM gatedhouse.group_memberships gm "
            + "    JOIN gatedhouse.group_roles gr "
            + "      ON gr.group_id = gm.group_id AND gr.org_id = gm.org_id "
            + "    WHERE gm.identity_id = ? AND gm.org_id = ? "
            + "), "
            + "all_roles AS ( "
            + "    SELECT role_key FROM direct_roles "
            + "    UNION "
            + "    SELECT ri.parent_key "
            + "    FROM gatedhouse.role_inherits ri "
            + "    JOIN all_roles ar ON ar.role_key = ri.child_key "
            + ") "
            + "SELECT DISTINCT rp.service, rp.resource, rp.action "
            + "FROM gatedhouse.role_permissions rp "
            + "WHERE rp.role_key IN (SELECT role_key FROM all_roles) "
            + "  AND EXISTS (SELECT 1 FROM active_membership)";

        return Sql.read(config.database(), "loadEffectivePermissions", conn -> {
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, identityId);
                ps.setString(2, orgId);
                ps.setString(3, identityId);
                ps.setString(4, orgId);
                ps.setString(5, identityId);
                ps.setString(6, orgId);
                try (ResultSet rs = ps.executeQuery()) {
                    List<EffectivePermission> out = new ArrayList<>();
                    while (rs.next()) {
                        out.add(new EffectivePermission(
                            rs.getString(1),
                            rs.getString(2),
                            rs.getString(3)));
                    }
                    return Collections.unmodifiableList(out);
                }
            }
        });
    }

    private static boolean matches(EffectivePermission grant,
                                   String service, String resource, String action) {
        return (grant.service()  == null || grant.service().equals(service))
            && (grant.resource() == null || grant.resource().equals(resource))
            && (grant.action()   == null || grant.action().equals(action));
    }

    /** Stand-in used when no cache is configured; every method is a no-op. */
    private static final class NoOpCache implements PermissionCache {

        static final NoOpCache INSTANCE = new NoOpCache();

        @Override
        public Optional<List<EffectivePermission>> get(String identityId, String orgId) {
            return Optional.empty();
        }

        @Override
        public void put(String identityId, String orgId, List<EffectivePermission> permissions) {}

        @Override
        public void invalidate(String identityId, String orgId) {}

        @Override
        public void invalidateAll() {}
    }
}
