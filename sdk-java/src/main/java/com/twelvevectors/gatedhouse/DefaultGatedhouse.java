// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

final class DefaultGatedhouse implements Gatedhouse {

    private final GatedhouseConfig config;
    private final PermissionCache cache;
    private final PermissionCatalog permissionCatalog;
    private final RoleManager roleManager;
    private final MembershipManager membershipManager;
    private final GroupManager groupManager;
    private final JwtVerification jwtVerification;  // null if unconfigured
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean cacheBypass = new AtomicBoolean(false);

    DefaultGatedhouse(GatedhouseConfig config) {
        this.config = config;
        this.cache = config.permissionCache();
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
    public void setCacheBypass(boolean bypass) {
        cacheBypass.set(bypass);
    }

    @Override
    public boolean isCacheBypassed() {
        return cacheBypass.get();
    }

    // ---- internals --------------------------------------------------------

    private List<EffectivePermission> effectivePermissionsCached(
            String identityId, String orgId) {
        if (cacheBypass.get()) {
            // Kill switch: skip the cache entirely on reads. We still don't
            // populate it — when bypass is cleared, the cache starts cold.
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

        try (Connection conn = config.database().getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
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
        } catch (SQLException e) {
            throw new GatedhouseDatabaseException("loadEffectivePermissions failed", e);
        }
    }

    private static boolean matches(EffectivePermission grant,
                                   String service, String resource, String action) {
        return (grant.service()  == null || grant.service().equals(service))
            && (grant.resource() == null || grant.resource().equals(resource))
            && (grant.action()   == null || grant.action().equals(action));
    }
}
