// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

final class DefaultRoleManager implements RoleManager {

    private final Database database;
    private final PermissionCache cache;

    DefaultRoleManager(Database database, PermissionCache cache) {
        this.database = database;
        this.cache = cache;
    }

    // ---- role definitions --------------------------------------------------

    @Override
    public void createRole(String key, String name, String description) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "INSERT INTO gatedhouse.roles (key, name, description, is_system) "
                 + "VALUES (?, ?, ?, FALSE)")) {
            ps.setString(1, key);
            ps.setString(2, name);
            ps.setString(3, description);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("createRole", e);
        }
    }

    @Override
    public void deleteRole(String key) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "DELETE FROM gatedhouse.roles WHERE key = ? AND is_system = FALSE")) {
            ps.setString(1, key);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("deleteRole", e);
        }
        // Cascade dropped every assignment of this role; affected identity
        // set is wide and not worth enumerating.
        cache.invalidateAll();
    }

    @Override
    public boolean hasRole(String key) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT 1 FROM gatedhouse.roles WHERE key = ?")) {
            ps.setString(1, key);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw fail("hasRole", e);
        }
    }

    @Override
    public List<String> listRoles() {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT key FROM gatedhouse.roles ORDER BY key");
             ResultSet rs = ps.executeQuery()) {
            List<String> out = new ArrayList<>();
            while (rs.next()) {
                out.add(rs.getString(1));
            }
            return out;
        } catch (SQLException e) {
            throw fail("listRoles", e);
        }
    }

    // ---- permission grants -------------------------------------------------

    @Override
    public void grantPermission(String roleKey, String service, String resource, String action) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "INSERT INTO gatedhouse.role_permissions (id, role_key, service, resource, action) "
                 + "VALUES (?, ?, ?, ?, ?)")) {
            ps.setObject(1, UUID.randomUUID());
            ps.setString(2, roleKey);
            setNullableString(ps, 3, service);
            setNullableString(ps, 4, resource);
            setNullableString(ps, 5, action);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("grantPermission", e);
        }
        // Affects every identity holding this role (directly, via group, or
        // via inheritance). Wholesale invalidate.
        cache.invalidateAll();
    }

    @Override
    public void revokePermission(String roleKey, String service, String resource, String action) {
        // Match on COALESCE so NULLs (wildcards) compare correctly.
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "DELETE FROM gatedhouse.role_permissions "
                 + "WHERE role_key = ? "
                 + "  AND COALESCE(service,  '') = COALESCE(?, '') "
                 + "  AND COALESCE(resource, '') = COALESCE(?, '') "
                 + "  AND COALESCE(action,   '') = COALESCE(?, '')")) {
            ps.setString(1, roleKey);
            setNullableString(ps, 2, service);
            setNullableString(ps, 3, resource);
            setNullableString(ps, 4, action);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("revokePermission", e);
        }
        cache.invalidateAll();
    }

    // ---- role inheritance --------------------------------------------------

    @Override
    public void addParentRole(String childKey, String parentKey) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "INSERT INTO gatedhouse.role_inherits (child_key, parent_key) VALUES (?, ?)")) {
            ps.setString(1, childKey);
            ps.setString(2, parentKey);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("addParentRole", e);
        }
        cache.invalidateAll();
    }

    @Override
    public void removeParentRole(String childKey, String parentKey) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "DELETE FROM gatedhouse.role_inherits WHERE child_key = ? AND parent_key = ?")) {
            ps.setString(1, childKey);
            ps.setString(2, parentKey);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("removeParentRole", e);
        }
        cache.invalidateAll();
    }

    @Override
    public List<String> getParentRoles(String childKey) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT parent_key FROM gatedhouse.role_inherits "
                 + "WHERE child_key = ? ORDER BY parent_key")) {
            ps.setString(1, childKey);
            try (ResultSet rs = ps.executeQuery()) {
                List<String> out = new ArrayList<>();
                while (rs.next()) {
                    out.add(rs.getString(1));
                }
                return out;
            }
        } catch (SQLException e) {
            throw fail("getParentRoles", e);
        }
    }

    // ---- assignments to identities ----------------------------------------

    @Override
    public void assignToIdentity(String identityId, String orgId, String roleKey) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "INSERT INTO gatedhouse.role_assignments (id, identity_id, org_id, role_key) "
                 + "VALUES (?, ?, ?, ?)")) {
            ps.setObject(1, UUID.randomUUID());
            ps.setString(2, identityId);
            ps.setString(3, orgId);
            ps.setString(4, roleKey);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("assignToIdentity", e);
        }
        cache.invalidate(identityId, orgId);
    }

    @Override
    public void revokeFromIdentity(String identityId, String orgId, String roleKey) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "DELETE FROM gatedhouse.role_assignments "
                 + "WHERE identity_id = ? AND org_id = ? AND role_key = ?")) {
            ps.setString(1, identityId);
            ps.setString(2, orgId);
            ps.setString(3, roleKey);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("revokeFromIdentity", e);
        }
        cache.invalidate(identityId, orgId);
    }

    @Override
    public List<String> getIdentityRoles(String identityId, String orgId) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT role_key FROM gatedhouse.role_assignments "
                 + "WHERE identity_id = ? AND org_id = ? ORDER BY role_key")) {
            ps.setString(1, identityId);
            ps.setString(2, orgId);
            try (ResultSet rs = ps.executeQuery()) {
                List<String> out = new ArrayList<>();
                while (rs.next()) {
                    out.add(rs.getString(1));
                }
                return out;
            }
        } catch (SQLException e) {
            throw fail("getIdentityRoles", e);
        }
    }

    // ---- assignments to groups --------------------------------------------

    @Override
    public void assignToGroup(String groupId, String orgId, String roleKey) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "INSERT INTO gatedhouse.group_roles (group_id, org_id, role_key) "
                 + "VALUES (?, ?, ?)")) {
            ps.setString(1, groupId);
            ps.setString(2, orgId);
            ps.setString(3, roleKey);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("assignToGroup", e);
        }
        // Affects every member of the group; cache doesn't index by group
        // membership, so wholesale invalidate.
        cache.invalidateAll();
    }

    @Override
    public void revokeFromGroup(String groupId, String orgId, String roleKey) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "DELETE FROM gatedhouse.group_roles "
                 + "WHERE group_id = ? AND org_id = ? AND role_key = ?")) {
            ps.setString(1, groupId);
            ps.setString(2, orgId);
            ps.setString(3, roleKey);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("revokeFromGroup", e);
        }
        cache.invalidateAll();
    }

    @Override
    public List<String> getGroupRoles(String groupId, String orgId) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT role_key FROM gatedhouse.group_roles "
                 + "WHERE group_id = ? AND org_id = ? ORDER BY role_key")) {
            ps.setString(1, groupId);
            ps.setString(2, orgId);
            try (ResultSet rs = ps.executeQuery()) {
                List<String> out = new ArrayList<>();
                while (rs.next()) {
                    out.add(rs.getString(1));
                }
                return out;
            }
        } catch (SQLException e) {
            throw fail("getGroupRoles", e);
        }
    }

    // ---- helpers -----------------------------------------------------------

    private static void setNullableString(PreparedStatement ps, int index, String value)
            throws SQLException {
        if (value == null) {
            ps.setNull(index, java.sql.Types.VARCHAR);
        } else {
            ps.setString(index, value);
        }
    }

    private static GatedhouseDatabaseException fail(String op, SQLException cause) {
        return new GatedhouseDatabaseException("RoleManager." + op + " failed", cause);
    }
}
