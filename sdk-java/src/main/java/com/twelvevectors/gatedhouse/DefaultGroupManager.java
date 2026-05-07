package com.twelvevectors.gatedhouse;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

final class DefaultGroupManager implements GroupManager {

    private final Database database;
    private final PermissionCache cache;

    DefaultGroupManager(Database database, PermissionCache cache) {
        this.database = database;
        this.cache = cache;
    }

    // ---- group definitions -------------------------------------------------

    @Override
    public void createGroup(String groupId, String orgId, String name, String description) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "INSERT INTO gatedhouse.groups (id, org_id, name, description) "
                 + "VALUES (?, ?, ?, ?)")) {
            ps.setString(1, groupId);
            ps.setString(2, orgId);
            ps.setString(3, name);
            ps.setString(4, description);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("createGroup", e);
        }
    }

    @Override
    public void deleteGroup(String groupId, String orgId) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "DELETE FROM gatedhouse.groups WHERE id = ? AND org_id = ?")) {
            ps.setString(1, groupId);
            ps.setString(2, orgId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("deleteGroup", e);
        }
        // Cascade dropped group_memberships and group_roles for every
        // member of this group.
        cache.invalidateAll();
    }

    @Override
    public boolean hasGroup(String groupId, String orgId) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT 1 FROM gatedhouse.groups WHERE id = ? AND org_id = ?")) {
            ps.setString(1, groupId);
            ps.setString(2, orgId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw fail("hasGroup", e);
        }
    }

    @Override
    public List<String> listGroups(String orgId) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT id FROM gatedhouse.groups WHERE org_id = ? ORDER BY id")) {
            ps.setString(1, orgId);
            try (ResultSet rs = ps.executeQuery()) {
                List<String> out = new ArrayList<>();
                while (rs.next()) {
                    out.add(rs.getString(1));
                }
                return out;
            }
        } catch (SQLException e) {
            throw fail("listGroups", e);
        }
    }

    // ---- group membership -------------------------------------------------

    @Override
    public void addIdentityToGroup(String groupId, String orgId, String identityId) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "INSERT INTO gatedhouse.group_memberships (group_id, org_id, identity_id) "
                 + "VALUES (?, ?, ?)")) {
            ps.setString(1, groupId);
            ps.setString(2, orgId);
            ps.setString(3, identityId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("addIdentityToGroup", e);
        }
        cache.invalidate(identityId, orgId);
    }

    @Override
    public void removeIdentityFromGroup(String groupId, String orgId, String identityId) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "DELETE FROM gatedhouse.group_memberships "
                 + "WHERE group_id = ? AND org_id = ? AND identity_id = ?")) {
            ps.setString(1, groupId);
            ps.setString(2, orgId);
            ps.setString(3, identityId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("removeIdentityFromGroup", e);
        }
        cache.invalidate(identityId, orgId);
    }

    @Override
    public List<String> getGroupMembers(String groupId, String orgId) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT identity_id FROM gatedhouse.group_memberships "
                 + "WHERE group_id = ? AND org_id = ? ORDER BY identity_id")) {
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
            throw fail("getGroupMembers", e);
        }
    }

    @Override
    public List<String> getIdentityGroups(String identityId, String orgId) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT group_id FROM gatedhouse.group_memberships "
                 + "WHERE identity_id = ? AND org_id = ? ORDER BY group_id")) {
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
            throw fail("getIdentityGroups", e);
        }
    }

    private static GatedhouseDatabaseException fail(String op, SQLException cause) {
        return new GatedhouseDatabaseException("GroupManager." + op + " failed", cause);
    }
}
