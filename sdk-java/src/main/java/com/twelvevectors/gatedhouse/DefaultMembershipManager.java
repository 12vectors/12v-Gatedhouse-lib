package com.twelvevectors.gatedhouse;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import java.util.UUID;

final class DefaultMembershipManager implements MembershipManager {

    private final Database database;
    private final PermissionCache cache;

    DefaultMembershipManager(Database database, PermissionCache cache) {
        this.database = database;
        this.cache = cache;
    }

    @Override
    public void createMembership(String identityId, String orgId, EntityType entityType) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "INSERT INTO gatedhouse.memberships "
                 + "(id, identity_id, org_id, entity_type, status) "
                 + "VALUES (?, ?, ?, ?::gatedhouse.entity_type, 'active'::gatedhouse.membership_status)")) {
            ps.setObject(1, UUID.randomUUID());
            ps.setString(2, identityId);
            ps.setString(3, orgId);
            ps.setString(4, entityType.dbValue());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("createMembership", e);
        }
        cache.invalidate(identityId, orgId);
    }

    @Override
    public void deleteMembership(String identityId, String orgId) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "DELETE FROM gatedhouse.memberships WHERE identity_id = ? AND org_id = ?")) {
            ps.setString(1, identityId);
            ps.setString(2, orgId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("deleteMembership", e);
        }
        cache.invalidate(identityId, orgId);
    }

    @Override
    public boolean hasMembership(String identityId, String orgId) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT 1 FROM gatedhouse.memberships WHERE identity_id = ? AND org_id = ?")) {
            ps.setString(1, identityId);
            ps.setString(2, orgId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw fail("hasMembership", e);
        }
    }

    @Override
    public void setStatus(String identityId, String orgId, MembershipStatus status) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "UPDATE gatedhouse.memberships "
                 + "SET status = ?::gatedhouse.membership_status, updated_at = NOW() "
                 + "WHERE identity_id = ? AND org_id = ?")) {
            ps.setString(1, status.dbValue());
            ps.setString(2, identityId);
            ps.setString(3, orgId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("setStatus", e);
        }
        cache.invalidate(identityId, orgId);
    }

    @Override
    public Optional<MembershipStatus> getStatus(String identityId, String orgId) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT status::TEXT FROM gatedhouse.memberships "
                 + "WHERE identity_id = ? AND org_id = ?")) {
            ps.setString(1, identityId);
            ps.setString(2, orgId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(MembershipStatus.fromDbValue(rs.getString(1)));
                }
                return Optional.empty();
            }
        } catch (SQLException e) {
            throw fail("getStatus", e);
        }
    }

    @Override
    public Optional<EntityType> getEntityType(String identityId, String orgId) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT entity_type::TEXT FROM gatedhouse.memberships "
                 + "WHERE identity_id = ? AND org_id = ?")) {
            ps.setString(1, identityId);
            ps.setString(2, orgId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(EntityType.fromDbValue(rs.getString(1)));
                }
                return Optional.empty();
            }
        } catch (SQLException e) {
            throw fail("getEntityType", e);
        }
    }

    private static GatedhouseDatabaseException fail(String op, SQLException cause) {
        return new GatedhouseDatabaseException("MembershipManager." + op + " failed", cause);
    }
}
