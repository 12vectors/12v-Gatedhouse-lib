// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import java.util.UUID;

/**
 * Memberships are never deleted. Every lifecycle transition runs in a single
 * transaction that first row-locks the membership, so a removal and the
 * revocation of its grants commit together, and concurrent transitions on the
 * same membership serialize. See docs/MODEL.md, "The membership lifecycle".
 */
final class DefaultMembershipManager implements MembershipManager {

    private final Database database;
    private final PermissionCache cache;

    DefaultMembershipManager(Database database, PermissionCache cache) {
        this.database = database;
        this.cache = cache;
    }

    @Override
    public void createMembership(String identityId, String orgId, EntityType entityType) {
        try (Connection conn = database.getConnection()) {
            inTransaction(conn, () -> {
                Optional<MembershipStatus> current = lockStatus(conn, identityId, orgId);
                if (current.isPresent() && current.get() == MembershipStatus.REMOVED) {
                    // Rejoin: same row, clean slate.
                    clearGrants(conn, identityId, orgId);
                    try (PreparedStatement ps = conn.prepareStatement(
                             "UPDATE gatedhouse.memberships "
                             + "SET status = 'active'::gatedhouse.membership_status, "
                             + "    entity_type = ?::gatedhouse.entity_type, updated_at = NOW() "
                             + "WHERE identity_id = ? AND org_id = ?")) {
                        ps.setString(1, entityType.dbValue());
                        ps.setString(2, identityId);
                        ps.setString(3, orgId);
                        ps.executeUpdate();
                    }
                    return;
                }
                // No row, or a live one: a live row makes this insert fail
                // with the unique violation, exactly as before.
                try (PreparedStatement ps = conn.prepareStatement(
                         "INSERT INTO gatedhouse.memberships "
                         + "(id, identity_id, org_id, entity_type, status) "
                         + "VALUES (?, ?, ?, ?::gatedhouse.entity_type, 'active'::gatedhouse.membership_status)")) {
                    ps.setObject(1, UUID.randomUUID());
                    ps.setString(2, identityId);
                    ps.setString(3, orgId);
                    ps.setString(4, entityType.dbValue());
                    ps.executeUpdate();
                }
            });
        } catch (SQLException e) {
            throw fail("createMembership", e);
        }
        cache.invalidate(identityId, orgId);
    }

    @Override
    public void removeMembership(String identityId, String orgId) {
        try (Connection conn = database.getConnection()) {
            inTransaction(conn, () -> {
                Optional<MembershipStatus> current = lockStatus(conn, identityId, orgId);
                if (current.isPresent() && current.get() != MembershipStatus.REMOVED) {
                    updateStatus(conn, identityId, orgId, MembershipStatus.REMOVED);
                }
                // Also when already REMOVED or absent: clears grants that
                // arrived after an earlier removal.
                clearGrants(conn, identityId, orgId);
            });
        } catch (SQLException e) {
            throw fail("removeMembership", e);
        }
        cache.invalidate(identityId, orgId);
    }

    @Override
    public boolean hasMembership(String identityId, String orgId) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT 1 FROM gatedhouse.memberships "
                 + "WHERE identity_id = ? AND org_id = ? AND status <> 'removed'")) {
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
        if (status == MembershipStatus.REMOVED) {
            removeMembership(identityId, orgId);
            return;
        }
        try (Connection conn = database.getConnection()) {
            inTransaction(conn, () -> {
                Optional<MembershipStatus> current = lockStatus(conn, identityId, orgId);
                if (current.isEmpty()) {
                    return;
                }
                if (current.get() == MembershipStatus.REMOVED) {
                    if (status == MembershipStatus.SUSPENDED) {
                        throw new IllegalStateException(
                            "Cannot suspend removed membership (" + identityId + ", " + orgId
                            + "); revive it as ACTIVE or PENDING instead");
                    }
                    // Rejoin: clean slate.
                    clearGrants(conn, identityId, orgId);
                }
                updateStatus(conn, identityId, orgId, status);
            });
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

    // ---- transaction helpers ------------------------------------------------

    @FunctionalInterface
    private interface SqlWork {
        void run() throws SQLException;
    }

    private static void inTransaction(Connection conn, SqlWork work) throws SQLException {
        boolean previousAutoCommit = conn.getAutoCommit();
        conn.setAutoCommit(false);
        try {
            work.run();
            conn.commit();
        } catch (SQLException | RuntimeException e) {
            try {
                conn.rollback();
            } catch (SQLException rollbackFailure) {
                e.addSuppressed(rollbackFailure);
            }
            throw e;
        } finally {
            // Restore for pooled connections.
            conn.setAutoCommit(previousAutoCommit);
        }
    }

    private static Optional<MembershipStatus> lockStatus(
            Connection conn, String identityId, String orgId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                 "SELECT status::TEXT FROM gatedhouse.memberships "
                 + "WHERE identity_id = ? AND org_id = ? FOR UPDATE")) {
            ps.setString(1, identityId);
            ps.setString(2, orgId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next()
                    ? Optional.of(MembershipStatus.fromDbValue(rs.getString(1)))
                    : Optional.empty();
            }
        }
    }

    private static void updateStatus(
            Connection conn, String identityId, String orgId, MembershipStatus status)
            throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                 "UPDATE gatedhouse.memberships "
                 + "SET status = ?::gatedhouse.membership_status, updated_at = NOW() "
                 + "WHERE identity_id = ? AND org_id = ?")) {
            ps.setString(1, status.dbValue());
            ps.setString(2, identityId);
            ps.setString(3, orgId);
            ps.executeUpdate();
        }
    }

    /** Revokes the identity's direct roles and group memberships in the org. */
    private static void clearGrants(Connection conn, String identityId, String orgId)
            throws SQLException {
        for (String sql : new String[] {
                 "DELETE FROM gatedhouse.role_assignments WHERE identity_id = ? AND org_id = ?",
                 "DELETE FROM gatedhouse.group_memberships WHERE identity_id = ? AND org_id = ?"}) {
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, identityId);
                ps.setString(2, orgId);
                ps.executeUpdate();
            }
        }
    }

    private static GatedhouseDatabaseException fail(String op, SQLException cause) {
        return new GatedhouseDatabaseException("MembershipManager." + op + " failed", cause);
    }
}
