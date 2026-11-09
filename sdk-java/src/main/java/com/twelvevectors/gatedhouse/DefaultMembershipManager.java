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
        Sql.write(database, op("createMembership"), conn -> {
            Optional<MembershipStatus> current = lockStatus(conn, identityId, orgId);
            if (current.isPresent() && current.get() == MembershipStatus.REMOVED) {
                // Rejoin: same row, clean slate.
                clearGrants(conn, identityId, orgId);
                return Sql.update(conn,
                    "UPDATE gatedhouse.memberships "
                    + "SET status = 'active'::gatedhouse.membership_status, "
                    + "    entity_type = ?::gatedhouse.entity_type, updated_at = NOW() "
                    + "WHERE identity_id = ? AND org_id = ?",
                    entityType.dbValue(), identityId, orgId);
            }
            // No row, or a live one: a live row makes this insert fail
            // with the unique violation, exactly as before.
            return Sql.update(conn,
                "INSERT INTO gatedhouse.memberships "
                + "(id, identity_id, org_id, entity_type, status) "
                + "VALUES (?, ?, ?, ?::gatedhouse.entity_type, "
                + "'active'::gatedhouse.membership_status)",
                UUID.randomUUID(), identityId, orgId, entityType.dbValue());
        });
        cache.invalidate(identityId, orgId);
    }

    @Override
    public void removeMembership(String identityId, String orgId) {
        Sql.write(database, op("removeMembership"), conn -> {
            Optional<MembershipStatus> current = lockStatus(conn, identityId, orgId);
            if (current.isPresent() && current.get() != MembershipStatus.REMOVED) {
                updateStatus(conn, identityId, orgId, MembershipStatus.REMOVED);
            }
            // Also when already REMOVED or absent: clears grants that
            // arrived after an earlier removal.
            clearGrants(conn, identityId, orgId);
            return null;
        });
        cache.invalidate(identityId, orgId);
    }

    @Override
    public boolean hasMembership(String identityId, String orgId) {
        return Sql.read(database, op("hasMembership"), conn -> Sql.exists(conn,
            "SELECT 1 FROM gatedhouse.memberships "
            + "WHERE identity_id = ? AND org_id = ? AND status <> 'removed'",
            identityId, orgId));
    }

    @Override
    public void setStatus(String identityId, String orgId, MembershipStatus status) {
        if (status == MembershipStatus.REMOVED) {
            removeMembership(identityId, orgId);
            return;
        }
        Sql.write(database, op("setStatus"), conn -> {
            Optional<MembershipStatus> current = lockStatus(conn, identityId, orgId);
            if (current.isEmpty()) {
                return null;
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
            return null;
        });
        cache.invalidate(identityId, orgId);
    }

    @Override
    public Optional<MembershipStatus> getStatus(String identityId, String orgId) {
        return Sql.read(database, op("getStatus"), conn -> {
            try (PreparedStatement ps = Sql.prepare(conn,
                     "SELECT status::TEXT FROM gatedhouse.memberships "
                     + "WHERE identity_id = ? AND org_id = ?", identityId, orgId);
                 ResultSet rs = ps.executeQuery()) {
                return rs.next()
                    ? Optional.of(MembershipStatus.fromDbValue(rs.getString(1)))
                    : Optional.<MembershipStatus>empty();
            }
        });
    }

    @Override
    public Optional<EntityType> getEntityType(String identityId, String orgId) {
        return Sql.read(database, op("getEntityType"), conn -> {
            try (PreparedStatement ps = Sql.prepare(conn,
                     "SELECT entity_type::TEXT FROM gatedhouse.memberships "
                     + "WHERE identity_id = ? AND org_id = ?", identityId, orgId);
                 ResultSet rs = ps.executeQuery()) {
                return rs.next()
                    ? Optional.of(EntityType.fromDbValue(rs.getString(1)))
                    : Optional.<EntityType>empty();
            }
        });
    }

    // ---- helpers -------------------------------------------------------------

    private static String op(String method) {
        return "MembershipManager." + method;
    }

    private static Optional<MembershipStatus> lockStatus(
            Connection conn, String identityId, String orgId) throws SQLException {
        try (PreparedStatement ps = Sql.prepare(conn,
                 "SELECT status::TEXT FROM gatedhouse.memberships "
                 + "WHERE identity_id = ? AND org_id = ? FOR UPDATE", identityId, orgId);
             ResultSet rs = ps.executeQuery()) {
            return rs.next()
                ? Optional.of(MembershipStatus.fromDbValue(rs.getString(1)))
                : Optional.empty();
        }
    }

    private static void updateStatus(
            Connection conn, String identityId, String orgId, MembershipStatus status)
            throws SQLException {
        Sql.update(conn,
            "UPDATE gatedhouse.memberships "
            + "SET status = ?::gatedhouse.membership_status, updated_at = NOW() "
            + "WHERE identity_id = ? AND org_id = ?",
            status.dbValue(), identityId, orgId);
    }

    /** Revokes the identity's direct roles and group memberships in the org. */
    private static void clearGrants(Connection conn, String identityId, String orgId)
            throws SQLException {
        Sql.update(conn,
            "DELETE FROM gatedhouse.role_assignments WHERE identity_id = ? AND org_id = ?",
            identityId, orgId);
        Sql.update(conn,
            "DELETE FROM gatedhouse.group_memberships WHERE identity_id = ? AND org_id = ?",
            identityId, orgId);
    }
}
