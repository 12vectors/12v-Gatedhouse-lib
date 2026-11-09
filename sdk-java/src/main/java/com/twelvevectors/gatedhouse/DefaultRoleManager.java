// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.sql.PreparedStatement;
import java.util.List;
import java.util.UUID;

final class DefaultRoleManager implements RoleManager {

    /**
     * Serializes role-inheritance edits across every process and instance
     * sharing the database, so two concurrent edits cannot each pass the
     * cycle check and together close a cycle. Transaction-scoped: released
     * at commit or rollback, never left on a pooled connection.
     */
    static final long INHERITANCE_LOCK_KEY = 0x6768726F6C65696EL; // 'ghrolein'

    private final Database database;
    private final PermissionCache cache;

    DefaultRoleManager(Database database, PermissionCache cache) {
        this.database = database;
        this.cache = cache;
    }

    // ---- role definitions --------------------------------------------------

    @Override
    public void createRole(String key, String name, String description) {
        Sql.write(database, op("createRole"), conn -> Sql.update(conn,
            "INSERT INTO gatedhouse.roles (key, name, description, is_system) "
            + "VALUES (?, ?, ?, FALSE)", key, name, description));
    }

    @Override
    public void deleteRole(String key) {
        Sql.write(database, op("deleteRole"), conn -> Sql.update(conn,
            "DELETE FROM gatedhouse.roles WHERE key = ? AND is_system = FALSE", key));
        // Cascade dropped every assignment of this role; affected identity
        // set is wide and not worth enumerating.
        cache.invalidateAll();
    }

    @Override
    public boolean hasRole(String key) {
        return Sql.read(database, op("hasRole"), conn -> Sql.exists(conn,
            "SELECT 1 FROM gatedhouse.roles WHERE key = ?", key));
    }

    @Override
    public List<String> listRoles() {
        return Sql.read(database, op("listRoles"), conn -> Sql.strings(conn,
            "SELECT key FROM gatedhouse.roles ORDER BY key"));
    }

    // ---- permission grants -------------------------------------------------

    @Override
    public void grantPermission(String roleKey, String service, String resource, String action) {
        Sql.write(database, op("grantPermission"), conn -> Sql.update(conn,
            "INSERT INTO gatedhouse.role_permissions (id, role_key, service, resource, action) "
            + "VALUES (?, ?, ?, ?, ?)", UUID.randomUUID(), roleKey, service, resource, action));
        // Affects every identity holding this role (directly, via group, or
        // via inheritance). Wholesale invalidate.
        cache.invalidateAll();
    }

    @Override
    public void revokePermission(String roleKey, String service, String resource, String action) {
        // Match on COALESCE so NULLs (wildcards) compare correctly.
        Sql.write(database, op("revokePermission"), conn -> Sql.update(conn,
            "DELETE FROM gatedhouse.role_permissions "
            + "WHERE role_key = ? "
            + "  AND COALESCE(service,  '') = COALESCE(?, '') "
            + "  AND COALESCE(resource, '') = COALESCE(?, '') "
            + "  AND COALESCE(action,   '') = COALESCE(?, '')",
            roleKey, service, resource, action));
        cache.invalidateAll();
    }

    // ---- role inheritance --------------------------------------------------

    /**
     * Inheritance must stay acyclic. The check and the insert run in one
     * transaction under {@link #INHERITANCE_LOCK_KEY}, so concurrent calls
     * adding {@code A -> B} and {@code B -> A} cannot both succeed.
     */
    @Override
    public void addParentRole(String childKey, String parentKey) {
        Sql.write(database, op("addParentRole"), conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                     "SELECT pg_advisory_xact_lock(?)")) {
                ps.setLong(1, INHERITANCE_LOCK_KEY);
                ps.execute();
            }
            // Would the new edge close a cycle? Only if the child is already
            // the parent itself or one of the parent's ancestors.
            boolean cycle = !childKey.equals(parentKey) && Sql.exists(conn,
                "WITH RECURSIVE ancestors(key) AS ( "
                + "    SELECT ?::TEXT "
                + "    UNION "
                + "    SELECT ri.parent_key FROM gatedhouse.role_inherits ri "
                + "    JOIN ancestors a ON ri.child_key = a.key "
                + ") SELECT 1 FROM ancestors WHERE key = ?",
                parentKey, childKey);
            if (cycle) {
                throw new IllegalArgumentException(
                    "Role '" + childKey + "' cannot inherit from '" + parentKey + "': '"
                    + parentKey + "' already inherits from '" + childKey
                    + "', so this would create an inheritance cycle");
            }
            return Sql.update(conn,
                "INSERT INTO gatedhouse.role_inherits (child_key, parent_key) VALUES (?, ?)",
                childKey, parentKey);
        });
        cache.invalidateAll();
    }

    @Override
    public void removeParentRole(String childKey, String parentKey) {
        Sql.write(database, op("removeParentRole"), conn -> Sql.update(conn,
            "DELETE FROM gatedhouse.role_inherits WHERE child_key = ? AND parent_key = ?",
            childKey, parentKey));
        cache.invalidateAll();
    }

    @Override
    public List<String> getParentRoles(String childKey) {
        return Sql.read(database, op("getParentRoles"), conn -> Sql.strings(conn,
            "SELECT parent_key FROM gatedhouse.role_inherits "
            + "WHERE child_key = ? ORDER BY parent_key", childKey));
    }

    // ---- assignments to identities ----------------------------------------

    @Override
    public void assignToIdentity(String identityId, String orgId, String roleKey) {
        Sql.write(database, op("assignToIdentity"), conn -> Sql.update(conn,
            "INSERT INTO gatedhouse.role_assignments (id, identity_id, org_id, role_key) "
            + "VALUES (?, ?, ?, ?)", UUID.randomUUID(), identityId, orgId, roleKey));
        cache.invalidate(identityId, orgId);
    }

    @Override
    public void revokeFromIdentity(String identityId, String orgId, String roleKey) {
        Sql.write(database, op("revokeFromIdentity"), conn -> Sql.update(conn,
            "DELETE FROM gatedhouse.role_assignments "
            + "WHERE identity_id = ? AND org_id = ? AND role_key = ?",
            identityId, orgId, roleKey));
        cache.invalidate(identityId, orgId);
    }

    @Override
    public List<String> getIdentityRoles(String identityId, String orgId) {
        return Sql.read(database, op("getIdentityRoles"), conn -> Sql.strings(conn,
            "SELECT role_key FROM gatedhouse.role_assignments "
            + "WHERE identity_id = ? AND org_id = ? ORDER BY role_key", identityId, orgId));
    }

    // ---- assignments to groups --------------------------------------------

    @Override
    public void assignToGroup(String groupId, String orgId, String roleKey) {
        Sql.write(database, op("assignToGroup"), conn -> Sql.update(conn,
            "INSERT INTO gatedhouse.group_roles (group_id, org_id, role_key) "
            + "VALUES (?, ?, ?)", groupId, orgId, roleKey));
        // Affects every member of the group; cache doesn't index by group
        // membership, so wholesale invalidate.
        cache.invalidateAll();
    }

    @Override
    public void revokeFromGroup(String groupId, String orgId, String roleKey) {
        Sql.write(database, op("revokeFromGroup"), conn -> Sql.update(conn,
            "DELETE FROM gatedhouse.group_roles "
            + "WHERE group_id = ? AND org_id = ? AND role_key = ?", groupId, orgId, roleKey));
        cache.invalidateAll();
    }

    @Override
    public List<String> getGroupRoles(String groupId, String orgId) {
        return Sql.read(database, op("getGroupRoles"), conn -> Sql.strings(conn,
            "SELECT role_key FROM gatedhouse.group_roles "
            + "WHERE group_id = ? AND org_id = ? ORDER BY role_key", groupId, orgId));
    }

    // ---- helpers -----------------------------------------------------------

    private static String op(String method) {
        return "RoleManager." + method;
    }
}
