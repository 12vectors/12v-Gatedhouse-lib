// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

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
        Sql.write(database, op("createGroup"), conn -> Sql.update(conn,
            "INSERT INTO gatedhouse.groups (id, org_id, name, description) "
            + "VALUES (?, ?, ?, ?)", groupId, orgId, name, description));
    }

    @Override
    public void deleteGroup(String groupId, String orgId) {
        Sql.write(database, op("deleteGroup"), conn -> Sql.update(conn,
            "DELETE FROM gatedhouse.groups WHERE id = ? AND org_id = ?", groupId, orgId));
        // Cascade dropped group_memberships and group_roles for every
        // member of this group.
        cache.invalidateAll();
    }

    @Override
    public boolean hasGroup(String groupId, String orgId) {
        return Sql.read(database, op("hasGroup"), conn -> Sql.exists(conn,
            "SELECT 1 FROM gatedhouse.groups WHERE id = ? AND org_id = ?", groupId, orgId));
    }

    @Override
    public List<String> listGroups(String orgId) {
        return Sql.read(database, op("listGroups"), conn -> Sql.strings(conn,
            "SELECT id FROM gatedhouse.groups WHERE org_id = ? ORDER BY id", orgId));
    }

    // ---- group membership -------------------------------------------------

    @Override
    public void addIdentityToGroup(String groupId, String orgId, String identityId) {
        Sql.write(database, op("addIdentityToGroup"), conn -> Sql.update(conn,
            "INSERT INTO gatedhouse.group_memberships (group_id, org_id, identity_id) "
            + "VALUES (?, ?, ?)", groupId, orgId, identityId));
        cache.invalidate(identityId, orgId);
    }

    @Override
    public void removeIdentityFromGroup(String groupId, String orgId, String identityId) {
        Sql.write(database, op("removeIdentityFromGroup"), conn -> Sql.update(conn,
            "DELETE FROM gatedhouse.group_memberships "
            + "WHERE group_id = ? AND org_id = ? AND identity_id = ?",
            groupId, orgId, identityId));
        cache.invalidate(identityId, orgId);
    }

    @Override
    public List<String> getGroupMembers(String groupId, String orgId) {
        return Sql.read(database, op("getGroupMembers"), conn -> Sql.strings(conn,
            "SELECT identity_id FROM gatedhouse.group_memberships "
            + "WHERE group_id = ? AND org_id = ? ORDER BY identity_id", groupId, orgId));
    }

    @Override
    public List<String> getIdentityGroups(String identityId, String orgId) {
        return Sql.read(database, op("getIdentityGroups"), conn -> Sql.strings(conn,
            "SELECT group_id FROM gatedhouse.group_memberships "
            + "WHERE identity_id = ? AND org_id = ? ORDER BY group_id", identityId, orgId));
    }

    private static String op(String method) {
        return "GroupManager." + method;
    }
}
