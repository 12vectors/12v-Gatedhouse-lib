// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.util.List;

final class DefaultPermissionCatalog implements PermissionCatalog {

    private final Database database;
    private final PermissionCache cache;

    DefaultPermissionCatalog(Database database, PermissionCache cache) {
        this.database = database;
        this.cache = cache;
    }

    // ---- services ----------------------------------------------------------

    @Override
    public void addService(String service, String description) {
        Sql.write(database, op("addService"), conn -> Sql.update(conn,
            "INSERT INTO gatedhouse.services (service, description) VALUES (?, ?)",
            service, description));
    }

    @Override
    public void removeService(String service) {
        Sql.write(database, op("removeService"), conn -> Sql.update(conn,
            "DELETE FROM gatedhouse.services WHERE service = ?", service));
        // Cascade dropped resources, actions, and any role_permissions
        // referencing them. Affected identity set is wide.
        cache.invalidateAll();
    }

    @Override
    public boolean hasService(String service) {
        return Sql.read(database, op("hasService"), conn -> Sql.exists(conn,
            "SELECT 1 FROM gatedhouse.services WHERE service = ?", service));
    }

    @Override
    public List<String> listServices() {
        return Sql.read(database, op("listServices"), conn -> Sql.strings(conn,
            "SELECT service FROM gatedhouse.services ORDER BY service"));
    }

    // ---- resources ---------------------------------------------------------

    @Override
    public void addResource(String service, String resource, String description) {
        Sql.write(database, op("addResource"), conn -> Sql.update(conn,
            "INSERT INTO gatedhouse.resources (service, resource, description) VALUES (?, ?, ?)",
            service, resource, description));
    }

    @Override
    public void removeResource(String service, String resource) {
        Sql.write(database, op("removeResource"), conn -> Sql.update(conn,
            "DELETE FROM gatedhouse.resources WHERE service = ? AND resource = ?",
            service, resource));
        cache.invalidateAll();
    }

    @Override
    public boolean hasResource(String service, String resource) {
        return Sql.read(database, op("hasResource"), conn -> Sql.exists(conn,
            "SELECT 1 FROM gatedhouse.resources WHERE service = ? AND resource = ?",
            service, resource));
    }

    @Override
    public List<String> listResources(String service) {
        return Sql.read(database, op("listResources"), conn -> Sql.strings(conn,
            "SELECT resource FROM gatedhouse.resources WHERE service = ? ORDER BY resource",
            service));
    }

    // ---- actions -----------------------------------------------------------

    @Override
    public void addAction(String service, String resource, String action, String description) {
        Sql.write(database, op("addAction"), conn -> Sql.update(conn,
            "INSERT INTO gatedhouse.actions (service, resource, action, description) "
            + "VALUES (?, ?, ?, ?)", service, resource, action, description));
    }

    @Override
    public void removeAction(String service, String resource, String action) {
        Sql.write(database, op("removeAction"), conn -> Sql.update(conn,
            "DELETE FROM gatedhouse.actions "
            + "WHERE service = ? AND resource = ? AND action = ?", service, resource, action));
        cache.invalidateAll();
    }

    @Override
    public boolean hasAction(String service, String resource, String action) {
        return Sql.read(database, op("hasAction"), conn -> Sql.exists(conn,
            "SELECT 1 FROM gatedhouse.actions "
            + "WHERE service = ? AND resource = ? AND action = ?", service, resource, action));
    }

    @Override
    public List<String> listActions(String service, String resource) {
        return Sql.read(database, op("listActions"), conn -> Sql.strings(conn,
            "SELECT action FROM gatedhouse.actions "
            + "WHERE service = ? AND resource = ? ORDER BY action", service, resource));
    }

    // ---- helpers -----------------------------------------------------------

    private static String op(String method) {
        return "PermissionCatalog." + method;
    }
}
