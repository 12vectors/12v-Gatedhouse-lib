package com.twelvevectors.gatedhouse;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
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
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "INSERT INTO gatedhouse.services (service, description) VALUES (?, ?)")) {
            ps.setString(1, service);
            ps.setString(2, description);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("addService", e);
        }
    }

    @Override
    public void removeService(String service) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "DELETE FROM gatedhouse.services WHERE service = ?")) {
            ps.setString(1, service);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("removeService", e);
        }
        // Cascade dropped resources, actions, and any role_permissions
        // referencing them. Affected identity set is wide.
        cache.invalidateAll();
    }

    @Override
    public boolean hasService(String service) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT 1 FROM gatedhouse.services WHERE service = ?")) {
            ps.setString(1, service);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw fail("hasService", e);
        }
    }

    @Override
    public List<String> listServices() {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT service FROM gatedhouse.services ORDER BY service");
             ResultSet rs = ps.executeQuery()) {
            List<String> out = new ArrayList<>();
            while (rs.next()) {
                out.add(rs.getString(1));
            }
            return out;
        } catch (SQLException e) {
            throw fail("listServices", e);
        }
    }

    // ---- resources ---------------------------------------------------------

    @Override
    public void addResource(String service, String resource, String description) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "INSERT INTO gatedhouse.resources (service, resource, description) VALUES (?, ?, ?)")) {
            ps.setString(1, service);
            ps.setString(2, resource);
            ps.setString(3, description);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("addResource", e);
        }
    }

    @Override
    public void removeResource(String service, String resource) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "DELETE FROM gatedhouse.resources WHERE service = ? AND resource = ?")) {
            ps.setString(1, service);
            ps.setString(2, resource);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("removeResource", e);
        }
        cache.invalidateAll();
    }

    @Override
    public boolean hasResource(String service, String resource) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT 1 FROM gatedhouse.resources WHERE service = ? AND resource = ?")) {
            ps.setString(1, service);
            ps.setString(2, resource);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw fail("hasResource", e);
        }
    }

    @Override
    public List<String> listResources(String service) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT resource FROM gatedhouse.resources WHERE service = ? ORDER BY resource")) {
            ps.setString(1, service);
            try (ResultSet rs = ps.executeQuery()) {
                List<String> out = new ArrayList<>();
                while (rs.next()) {
                    out.add(rs.getString(1));
                }
                return out;
            }
        } catch (SQLException e) {
            throw fail("listResources", e);
        }
    }

    // ---- actions -----------------------------------------------------------

    @Override
    public void addAction(String service, String resource, String action, String description) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "INSERT INTO gatedhouse.actions (service, resource, action, description) "
                 + "VALUES (?, ?, ?, ?)")) {
            ps.setString(1, service);
            ps.setString(2, resource);
            ps.setString(3, action);
            ps.setString(4, description);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("addAction", e);
        }
    }

    @Override
    public void removeAction(String service, String resource, String action) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "DELETE FROM gatedhouse.actions "
                 + "WHERE service = ? AND resource = ? AND action = ?")) {
            ps.setString(1, service);
            ps.setString(2, resource);
            ps.setString(3, action);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail("removeAction", e);
        }
        cache.invalidateAll();
    }

    @Override
    public boolean hasAction(String service, String resource, String action) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT 1 FROM gatedhouse.actions "
                 + "WHERE service = ? AND resource = ? AND action = ?")) {
            ps.setString(1, service);
            ps.setString(2, resource);
            ps.setString(3, action);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw fail("hasAction", e);
        }
    }

    @Override
    public List<String> listActions(String service, String resource) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT action FROM gatedhouse.actions "
                 + "WHERE service = ? AND resource = ? ORDER BY action")) {
            ps.setString(1, service);
            ps.setString(2, resource);
            try (ResultSet rs = ps.executeQuery()) {
                List<String> out = new ArrayList<>();
                while (rs.next()) {
                    out.add(rs.getString(1));
                }
                return out;
            }
        } catch (SQLException e) {
            throw fail("listActions", e);
        }
    }

    // ---- helpers -----------------------------------------------------------

    private static GatedhouseDatabaseException fail(String op, SQLException cause) {
        return new GatedhouseDatabaseException("PermissionCatalog." + op + " failed", cause);
    }
}
