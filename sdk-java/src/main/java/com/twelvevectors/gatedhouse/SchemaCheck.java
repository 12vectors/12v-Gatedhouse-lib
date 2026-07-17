// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

final class SchemaCheck {

    static final int EXPECTED_VERSION = 1;

    private SchemaCheck() {
    }

    static void verify(Database database) throws SQLException {
        try (Connection conn = database.getConnection()) {
            if (!schemaVersionsTableExists(conn)) {
                throw new SchemaNotInitializedException();
            }
            int current = currentVersion(conn);
            if (current < EXPECTED_VERSION) {
                throw new SchemaOutOfDateException(current, EXPECTED_VERSION);
            }
        }
    }

    private static boolean schemaVersionsTableExists(Connection conn) throws SQLException {
        String sql =
            "SELECT 1 FROM information_schema.tables "
            + "WHERE table_schema = 'gatedhouse' AND table_name = 'schema_versions'";
        try (PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            return rs.next();
        }
    }

    private static int currentVersion(Connection conn) throws SQLException {
        String sql = "SELECT COALESCE(MAX(version), 0) FROM gatedhouse.schema_versions";
        try (PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            rs.next();
            return rs.getInt(1);
        }
    }
}
