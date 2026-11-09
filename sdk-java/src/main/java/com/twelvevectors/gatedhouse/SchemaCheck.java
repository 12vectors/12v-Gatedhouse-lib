// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

final class SchemaCheck {

    static final int EXPECTED_VERSION = 2;

    private SchemaCheck() {
    }

    /**
     * @throws SchemaNotInitializedException if the schema was never migrated
     * @throws SchemaOutOfDateException if it is older than this library expects
     * @throws GatedhouseDatabaseException if the database could not be queried
     */
    static void verify(Database database) {
        Integer current = Sql.<Integer>read(database, "SchemaCheck.verify", conn -> {
            if (!Sql.exists(conn,
                    "SELECT 1 FROM information_schema.tables "
                    + "WHERE table_schema = 'gatedhouse' AND table_name = 'schema_versions'")) {
                return null;
            }
            return Integer.valueOf(Sql.strings(conn,
                "SELECT COALESCE(MAX(version), 0)::TEXT FROM gatedhouse.schema_versions").get(0));
        });
        if (current == null) {
            throw new SchemaNotInitializedException();
        }
        if (current < EXPECTED_VERSION) {
            throw new SchemaOutOfDateException(current, EXPECTED_VERSION);
        }
    }
}
