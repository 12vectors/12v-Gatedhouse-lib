// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

public final class SchemaNotInitializedException extends RuntimeException {

    public SchemaNotInitializedException() {
        super(
            "Gatedhouse schema is not initialized in the target database.\n"
            + "\n"
            + "Run the migration tool against the same database, e.g.:\n"
            + "    java -cp gatedhouse-<version>.jar com.twelvevectors.gatedhouse.cli.Migrate \\\n"
            + "         <jdbc-url> <user> <password>\n"
            + "\n"
            + "Or, from your application's bootstrap, call:\n"
            + "    GatedhouseFactory.migrate(config);\n"
        );
    }
}
