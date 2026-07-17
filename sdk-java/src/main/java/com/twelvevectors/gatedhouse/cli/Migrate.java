// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse.cli;

import com.twelvevectors.gatedhouse.Database;
import com.twelvevectors.gatedhouse.GatedhouseConfig;
import com.twelvevectors.gatedhouse.GatedhouseFactory;

public final class Migrate {

    private Migrate() {
    }

    public static void main(String[] args) {
        if (args.length < 2 || args.length > 3) {
            System.err.println(
                "Usage: java -cp gatedhouse-<version>.jar:postgresql-<version>.jar \\\n"
                + "         com.twelvevectors.gatedhouse.cli.Migrate \\\n"
                + "         <jdbc-url> <user> [password]\n"
                + "\n"
                + "Example:\n"
                + "  java -cp gatedhouse.jar:postgresql.jar com.twelvevectors.gatedhouse.cli.Migrate \\\n"
                + "       jdbc:postgresql://localhost:5432/mydb gatedhouse_user secret"
            );
            System.exit(2);
        }

        String url = args[0];
        String user = args[1];
        String password = args.length == 3 ? args[2] : "";

        Database database = Database.fromUrl(url, user, password);
        GatedhouseConfig config = GatedhouseConfig.builder()
            .database(database)
            .build();

        try {
            GatedhouseFactory.migrate(config);
            System.out.println("Gatedhouse migration completed successfully.");
        } catch (RuntimeException e) {
            System.err.println("Gatedhouse migration failed: " + e.getMessage());
            Throwable cause = e.getCause();
            if (cause != null) {
                System.err.println("Caused by: " + cause);
            }
            System.exit(1);
        }
    }
}
