// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

/**
 * The only class that references HikariCP. Loaded only after {@link
 * PooledDatabase} has checked HikariCP is present, so hosts that never call
 * {@code Database.fromUrl} never need it.
 */
final class HikariPool {

    private HikariPool() {}

    /**
     * Declared as {@link javax.sql.DataSource} (it is also {@link
     * AutoCloseable}) so callers never name a HikariCP type.
     */
    static javax.sql.DataSource open(String jdbcUrl, String user, String password,
                                     PooledDatabase.Settings settings) {
        HikariConfig config = new HikariConfig();
        config.setPoolName("gatedhouse");
        config.setJdbcUrl(jdbcUrl);
        config.setUsername(user);
        config.setPassword(password);
        config.setMaximumPoolSize(settings.maximumPoolSize());
        config.setConnectionTimeout(settings.connectionTimeout().toMillis());
        config.setMaxLifetime(settings.maxLifetime().toMillis());
        // The pool is Gatedhouse's own, so its sessions may carry settings.
        // Runs once per new connection.
        config.setConnectionInitSql(
            "SET statement_timeout = " + settings.statementTimeout().toMillis());
        // Open lazily: creating the pool must not fail just because the
        // database is briefly unreachable; the first operation reports it.
        config.setInitializationFailTimeout(-1);
        return new HikariDataSource(config);
    }
}
