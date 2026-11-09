// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Objects;
import javax.sql.DataSource;

/**
 * Where Gatedhouse gets its database connections. Gatedhouse borrows one
 * connection per operation, never holds two at once, and closes it when the
 * operation ends, which returns it to the host's pool.
 *
 * <p>Ways to provide one, in order of preference for production:
 * <ol>
 *   <li>{@link #fromDataSource(DataSource)}: your application's existing
 *       pool (HikariCP, Agroal, DBCP2, Tomcat JDBC, an application server's
 *       JNDI pool, Spring Boot's auto-configured {@code DataSource}). Gatedhouse
 *       then opens no connections of its own.</li>
 *   <li>A lambda, for any other connection source:
 *       {@code Database db = myPool::borrow;}</li>
 *   <li>{@link #fromUrl(String, String, String)}: Gatedhouse runs its own
 *       pool. Recommended for development and staging; requires the optional
 *       HikariCP dependency.</li>
 * </ol>
 *
 * <p>Whatever the source, Gatedhouse commits or rolls back its own work and
 * hands each connection back with its autocommit setting unchanged and no
 * transaction open. It refuses a connection that is already inside a
 * transaction (for example one bound to a Spring {@code @Transactional}
 * method through a transaction-aware {@code DataSource}) rather than commit
 * the caller's work.
 *
 * <p>Implementations must be safe to call from many threads at once.
 */
@FunctionalInterface
public interface Database {

    /**
     * Returns a connection for one unit of work. Gatedhouse closes it when the
     * unit of work ends. Must not return the same connection to two callers
     * at the same time.
     */
    Connection getConnection() throws SQLException;

    /**
     * Borrows connections from the host application's pool. Gatedhouse opens
     * no connections of its own and never closes the pool.
     */
    static Database fromDataSource(DataSource dataSource) {
        Objects.requireNonNull(dataSource, "dataSource");
        return dataSource::getConnection;
    }

    /**
     * Runs a pool owned by Gatedhouse, with {@link PooledDatabase.Settings}
     * defaults. Recommended for development and staging; in production, pass
     * your application's pool with {@link #fromDataSource(DataSource)}.
     *
     * <p>Requires {@code com.zaxxer:HikariCP} on the classpath. Close the
     * returned pool when done with it; closing a {@link Gatedhouse} does not.
     *
     * @throws IllegalStateException if HikariCP is not on the classpath
     */
    static PooledDatabase fromUrl(String jdbcUrl, String user, String password) {
        return fromUrl(jdbcUrl, user, password, PooledDatabase.Settings.defaults());
    }

    /** As {@link #fromUrl(String, String, String)}, with explicit pool settings. */
    static PooledDatabase fromUrl(String jdbcUrl, String user, String password,
                                  PooledDatabase.Settings settings) {
        return PooledDatabase.open(jdbcUrl, user, password, settings);
    }
}
