// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Objects;
import javax.sql.DataSource;

/**
 * A connection pool owned by Gatedhouse, created by {@link
 * Database#fromUrl(String, String, String)}. Backed by HikariCP, which must be
 * on the classpath (it is an optional dependency of this library).
 *
 * <p>Recommended for development and staging. In production, prefer {@link
 * Database#fromDataSource(DataSource)} with your application's own pool, so
 * one pool is sized and monitored against the database's connection limit.
 *
 * <p>Whoever creates it closes it. {@link Gatedhouse#close()} does not, because
 * one {@code Database} is commonly shared by {@link
 * GatedhouseFactory#migrate(GatedhouseConfig)} and several {@link Gatedhouse}
 * instances.
 */
public final class PooledDatabase implements Database, AutoCloseable {

    /** Pool settings. Every value has a default; see {@link #defaults()}. */
    public static final class Settings {

        /** Default {@link #maximumPoolSize()}: 10 connections. */
        public static final int DEFAULT_MAXIMUM_POOL_SIZE = 10;
        /** Default {@link #connectionTimeout()}: 10 seconds. */
        public static final Duration DEFAULT_CONNECTION_TIMEOUT = Duration.ofSeconds(10);
        /** Default {@link #maxLifetime()}: 30 minutes. */
        public static final Duration DEFAULT_MAX_LIFETIME = Duration.ofMinutes(30);
        /** Default {@link #statementTimeout()}: 30 seconds. */
        public static final Duration DEFAULT_STATEMENT_TIMEOUT = Duration.ofSeconds(30);

        private final int maximumPoolSize;
        private final Duration connectionTimeout;
        private final Duration maxLifetime;
        private final Duration statementTimeout;

        private Settings(Builder b) {
            this.maximumPoolSize = b.maximumPoolSize;
            this.connectionTimeout = b.connectionTimeout;
            this.maxLifetime = b.maxLifetime;
            this.statementTimeout = b.statementTimeout;
        }

        public static Settings defaults() {
            return builder().build();
        }

        public static Builder builder() {
            return new Builder();
        }

        /** Most connections the pool opens. */
        public int maximumPoolSize() {
            return maximumPoolSize;
        }

        /**
         * Longest an operation waits for a free connection before failing
         * with {@link GatedhouseDatabaseException.Kind#UNAVAILABLE}.
         */
        public Duration connectionTimeout() {
            return connectionTimeout;
        }

        /** Connections older than this are retired and replaced. */
        public Duration maxLifetime() {
            return maxLifetime;
        }

        /**
         * Longest any single statement may run before PostgreSQL cancels it
         * (then {@link GatedhouseDatabaseException.Kind#UNAVAILABLE}), so a
         * slow or blocked query cannot hold a connection indefinitely. Zero
         * means no limit. Set on the pool's own sessions only.
         */
        public Duration statementTimeout() {
            return statementTimeout;
        }

        public static final class Builder {
            private int maximumPoolSize = DEFAULT_MAXIMUM_POOL_SIZE;
            private Duration connectionTimeout = DEFAULT_CONNECTION_TIMEOUT;
            private Duration maxLifetime = DEFAULT_MAX_LIFETIME;
            private Duration statementTimeout = DEFAULT_STATEMENT_TIMEOUT;

            private Builder() {}

            public Builder maximumPoolSize(int size) {
                if (size < 1) {
                    throw new IllegalArgumentException("maximumPoolSize must be at least 1");
                }
                this.maximumPoolSize = size;
                return this;
            }

            /** At least 250 ms (HikariCP's minimum). */
            public Builder connectionTimeout(Duration timeout) {
                Objects.requireNonNull(timeout, "connectionTimeout");
                if (timeout.toMillis() < 250) {
                    throw new IllegalArgumentException("connectionTimeout must be at least 250 ms");
                }
                this.connectionTimeout = timeout;
                return this;
            }

            /** At least 30 seconds (HikariCP's minimum). */
            public Builder maxLifetime(Duration lifetime) {
                Objects.requireNonNull(lifetime, "maxLifetime");
                if (lifetime.compareTo(Duration.ofSeconds(30)) < 0) {
                    throw new IllegalArgumentException("maxLifetime must be at least 30 seconds");
                }
                this.maxLifetime = lifetime;
                return this;
            }

            /** Zero means no limit; otherwise at least 1 millisecond. */
            public Builder statementTimeout(Duration timeout) {
                Objects.requireNonNull(timeout, "statementTimeout");
                if (timeout.isNegative()) {
                    throw new IllegalArgumentException("statementTimeout must not be negative");
                }
                this.statementTimeout = timeout;
                return this;
            }

            public Settings build() {
                return new Settings(this);
            }
        }
    }

    static final String HIKARI_CLASS = "com.zaxxer.hikari.HikariDataSource";

    private final DataSource dataSource;
    private final AutoCloseable pool;

    private PooledDatabase(DataSource dataSource, AutoCloseable pool) {
        this.dataSource = dataSource;
        this.pool = pool;
    }

    static PooledDatabase open(String jdbcUrl, String user, String password, Settings settings) {
        Objects.requireNonNull(jdbcUrl, "jdbcUrl");
        Objects.requireNonNull(settings, "settings");
        try {
            Class.forName(HIKARI_CLASS, false, PooledDatabase.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(
                "Database.fromUrl runs a connection pool and needs HikariCP, an optional "
                + "dependency of gatedhouse. Add com.zaxxer:HikariCP to your build, or pass "
                + "your application's pool with Database.fromDataSource(...).", e);
        }
        // Only now touch the class that references HikariCP.
        DataSource hikari = HikariPool.open(jdbcUrl, user, password, settings);
        return new PooledDatabase(hikari, (AutoCloseable) hikari);
    }

    @Override
    public Connection getConnection() throws SQLException {
        return dataSource.getConnection();
    }

    /** Closes every pooled connection. Idempotent. */
    @Override
    public void close() {
        try {
            pool.close();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to close the Gatedhouse connection pool", e);
        }
    }
}
