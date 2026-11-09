// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * The only way library code touches the database. Every operation borrows
 * exactly one connection through here, so the connection contract holds in
 * one place instead of at every call site:
 *
 * <ul>
 *   <li><b>Borrow and return.</b> The connection is borrowed from the host's
 *       {@link Database} and closed (returned to the pool) on every path.</li>
 *   <li><b>We own our commits.</b> Work commits or rolls back here, whatever
 *       autocommit setting the pool hands out, so a write is never lost
 *       because a pool defaults to {@code autoCommit=false}.</li>
 *   <li><b>Returned clean.</b> The connection's autocommit setting is
 *       restored and no transaction is left open.</li>
 *   <li><b>Never someone else's transaction.</b> A connection that is
 *       already inside a transaction (for example from a transaction-aware
 *       {@code DataSource} inside {@code @Transactional}) is refused, so we
 *       never commit or roll back the host's work.</li>
 *   <li><b>Typed failures.</b> A failed borrow is {@link
 *       GatedhouseDatabaseException.Kind#UNAVAILABLE}.</li>
 * </ul>
 *
 * Library code never holds two connections at once, so a pool of size 1
 * cannot deadlock.
 */
final class Sql {

    @FunctionalInterface
    interface Work<T> {
        T run(Connection conn) throws SQLException;
    }

    private Sql() {}

    /**
     * Runs read-only work. On an autocommit connection (the JDBC default)
     * this adds no round trips; on a non-autocommit one, the implicit
     * transaction the reads opened is ended before the connection goes back.
     */
    static <T> T read(Database database, String op, Work<T> work) {
        return run(database, op, work, false);
    }

    /**
     * Runs work in one explicit READ COMMITTED transaction that commits only
     * if the work completes. Locking in library code (row locks, advisory
     * locks) is reasoned about under READ COMMITTED, so the level is set
     * explicitly rather than inherited from the pool's default.
     */
    static <T> T write(Database database, String op, Work<T> work) {
        return run(database, op, work, true);
    }

    private static <T> T run(Database database, String op, Work<T> work, boolean write) {
        Connection conn = borrow(database, op);
        try (conn) {
            boolean autoCommit = conn.getAutoCommit();
            if (!autoCommit) {
                requireNoOpenTransaction(conn, op);
            }
            if (write) {
                return inTransaction(conn, autoCommit, work);
            }
            if (autoCommit) {
                return work.run(conn);
            }
            return inTransaction(conn, false, work);
        } catch (SQLException e) {
            throw GatedhouseDatabaseException.classify(op + " failed", e);
        }
    }

    /** Borrows a connection; a failure here means no connection was available. */
    static Connection borrow(Database database, String op) {
        Connection conn;
        try {
            conn = database.getConnection();
        } catch (SQLException e) {
            throw new GatedhouseDatabaseException(
                GatedhouseDatabaseException.Kind.UNAVAILABLE,
                op + " failed: could not obtain a database connection", e);
        }
        if (conn == null) {
            throw new IllegalStateException(
                "Database.getConnection() returned null (in " + op + ")");
        }
        return conn;
    }

    private static <T> T inTransaction(Connection conn, boolean restoreAutoCommit, Work<T> work)
            throws SQLException {
        if (restoreAutoCommit) {
            conn.setAutoCommit(false);
        }
        Throwable primary = null;
        try {
            try (var st = conn.createStatement()) {
                st.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED");
            }
            T result = work.run(conn);
            conn.commit();
            return result;
        } catch (SQLException | RuntimeException | Error e) {
            primary = e;
            try {
                conn.rollback();
            } catch (SQLException rollbackFailure) {
                e.addSuppressed(rollbackFailure);
            }
            throw e;
        } finally {
            if (restoreAutoCommit) {
                try {
                    conn.setAutoCommit(true);
                } catch (SQLException restoreFailure) {
                    if (primary != null) {
                        primary.addSuppressed(restoreFailure);
                    } else {
                        throw restoreFailure;
                    }
                }
            }
        }
    }

    // ---- statement helpers ------------------------------------------------

    /** Executes an INSERT/UPDATE/DELETE; null parameters bind as SQL NULL. */
    static Integer update(Connection conn, String sql, Object... params) throws SQLException {
        try (PreparedStatement ps = prepare(conn, sql, params)) {
            return ps.executeUpdate();
        }
    }

    static boolean exists(Connection conn, String sql, Object... params) throws SQLException {
        try (PreparedStatement ps = prepare(conn, sql, params);
             ResultSet rs = ps.executeQuery()) {
            return rs.next();
        }
    }

    /** The first column of every row, as strings. */
    static List<String> strings(Connection conn, String sql, Object... params)
            throws SQLException {
        try (PreparedStatement ps = prepare(conn, sql, params);
             ResultSet rs = ps.executeQuery()) {
            List<String> out = new ArrayList<>();
            while (rs.next()) {
                out.add(rs.getString(1));
            }
            return out;
        }
    }

    static PreparedStatement prepare(Connection conn, String sql, Object... params)
            throws SQLException {
        PreparedStatement ps = conn.prepareStatement(sql);
        try {
            for (int i = 0; i < params.length; i++) {
                Object p = params[i];
                if (p == null) {
                    ps.setNull(i + 1, java.sql.Types.VARCHAR);
                } else if (p instanceof String s) {
                    ps.setString(i + 1, s);
                } else {
                    ps.setObject(i + 1, p);
                }
            }
            return ps;
        } catch (SQLException | RuntimeException e) {
            ps.close();
            throw e;
        }
    }

    // ---- "is this connection already in a transaction?" -----------------

    /**
     * Refuses a connection the host is using for a transaction of its own.
     * JDBC has no standard way to ask, so this asks the PostgreSQL driver
     * (through {@link Connection#unwrap}, which sees through pool proxies
     * such as HikariCP's). The driver is reached reflectively so library
     * code keeps compiling against {@code java.sql} only. With another
     * driver the check is skipped.
     */
    static void requireNoOpenTransaction(Connection conn, String op) throws SQLException {
        String state = transactionState(conn);
        if (state != null && !state.equals("IDLE")) {
            throw new IllegalStateException(
                op + ": the connection from Database.getConnection() is already inside a "
                + "transaction (" + state + "). Gatedhouse commits its own work, so it "
                + "will not run on a connection bound to the caller's transaction. Pass a "
                + "plain pooled DataSource, not a transaction-aware one.");
        }
    }

    private static final Class<?> PG_BASE_CONNECTION;
    private static final Method GET_TRANSACTION_STATE;

    static {
        Class<?> base = null;
        Method getState = null;
        try {
            base = Class.forName("org.postgresql.core.BaseConnection");
            getState = base.getMethod("getTransactionState");
        } catch (ReflectiveOperationException | LinkageError absent) {
            base = null;
            getState = null;
        }
        PG_BASE_CONNECTION = base;
        GET_TRANSACTION_STATE = getState;
    }

    /** IDLE, OPEN or FAILED; null when the driver can't say. */
    static String transactionState(Connection conn) throws SQLException {
        if (PG_BASE_CONNECTION == null || !conn.isWrapperFor(PG_BASE_CONNECTION)) {
            return null;
        }
        try {
            Object state = GET_TRANSACTION_STATE.invoke(conn.unwrap(PG_BASE_CONNECTION));
            return state == null ? null : state.toString();
        } catch (ReflectiveOperationException e) {
            return null;
        }
    }
}
