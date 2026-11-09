// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.sql.SQLException;
import java.util.Objects;

/**
 * A Gatedhouse database operation failed. {@link #kind()} says how, so a host
 * can tell "the database is unavailable, try again later" ({@link
 * Kind#UNAVAILABLE}, typically answered with HTTP 503) apart from a statement
 * the database refused ({@link Kind#QUERY}).
 *
 * <p>An authorization check that ends in this exception has not granted
 * anything: callers must treat it as a failure, never as "allowed".
 */
public final class GatedhouseDatabaseException extends RuntimeException {

    /** How a database operation failed. */
    public enum Kind {
        /**
         * No usable connection: the pool timed out handing one out, the
         * database could not be reached, or the connection was lost or shut
         * down mid-operation.
         */
        UNAVAILABLE,
        /** The database was reached, but refused or failed the statement. */
        QUERY
    }

    private final Kind kind;

    /** A {@link Kind#QUERY} failure. */
    public GatedhouseDatabaseException(String message, Throwable cause) {
        this(Kind.QUERY, message, cause);
    }

    public GatedhouseDatabaseException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = Objects.requireNonNull(kind, "kind");
    }

    public Kind kind() {
        return kind;
    }

    /**
     * Classifies a failure from an operation that did obtain a connection.
     * Transient conditions are {@link Kind#UNAVAILABLE}: SQLSTATE class 08
     * (connection exception), class 53 (insufficient resources), 57014
     * (statement timeout or cancellation) and 57P01-57P03 (server shut down
     * or not accepting connections). Anything else is the statement failing.
     */
    static GatedhouseDatabaseException classify(String message, SQLException cause) {
        return new GatedhouseDatabaseException(
            isTransient(cause.getSQLState()) ? Kind.UNAVAILABLE : Kind.QUERY, message, cause);
    }

    static boolean isTransient(String state) {
        return state != null
            && (state.startsWith("08") || state.startsWith("53") || state.equals("57014")
                || state.equals("57P01") || state.equals("57P02") || state.equals("57P03"));
    }
}
