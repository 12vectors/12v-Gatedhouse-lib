// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.util.Optional;
import java.util.OptionalInt;

/**
 * A {@link SphinxClient} call failed. {@link #kind()} says how, so a host can
 * tell "the IdP is unavailable, try again" ({@link Kind#TIMEOUT},
 * {@link Kind#TRANSPORT}) apart from "the request was refused"
 * ({@link Kind#HTTP_STATUS}, e.g. an invalid or already-used authorization
 * code).
 *
 * <p>The library never retries. In particular, do not blindly retry
 * {@link SphinxClient#exchangeCode} after a timeout: authorization codes are
 * single-use, and the IdP may already have consumed the code.
 *
 * <p>Extends {@link RuntimeException}, which these calls threw before, so
 * existing handlers keep working.
 */
public final class SphinxException extends RuntimeException {

    /** How a Sphinx call failed. */
    public enum Kind {
        /** A network wait (connecting, or waiting for data) exceeded the client's timeout. */
        TIMEOUT,
        /** The endpoint could not be reached, or the connection failed, other than by timing out. */
        TRANSPORT,
        /** The endpoint answered with an unsuccessful HTTP status; see {@link #statusCode()}. */
        HTTP_STATUS,
        /** The endpoint answered, but the body was not the expected JSON object. */
        INVALID_RESPONSE
    }

    private final Kind kind;
    private final Integer statusCode;
    private final String errorCode;

    /**
     * @param statusCode the HTTP status, for {@link Kind#HTTP_STATUS}; otherwise {@code null}
     */
    public SphinxException(Kind kind, Integer statusCode, String message, Throwable cause) {
        this(kind, statusCode, null, message, cause);
    }

    /**
     * @param statusCode the HTTP status, for {@link Kind#HTTP_STATUS}; otherwise {@code null}
     * @param errorCode  the {@code error} field of Sphinx's JSON error body, or {@code null}
     */
    public SphinxException(Kind kind, Integer statusCode, String errorCode, String message,
                           Throwable cause) {
        super(message, cause);
        this.kind = java.util.Objects.requireNonNull(kind, "kind");
        this.statusCode = statusCode;
        this.errorCode = errorCode;
    }

    public Kind kind() {
        return kind;
    }

    /** The HTTP status for {@link Kind#HTTP_STATUS}; empty for every other kind. */
    public OptionalInt statusCode() {
        return statusCode == null ? OptionalInt.empty() : OptionalInt.of(statusCode);
    }

    /**
     * Sphinx's machine-readable error code (the {@code error} field of its JSON
     * error body, e.g. {@code "conflict"}, {@code "unauthorized_client"}) for
     * {@link Kind#HTTP_STATUS}; empty when the body carried none.
     */
    public Optional<String> errorCode() {
        return Optional.ofNullable(errorCode);
    }
}
