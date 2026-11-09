// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;

/**
 * Response conventions shared by {@link GatedhouseApiFilter} and
 * {@link GatedhouseWebFilter}, identical across the three SDKs:
 *
 * <ul>
 *   <li>401 bodies name a stable {@code reason} code, never the verifier's
 *       internal message (which can include the IdP's URL or network
 *       errors).</li>
 *   <li>An identity-provider outage ({@code JWKS_UNAVAILABLE}) is our failure,
 *       not the caller's: 503 with {@code Retry-After}, no challenge.</li>
 * </ul>
 */
final class FilterSupport {

    /** Seconds a client should wait before retrying after a 503. */
    static final int RETRY_AFTER_SECONDS = 30;

    private FilterSupport() {}

    static void applySecurityHeaders(HttpServletResponse resp) {
        resp.setHeader("X-Content-Type-Options", "nosniff");
        resp.setHeader("X-Frame-Options", "DENY");
        resp.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    }

    /**
     * The token from an {@code Authorization} header, or null. The scheme is
     * matched case-insensitively (RFC 7235 section 2.1).
     */
    static String bearerToken(String authorization) {
        if (authorization == null || authorization.length() < 7
                || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        String token = authorization.substring(7).trim();
        return token.isEmpty() ? null : token;
    }

    /** The reason as sent to clients: the enum name in lower case. */
    static String reasonCode(TokenVerificationException.Reason reason) {
        return reason.name().toLowerCase(Locale.ROOT);
    }

    static boolean isOutage(TokenVerificationException e) {
        return e.reason() == TokenVerificationException.Reason.JWKS_UNAVAILABLE;
    }

    static void sendUnauthorized(HttpServletResponse resp, String reason, String detail)
            throws IOException {
        resp.setHeader("WWW-Authenticate", GatedhouseApiFilter.WWW_AUTHENTICATE_CHALLENGE);
        sendJson(resp, 401, "unauthorized", reason, detail);
    }

    static void sendForbidden(HttpServletResponse resp, String detail) throws IOException {
        sendJson(resp, 403, "forbidden", null, detail);
    }

    static void sendUnavailable(HttpServletResponse resp) throws IOException {
        resp.setHeader("Retry-After", Integer.toString(RETRY_AFTER_SECONDS));
        sendJson(resp, 503, "unavailable", "jwks_unavailable",
            "Token verification is temporarily unavailable");
    }

    private static void sendJson(HttpServletResponse resp, int status, String error,
                                 String reason, String detail) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        StringBuilder body = new StringBuilder(96).append("{\"error\":");
        appendJsonString(body, error);
        if (reason != null) {
            body.append(",\"reason\":");
            appendJsonString(body, reason);
        }
        body.append(",\"detail\":");
        appendJsonString(body, detail);
        resp.getWriter().write(body.append('}').toString());
    }

    /** Appends {@code value} as a JSON string literal (RFC 8259 escaping). */
    static void appendJsonString(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20 || c == ' ' || c == ' ') {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}
