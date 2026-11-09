// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The session filter: redirects for bad tokens, 503 (session kept) for outages. */
class GatedhouseWebFilterTest {

    private static final class Capture {
        int status;
        String redirect;
        final Map<String, String> headers = new HashMap<>();
        final StringWriter body = new StringWriter();
    }

    private static HttpSession session(Map<String, Object> attrs) {
        return (HttpSession) Proxy.newProxyInstance(HttpSession.class.getClassLoader(),
            new Class<?>[] {HttpSession.class}, (p, m, a) -> switch (m.getName()) {
                case "getAttribute" -> attrs.get(a[0]);
                case "removeAttribute" -> attrs.remove(a[0]);
                default -> null;
            });
    }

    private static HttpServletRequest request(HttpSession session) {
        return (HttpServletRequest) Proxy.newProxyInstance(HttpServletRequest.class.getClassLoader(),
            new Class<?>[] {HttpServletRequest.class}, (p, m, a) -> switch (m.getName()) {
                case "getSession" -> session;
                case "getContextPath" -> "/app";
                default -> null;
            });
    }

    private static HttpServletResponse response(Capture c) {
        PrintWriter writer = new PrintWriter(c.body);
        return (HttpServletResponse) Proxy.newProxyInstance(HttpServletResponse.class.getClassLoader(),
            new Class<?>[] {HttpServletResponse.class}, (p, m, a) -> switch (m.getName()) {
                case "setStatus" -> {
                    c.status = (int) a[0];
                    yield null;
                }
                case "setHeader" -> c.headers.put((String) a[0], (String) a[1]);
                case "sendRedirect" -> {
                    c.redirect = (String) a[0];
                    yield null;
                }
                case "getWriter" -> writer;
                case "isCommitted" -> false;
                default -> null;
            });
    }

    private static Gatedhouse verifying(TokenVerificationException.Reason failure) {
        return (Gatedhouse) Proxy.newProxyInstance(Gatedhouse.class.getClassLoader(),
            new Class<?>[] {Gatedhouse.class}, (p, m, a) -> {
                if (m.getName().equals("verifyToken")) {
                    if (failure != null) {
                        throw new TokenVerificationException(failure, "x");
                    }
                    return new AuthenticatedSubject("u", "i", "a", null, null, "Bearer", Map.of());
                }
                return null;
            });
    }

    private static final FilterChain UNREACHABLE = (rq, rs) -> {
        throw new AssertionError("must not reach the application");
    };

    @Test
    void outageIs503AndKeepsTheSession() throws Exception {
        Map<String, Object> attrs = new HashMap<>(Map.of("access_token", "tok"));
        Capture c = new Capture();
        new GatedhouseWebFilter(verifying(TokenVerificationException.Reason.JWKS_UNAVAILABLE))
            .doFilter(request(session(attrs)), response(c), UNREACHABLE);
        assertEquals(503, c.status);
        assertEquals("30", c.headers.get("Retry-After"));
        assertNull(c.redirect, "no redirect to a login page that cannot work either");
        assertEquals("tok", attrs.get("access_token"), "session kept through an IdP outage");
    }

    @Test
    void badTokenIsClearedAndRedirected() throws Exception {
        Map<String, Object> attrs = new HashMap<>(Map.of("access_token", "tok"));
        Capture c = new Capture();
        new GatedhouseWebFilter(verifying(TokenVerificationException.Reason.EXPIRED))
            .doFilter(request(session(attrs)), response(c), UNREACHABLE);
        assertEquals("/app/auth/login", c.redirect);
        assertTrue(attrs.isEmpty(), "invalid token removed from the session");
    }

    @Test
    void applicationFailuresPropagateInsteadOfBecomingRedirects() {
        RuntimeException appBug = new RuntimeException("boom");
        Map<String, Object> attrs = new HashMap<>(Map.of("access_token", "tok"));
        Capture c = new Capture();
        RuntimeException thrown = assertThrows(RuntimeException.class, () ->
            new GatedhouseWebFilter(verifying(null)).doFilter(request(session(attrs)), response(c),
                (rq, rs) -> { throw appBug; }));
        assertSame(appBug, thrown);
        assertNull(c.redirect);
        assertEquals("tok", attrs.get("access_token"));
    }
}
