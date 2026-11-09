// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the API filter's 401 contract: RFC 6750 challenge header,
 * unchanged JSON body, and unchanged security headers, for both 401
 * causes (missing credentials, failed verification).
 */
class GatedhouseApiFilterTest {

    /** Response capture backing the {@link HttpServletResponse} proxy. */
    private static final class ResponseCapture {
        int status;
        String contentType;
        final Map<String, String> headers = new LinkedHashMap<>();
        final StringWriter body = new StringWriter();
    }

    private static HttpServletRequest fakeRequest(String authorization) {
        Map<String, Object> attributes = new LinkedHashMap<>();
        return (HttpServletRequest) Proxy.newProxyInstance(
                GatedhouseApiFilterTest.class.getClassLoader(),
                new Class<?>[] {HttpServletRequest.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getHeader" -> "Authorization".equals(args[0]) ? authorization : null;
                    case "setAttribute" -> attributes.put((String) args[0], args[1]);
                    case "getAttribute" -> attributes.get(args[0]);
                    default -> null;
                });
    }

    private static HttpServletResponse fakeResponse(ResponseCapture capture) {
        PrintWriter writer = new PrintWriter(capture.body);
        return (HttpServletResponse) Proxy.newProxyInstance(
                GatedhouseApiFilterTest.class.getClassLoader(),
                new Class<?>[] {HttpServletResponse.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "setStatus" -> {
                        capture.status = (int) args[0];
                        yield null;
                    }
                    case "setHeader" -> capture.headers.put((String) args[0], (String) args[1]);
                    case "setContentType" -> {
                        capture.contentType = (String) args[0];
                        yield null;
                    }
                    case "getWriter" -> writer;
                    case "isCommitted" -> false;
                    default -> null;
                });
    }

    private static Gatedhouse rejectingGatedhouse() {
        return verifyingWith(TokenVerificationException.Reason.INVALID_SIGNATURE,
            "bad signature from \"kid\": <script>");
    }

    private static Gatedhouse verifyingWith(TokenVerificationException.Reason reason, String message) {
        return (Gatedhouse) Proxy.newProxyInstance(
                GatedhouseApiFilterTest.class.getClassLoader(),
                new Class<?>[] {Gatedhouse.class},
                (proxy, method, args) -> {
                    if ("verifyToken".equals(method.getName())) {
                        throw new TokenVerificationException(reason, message);
                    }
                    return null;
                });
    }

    private static Gatedhouse accepting() {
        return (Gatedhouse) Proxy.newProxyInstance(
                GatedhouseApiFilterTest.class.getClassLoader(),
                new Class<?>[] {Gatedhouse.class},
                (proxy, method, args) -> {
                    if ("verifyToken".equals(method.getName())) {
                        return new AuthenticatedSubject(
                                "person-1", "iss", "aud", null, null, "Bearer", Map.of());
                    }
                    return null;
                });
    }

    private static FilterChain unreachableChain() {
        return (request, response) -> {
            throw new AssertionError("filter chain must not continue on a 401");
        };
    }

    private static void assertSecurityHeaders(ResponseCapture resp) {
        assertEquals("nosniff", resp.headers.get("X-Content-Type-Options"));
        assertEquals("DENY", resp.headers.get("X-Frame-Options"));
        assertEquals("strict-origin-when-cross-origin", resp.headers.get("Referrer-Policy"));
    }

    private static void assertUnauthorizedContract(ResponseCapture resp) {
        assertEquals(401, resp.status);
        assertEquals("Bearer", resp.headers.get("WWW-Authenticate"));
        assertEquals(GatedhouseApiFilter.WWW_AUTHENTICATE_CHALLENGE, resp.headers.get("WWW-Authenticate"));
        assertSecurityHeaders(resp);
        assertEquals("application/json", resp.contentType);
    }

    @Test
    void missingTokenGets401WithChallenge() throws Exception {
        ResponseCapture resp = new ResponseCapture();
        new GatedhouseApiFilter(rejectingGatedhouse())
                .doFilter(fakeRequest(null), fakeResponse(resp), unreachableChain());

        assertUnauthorizedContract(resp);
        assertEquals("{\"error\":\"unauthorized\",\"reason\":\"missing_token\","
                + "\"detail\":\"Missing or invalid Bearer token\"}", resp.body.toString());
    }

    @Test
    void invalidTokenGets401WithAStableReasonAndNoInternalDetail() throws Exception {
        ResponseCapture resp = new ResponseCapture();
        new GatedhouseApiFilter(rejectingGatedhouse())
                .doFilter(fakeRequest("Bearer not-a-real-token"), fakeResponse(resp), unreachableChain());

        assertUnauthorizedContract(resp);
        assertEquals("{\"error\":\"unauthorized\",\"reason\":\"invalid_signature\","
                + "\"detail\":\"Token verification failed\"}", resp.body.toString());
    }

    @Test
    void identityProviderOutageIs503NotA401() throws Exception {
        ResponseCapture resp = new ResponseCapture();
        new GatedhouseApiFilter(verifyingWith(TokenVerificationException.Reason.JWKS_UNAVAILABLE,
                "Couldn't retrieve JWKS from https://idp.internal:8443/jwks: connect timed out"))
                .doFilter(fakeRequest("Bearer t"), fakeResponse(resp), unreachableChain());

        assertEquals(503, resp.status);
        assertEquals("30", resp.headers.get("Retry-After"));
        assertNull(resp.headers.get("WWW-Authenticate"), "no challenge: the token is not at fault");
        assertSecurityHeaders(resp);
        assertEquals("{\"error\":\"unavailable\",\"reason\":\"jwks_unavailable\","
                + "\"detail\":\"Token verification is temporarily unavailable\"}", resp.body.toString());
    }

    @Test
    void bearerSchemeIsCaseInsensitive() throws Exception {
        for (String header : new String[] {"bearer good", "BEARER good", "Bearer   good  "}) {
            boolean[] chained = {false};
            new GatedhouseApiFilter(accepting())
                .doFilter(fakeRequest(header), fakeResponse(new ResponseCapture()),
                    (rq, rs) -> chained[0] = true);
            assertTrue(chained[0], header);
        }
        ResponseCapture resp = new ResponseCapture();
        new GatedhouseApiFilter(accepting())
            .doFilter(fakeRequest("Bearer    "), fakeResponse(resp), unreachableChain());
        assertEquals(401, resp.status, "empty token");
    }

    @Test
    void validTokenPassesThroughWithoutChallenge() throws Exception {
        ResponseCapture resp = new ResponseCapture();
        boolean[] chained = {false};
        FilterChain chain = (request, response) -> chained[0] = true;

        new GatedhouseApiFilter(accepting())
                .doFilter(fakeRequest("Bearer good-token"), fakeResponse(resp), chain);

        assertTrue(chained[0], "authenticated request must continue down the chain");
        assertNull(resp.headers.get("WWW-Authenticate"), "no challenge on success");
        assertEquals("", resp.body.toString(), "no error body on success");
    }

    @Test
    void applicationFailuresPropagateInsteadOfBecoming401s() {
        IllegalStateException appBug = new IllegalStateException("database down");
        IllegalStateException thrown = assertThrows(IllegalStateException.class, () ->
            new GatedhouseApiFilter(accepting()).doFilter(fakeRequest("Bearer good"),
                fakeResponse(new ResponseCapture()), (rq, rs) -> { throw appBug; }));
        assertSame(appBug, thrown);
    }

    @Test
    void helperExceptionsFromTheApplicationKeepTheirStatus() throws Exception {
        ResponseCapture forbidden = new ResponseCapture();
        new GatedhouseApiFilter(accepting()).doFilter(fakeRequest("Bearer good"),
            fakeResponse(forbidden), (rq, rs) -> {
                throw new GatedhouseApiFilter.ForbiddenException("Admin access required");
            });
        assertEquals(403, forbidden.status);
        assertNull(forbidden.headers.get("WWW-Authenticate"));
        assertEquals("{\"error\":\"forbidden\",\"detail\":\"Admin access required\"}",
            forbidden.body.toString());

        ResponseCapture unauthorized = new ResponseCapture();
        new GatedhouseApiFilter(accepting()).doFilter(fakeRequest("Bearer good"),
            fakeResponse(unauthorized), (rq, rs) -> {
                throw new GatedhouseApiFilter.UnauthorizedException("Authentication required");
            });
        assertUnauthorizedContract(unauthorized);
    }

    @Test
    void jsonBodiesAreEscaped() {
        StringBuilder out = new StringBuilder();
        FilterSupport.appendJsonString(out, "a\"b\\c\n\u0001\u2028");
        assertEquals("\"a\\\"b\\\\c\\n\\u0001\\u2028\"", out.toString());
    }
}
