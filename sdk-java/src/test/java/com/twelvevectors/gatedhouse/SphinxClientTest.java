// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Issue #4: every outbound HTTP call is bounded, and Sphinx failures are
 * typed. Each test stands up a local server that misbehaves in one specific
 * way.
 */
class SphinxClientTest {

    private static final Duration SHORT = Duration.ofMillis(500);

    private final List<AutoCloseable> servers = new ArrayList<>();

    @AfterEach
    void stopServers() throws Exception {
        for (AutoCloseable s : servers) {
            s.close();
        }
    }

    // ---- misbehaving servers ----------------------------------------------

    /** Accepts connections, then never sends a byte. */
    private String blackHole() throws IOException {
        ServerSocket server = new ServerSocket(0);
        List<Socket> held = new ArrayList<>();
        Thread acceptor = new Thread(() -> {
            try {
                while (true) {
                    held.add(server.accept());   // keep it open, say nothing
                }
            } catch (IOException closed) {
                // server closed
            }
        });
        acceptor.setDaemon(true);
        acceptor.start();
        servers.add(() -> {
            server.close();
            for (Socket s : held) {
                s.close();
            }
        });
        return "http://127.0.0.1:" + server.getLocalPort();
    }

    /** Sends a complete status line and headers promising a body, then stalls. */
    private String stallsMidBody() throws IOException {
        ServerSocket server = new ServerSocket(0);
        List<Socket> held = new ArrayList<>();
        Thread acceptor = new Thread(() -> {
            try {
                while (true) {
                    Socket s = server.accept();
                    held.add(s);
                    s.getInputStream().read(new byte[8192]);   // consume the request
                    OutputStream out = s.getOutputStream();
                    out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        + "Content-Length: 100\r\n\r\n{\"access").getBytes(StandardCharsets.UTF_8));
                    out.flush();                                   // ... and never finishes
                }
            } catch (IOException closed) {
                // server closed
            }
        });
        acceptor.setDaemon(true);
        acceptor.start();
        servers.add(() -> {
            server.close();
            for (Socket s : held) {
                s.close();
            }
        });
        return "http://127.0.0.1:" + server.getLocalPort();
    }

    /** A port with nothing listening on it. */
    private static String refusing() throws IOException {
        try (ServerSocket s = new ServerSocket(0)) {
            return "http://127.0.0.1:" + s.getLocalPort();
        }
    }

    /** Answers every request with the given status and body. */
    private String answering(int status, String body) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
        servers.add(() -> server.stop(0));
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private static SphinxClient client(String baseUrl) {
        return new SphinxClient(baseUrl, "client", "secret", SHORT);
    }

    private static long millisSince(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000;
    }

    // ---- timeouts ----------------------------------------------------------

    @Test
    void defaultTimeoutIsTenSeconds() {
        assertEquals(Duration.ofSeconds(10), SphinxClient.DEFAULT_TIMEOUT);
        assertEquals(Duration.ofSeconds(10), new SphinxClient("http://x", "c", "s").timeout());
    }

    @Test
    void timeoutMustBePositive() {
        assertThrows(IllegalArgumentException.class, () -> new SphinxClient("http://x", "c", "s", Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new SphinxClient("http://x", "c", "s", Duration.ofSeconds(-1)));
        assertThrows(IllegalArgumentException.class, () -> new SphinxClient("http://x", "c", "s", null));
    }

    @Test
    void unresponsiveTokenEndpointTimesOutInsteadOfHanging() throws IOException {
        SphinxClient c = client(blackHole());
        long start = System.nanoTime();
        SphinxException e = assertThrows(SphinxException.class, () -> c.exchangeCode("code", "http://cb"));
        long elapsed = millisSince(start);
        assertEquals(SphinxException.Kind.TIMEOUT, e.kind());
        assertTrue(e.statusCode().isEmpty());
        assertTrue(elapsed >= 400 && elapsed < 3_000, "timed out after " + elapsed + " ms");
    }

    @Test
    void unresponsiveIntrospectionEndpointTimesOut() throws IOException {
        SphinxClient c = client(blackHole());
        SphinxException e = assertThrows(SphinxException.class, () -> c.introspect("tok"));
        assertEquals(SphinxException.Kind.TIMEOUT, e.kind());
    }

    @Test
    void bodyThatStallsMidwayIsCaughtByTheBackstop() throws IOException {
        SphinxClient c = client(stallsMidBody());
        long start = System.nanoTime();
        SphinxException e = assertThrows(SphinxException.class, () -> c.refreshToken("rt"));
        long elapsed = millisSince(start);
        assertEquals(SphinxException.Kind.TIMEOUT, e.kind());
        assertTrue(elapsed < 3_000, "backstop fired after " + elapsed + " ms");
    }

    // ---- other failure kinds ------------------------------------------------

    @Test
    void unreachableEndpointIsTransport() throws IOException {
        SphinxException e = assertThrows(SphinxException.class,
            () -> client(refusing()).clientCredentials(null));
        assertEquals(SphinxException.Kind.TRANSPORT, e.kind());
    }

    @Test
    void refusedTokenRequestIsHttpStatusWithCodeAndBody() throws IOException {
        String base = answering(400, "{\"error\":\"invalid_grant\"}");
        SphinxException e = assertThrows(SphinxException.class,
            () -> client(base).exchangeCode("used-code", "http://cb"));
        assertEquals(SphinxException.Kind.HTTP_STATUS, e.kind());
        assertEquals(400, e.statusCode().orElseThrow());
        assertTrue(e.getMessage().contains("invalid_grant"), e.getMessage());
    }

    @Test
    void nonJsonTokenResponseIsInvalidResponse() throws IOException {
        SphinxException e = assertThrows(SphinxException.class,
            () -> client(answering(200, "<html>proxy error</html>")).refreshToken("rt"));
        assertEquals(SphinxException.Kind.INVALID_RESPONSE, e.kind());
    }

    @Test
    void stillARuntimeExceptionForExistingHandlers() throws IOException {
        RuntimeException e = assertThrows(RuntimeException.class,
            () -> client(refusing()).refreshToken("rt"));
        assertInstanceOf(SphinxException.class, e);
    }

    // ---- unchanged success paths -------------------------------------------

    @Test
    void successfulTokenResponseIsParsed() throws IOException {
        String base = answering(200,
            "{\"access_token\":\"at\",\"refresh_token\":\"rt\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
        SphinxClient.TokenResponse t = client(base).exchangeCode("code", "http://cb");
        assertEquals("at", t.accessToken());
        assertEquals("rt", t.refreshToken());
        assertEquals(3600, t.expiresIn());
    }

    @Test
    void introspectionStillParsesTheBodyOfANonSuccessStatus() throws IOException {
        Map<String, Object> result = client(answering(401, "{\"active\":false}")).introspect("tok");
        assertEquals(Boolean.FALSE, result.get("active"));
    }

    // ---- JWKS ---------------------------------------------------------------

    @Test
    void defaultJwksTimeoutIsFiveSeconds() {
        TokenVerifierConfig config = TokenVerifierConfig.builder()
            .jwksUri(URI.create("http://x/jwks")).issuer("i").audience("a").build();
        assertEquals(Duration.ofSeconds(5), config.jwksTimeout());
        assertEquals(Duration.ofSeconds(5), TokenVerifierConfig.DEFAULT_JWKS_TIMEOUT);
    }

    @Test
    void unresponsiveJwksEndpointFailsFastAsJwksUnavailable() throws IOException {
        TokenVerifierConfig config = TokenVerifierConfig.builder()
            .jwksUri(URI.create(blackHole() + "/jwks.json"))
            .issuer("https://issuer").audience("app")
            .jwksTimeout(SHORT)
            .build();
        Gatedhouse gh = GatedhouseFactory.createJustTokenVerifier(config);
        long start = System.nanoTime();
        TokenVerificationException e = assertThrows(TokenVerificationException.class,
            () -> gh.verifyToken(unverifiableTokenWithKid()));
        long elapsed = millisSince(start);
        assertEquals(TokenVerificationException.Reason.JWKS_UNAVAILABLE, e.reason());
        assertTrue(elapsed < 3_000, "JWKS fetch gave up after " + elapsed + " ms");
    }

    /** Well-formed RS256 JWT with a kid, so verification must fetch the JWKS. */
    private static String unverifiableTokenWithKid() {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String header = b64.encodeToString(
            "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"k1\"}".getBytes(StandardCharsets.UTF_8));
        String payload = b64.encodeToString(
            "{\"sub\":\"x\",\"iss\":\"https://issuer\",\"aud\":\"app\",\"exp\":4102444800}"
                .getBytes(StandardCharsets.UTF_8));
        String signature = b64.encodeToString(new byte[256]);
        return header + "." + payload + "." + signature;
    }
}
