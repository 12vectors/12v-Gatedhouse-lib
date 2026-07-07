package com.twelvevectors.gatedhouse;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the exact path Sphinx serves introspection at
 * ({@code /api/sphinx/v1/oauth/token/introspect}) — a loopback mock captures the
 * requested path so this can't silently drift back to a wrong endpoint.
 */
class SphinxClientIntrospectTest {

    @Test
    void tokenResponseToStringRedactsSecrets() {
        var tr = new SphinxClient.TokenResponse(
            "SECRET_ACCESS", "SECRET_REFRESH", "Bearer", 3600, "openid", null);
        String s = tr.toString();
        assertFalse(s.contains("SECRET_ACCESS"), "access token must not appear in toString()");
        assertFalse(s.contains("SECRET_REFRESH"), "refresh token must not appear in toString()");
        assertTrue(s.contains("<redacted>"));
        assertTrue(s.contains("Bearer") && s.contains("3600"), "non-secret fields remain visible");
    }

    @Test
    void introspectHitsTheTokenIntrospectEndpoint() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicReference<String> path = new AtomicReference<>();
        server.createContext("/", exchange -> {
            path.set(exchange.getRequestURI().getPath());
            byte[] body = "{\"active\":true}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (var os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            var client = new SphinxClient("http://127.0.0.1:" + port, "c", "s");
            Map<String, Object> result = client.introspect("some-token");
            assertEquals(Boolean.TRUE, result.get("active"));
            assertEquals("/api/sphinx/v1/oauth/token/introspect", path.get());
        } finally {
            server.stop(0);
        }
    }
}
