package com.twelvevectors.gatedhouse;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TLS-enforcement for the two security-sensitive endpoints (review M4/M5): HTTPS is required, with a
 * loopback carve-out so local dev/test over http still works.
 */
class SecureUrlsTest {

    @Test
    void httpsIsAccepted() {
        assertDoesNotThrow(() -> SecureUrls.requireHttpsOrLoopback("https://auth.example.com", "x"));
        assertDoesNotThrow(() -> SecureUrls.requireHttpsOrLoopback(
            URI.create("https://auth.example.com/.well-known/jwks.json"), "x"));
    }

    @Test
    void httpLoopbackIsAccepted() {
        assertDoesNotThrow(() -> SecureUrls.requireHttpsOrLoopback("http://localhost:8080/x", "x"));
        assertDoesNotThrow(() -> SecureUrls.requireHttpsOrLoopback("http://127.0.0.1/x", "x"));
    }

    @Test
    void httpNonLoopbackIsRejected() {
        assertThrows(IllegalArgumentException.class,
            () -> SecureUrls.requireHttpsOrLoopback("http://auth.example.com", "x"));
        assertThrows(IllegalArgumentException.class,
            () -> SecureUrls.requireHttpsOrLoopback("http://evil.com/.well-known/jwks.json", "x"));
    }

    @Test
    void sphinxClientConstructorRejectsPlaintextBaseUrl() {
        assertThrows(IllegalArgumentException.class,
            () -> new SphinxClient("http://sphinx.example.com", "client", "secret"));
        assertDoesNotThrow(() -> new SphinxClient("https://sphinx.example.com", "client", "secret"));
    }

    @Test
    void loginFlowConstructorRejectsPlaintextBaseUrl() {
        byte[] key = "signing-key".getBytes(StandardCharsets.UTF_8);
        SphinxClient client = new SphinxClient("https://sphinx.example.com", "client", "secret");
        assertThrows(IllegalArgumentException.class,
            () -> new LoginFlow("http://sphinx.example.com", "client", "https://app/cb", "openid",
                key, client));
        assertDoesNotThrow(() ->
            new LoginFlow("https://sphinx.example.com", "client", "https://app/cb", "openid",
                key, client));
    }

    @Test
    void tokenVerifierConfigRejectsPlaintextJwksUri() {
        assertThrows(IllegalArgumentException.class, () -> TokenVerifierConfig.builder()
            .jwksUri(URI.create("http://sphinx.example.com/jwks.json"))
            .issuer("sphinx").audience("app").build());
        assertDoesNotThrow(() -> TokenVerifierConfig.builder()
            .jwksUri(URI.create("https://sphinx.example.com/jwks.json"))
            .issuer("sphinx").audience("app").build());
    }
}
