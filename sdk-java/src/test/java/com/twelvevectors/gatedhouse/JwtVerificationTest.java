// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.
package com.twelvevectors.gatedhouse;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Verification of correctly signed tokens with unusual claims. */
class JwtVerificationTest {

    private static RSAKey key;
    private static HttpServer jwks;
    private static JwtVerification verifier;

    @BeforeAll
    static void start() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("k1").generate();
        byte[] body = new JWKSet(key.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
        jwks = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        jwks.createContext("/jwks", ex -> {
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(body);
            }
        });
        jwks.start();
        verifier = new JwtVerification(TokenVerifierConfig.builder()
            .jwksUri(URI.create("http://127.0.0.1:" + jwks.getAddress().getPort() + "/jwks"))
            .issuer("sphinx").audience("app").build());
    }

    @AfterAll
    static void stop() {
        jwks.stop(0);
    }

    /** A valid token for alice, adjusted by {@code edit}. */
    private static String token(Consumer<JWTClaimsSet.Builder> edit) throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
            .subject("alice").issuer("sphinx").audience("app")
            .expirationTime(Date.from(Instant.now().plusSeconds(300)));
        edit.accept(claims);
        SignedJWT jwt = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("k1").build(), claims.build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private static TokenVerificationException.Reason rejection(String token) {
        return assertThrows(TokenVerificationException.class, () -> verifier.verify(token)).reason();
    }

    @Test
    void validTokenYieldsTheSubject() throws Exception {
        assertEquals("alice", verifier.verify(token(c -> {})).id());
    }

    @Test
    void missingSubIsMalformed() throws Exception {
        assertEquals(TokenVerificationException.Reason.MALFORMED,
            rejection(token(c -> c.subject(null))));
    }

    @Test
    void emptySubIsMalformed() throws Exception {
        assertEquals(TokenVerificationException.Reason.MALFORMED,
            rejection(token(c -> c.subject(""))));
    }

    @Test
    void nonStringSubIsMalformed() throws Exception {
        assertEquals(TokenVerificationException.Reason.MALFORMED,
            rejection(token(c -> c.claim("sub", 123))));
    }

    @Test
    void wronglyTypedContextClaimsAreAbsent() throws Exception {
        AuthenticatedSubject subject = verifier.verify(token(c -> c
            .claim("email", 1).claim("role", List.of("admin")).claim("auth_method", true)
            .claim("client_id", 2).claim("scope", Map.of("a", "b"))
            .claim("delegation_id", 3).claim("act", "not-an-object")));
        GatedContext ctx = GatedContext.fromSubject(subject);
        assertEquals("alice", ctx.personId());
        assertNull(ctx.email());
        assertNull(ctx.role());
        assertFalse(ctx.isAdmin());
        assertNull(ctx.authMethod());
        assertNull(ctx.clientId());
        assertNull(ctx.scope());
        assertNull(ctx.delegationId());
        assertFalse(ctx.isDelegated());
        assertNull(ctx.actorClaims());
        assertTrue(ctx.isHuman(), "a missing person_type still defaults to human");
    }

    @Test
    void wronglyTypedPersonTypeIsNotHuman() throws Exception {
        GatedContext ctx = GatedContext.fromSubject(
            verifier.verify(token(c -> c.claim("person_type", 7))));
        assertNull(ctx.identityType());
        assertFalse(ctx.isHuman());
    }

    @Test
    void wellTypedContextClaimsAreKept() throws Exception {
        GatedContext ctx = GatedContext.fromSubject(verifier.verify(token(c -> c
            .claim("person_type", "agent").claim("scope", "read write")
            .claim("act", Map.of("sub", "bob")))));
        assertEquals("agent", ctx.identityType());
        assertFalse(ctx.isHuman());
        assertTrue(ctx.hasScope("write"));
        assertEquals("bob", ctx.actorClaims().get("sub"));
    }
}
