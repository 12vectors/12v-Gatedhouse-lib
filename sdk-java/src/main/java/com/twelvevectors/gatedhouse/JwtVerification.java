// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.MalformedURLException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Package-private Nimbus-backed JWT verifier. Used internally by
 * {@link DefaultGatedhouse#verifyToken(String)}; not part of the public API.
 *
 * <p>Thread-safe: Nimbus's {@link DefaultJWTProcessor} and the
 * {@link JWKSource} produced by {@link JWKSourceBuilder} are documented
 * thread-safe. We hold both as final fields and never mutate verifier
 * state on a verify call. Safe to share a single instance across all
 * threads.
 */
final class JwtVerification {

    /** Standard JWT claims we extract or validate explicitly; everything
     *  else is exposed via {@link AuthenticatedSubject#claims}. */
    private static final Set<String> STANDARD_CLAIMS = Set.of(
        "sub", "iss", "aud", "iat", "exp", "nbf", "type"
    );

    private final String expectedIssuer;
    private final String expectedAudience;
    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    JwtVerification(TokenVerifierConfig config) {
        this.expectedIssuer = config.issuer();
        this.expectedAudience = config.audience();
        try {
            JWKSource<SecurityContext> jwkSource = JWKSourceBuilder
                .create(config.jwksUri().toURL())
                .build();
            JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
            DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            processor.setJWSKeySelector(keySelector);
            // Disable Nimbus's claims verifier — we validate claims explicitly
            // below so each failure mode maps to a distinct Reason.
            processor.setJWTClaimsSetVerifier((claims, context) -> {});
            this.jwtProcessor = processor;
        } catch (MalformedURLException e) {
            throw new GatedhouseInitializationException(
                "TokenVerifierConfig jwksUri is not a valid URL: " + config.jwksUri(), e);
        }
    }

    AuthenticatedSubject verify(String token) {
        Objects.requireNonNull(token, "token");

        JWTClaimsSet claims;
        try {
            claims = jwtProcessor.process(token, null);
        } catch (ParseException e) {
            throw fail(TokenVerificationException.Reason.MALFORMED,
                "JWT could not be parsed: " + e.getMessage(), e);
        } catch (BadJOSEException e) {
            // We disabled the claims verifier, so anything reaching here is a
            // signature-level failure (BadJWSException, missing-key, etc.).
            throw fail(TokenVerificationException.Reason.INVALID_SIGNATURE,
                "Signature verification failed: " + e.getMessage(), e);
        } catch (RemoteKeySourceException e) {
            throw fail(TokenVerificationException.Reason.JWKS_UNAVAILABLE,
                "JWKS endpoint unreachable: " + e.getMessage(), e);
        } catch (KeySourceException e) {
            throw fail(TokenVerificationException.Reason.UNKNOWN_KEY,
                "Token kid not present in JWKS: " + e.getMessage(), e);
        } catch (JOSEException e) {
            throw fail(TokenVerificationException.Reason.OTHER,
                "JOSE failure: " + e.getMessage(), e);
        }

        // Explicit claim validation — distinct exception per failure mode.
        if (!Objects.equals(expectedIssuer, claims.getIssuer())) {
            throw fail(TokenVerificationException.Reason.INVALID_ISSUER,
                "Expected issuer '" + expectedIssuer + "', got '" + claims.getIssuer() + "'");
        }
        List<String> audiences = claims.getAudience();
        if (audiences == null || !audiences.contains(expectedAudience)) {
            throw fail(TokenVerificationException.Reason.INVALID_AUDIENCE,
                "Expected audience '" + expectedAudience + "' not in token audiences " + audiences);
        }
        Date exp = claims.getExpirationTime();
        Instant now = Instant.now();
        if (exp == null) {
            throw fail(TokenVerificationException.Reason.EXPIRED,
                "Token has no 'exp' claim");
        }
        if (exp.toInstant().isBefore(now)) {
            throw fail(TokenVerificationException.Reason.EXPIRED,
                "Token expired at " + exp.toInstant());
        }
        Date nbf = claims.getNotBeforeTime();
        if (nbf != null && nbf.toInstant().isAfter(now)) {
            throw fail(TokenVerificationException.Reason.NOT_YET_VALID,
                "Token not valid before " + nbf.toInstant());
        }

        Date iat = claims.getIssueTime();
        Object typeClaim = claims.getClaim("type");
        String tokenType = typeClaim instanceof String s ? s : null;

        Map<String, Object> custom = new HashMap<>(claims.getClaims());
        custom.keySet().removeAll(STANDARD_CLAIMS);

        return new AuthenticatedSubject(
            claims.getSubject(),
            claims.getIssuer(),
            audiences.get(0),
            iat == null ? null : iat.toInstant(),
            exp.toInstant(),
            tokenType,
            Collections.unmodifiableMap(custom)
        );
    }

    private static TokenVerificationException fail(
            TokenVerificationException.Reason reason, String message) {
        return new TokenVerificationException(reason, message);
    }

    private static TokenVerificationException fail(
            TokenVerificationException.Reason reason, String message, Throwable cause) {
        return new TokenVerificationException(reason, message, cause);
    }
}
