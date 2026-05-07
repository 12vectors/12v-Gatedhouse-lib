package com.twelvevectors.gatedhouse;

import java.time.Instant;
import java.util.Map;

/**
 * The trusted output of a successful {@link Gatedhouse#verifyToken} call.
 * The {@link #id} is the JWT {@code sub} claim — pass it to
 * {@code Gatedhouse.hasPermission(...)} as the authenticated identity.
 *
 * @param id          JWT {@code sub} claim — the authenticated identity
 * @param issuer      JWT {@code iss} claim
 * @param audience    JWT {@code aud} claim (first entry if multiple)
 * @param issuedAt    JWT {@code iat} claim, may be null
 * @param expiresAt   JWT {@code exp} claim
 * @param tokenType   JWT {@code type} claim if present (e.g. "access",
 *                    "refresh", "delegation"), else null
 * @param claims      All non-standard claims (immutable). Use this to read
 *                    custom values like {@code org_id} or delegation
 *                    metadata.
 */
public record AuthenticatedSubject(
    String id,
    String issuer,
    String audience,
    Instant issuedAt,
    Instant expiresAt,
    String tokenType,
    Map<String, Object> claims
) {
}
