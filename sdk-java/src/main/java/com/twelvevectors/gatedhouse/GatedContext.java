// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.util.Map;

/**
 * Representation of a verified Sphinx token's request context.
 * This is a type-safe record wrapping the generic authenticated subject and its claims.
 */
public record GatedContext(
    String personId,
    String email,
    String role,
    String identityType,
    String authMethod,
    boolean mfaVerified,
    boolean emailVerified,
    String clientId,
    String scope,
    String delegationId,
    Map<String, Object> actorClaims,
    Map<String, Object> rawClaims
) {
    /**
     * Checks if the user has an admin role.
     *
     * @return true if the role is "admin", false otherwise
     */
    public boolean isAdmin() {
        return "admin".equals(role);
    }

    /**
     * Checks if the subject is a human identity.
     *
     * @return true if the identityType is "human", false otherwise
     */
    public boolean isHuman() {
        return "human".equals(identityType);
    }

    /**
     * Checks if the request is delegated.
     *
     * @return true if a delegation ID is present, false otherwise
     */
    public boolean isDelegated() {
        return delegationId != null;
    }

    /**
     * Checks if the token contains a specific scope.
     *
     * @param requiredScope the scope to verify
     * @return true if the scope is present, false otherwise
     */
    public boolean hasScope(String requiredScope) {
        if (scope == null) {
            return false;
        }
        for (String s : scope.split("\\s+")) {
            if (s.equals(requiredScope)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Factory method to construct a GatedContext from an {@link AuthenticatedSubject}.
     *
     * @param subject the authenticated subject verified by Gatedhouse
     * @return a structured GatedContext record
     */
    @SuppressWarnings("unchecked")
    public static GatedContext fromSubject(AuthenticatedSubject subject) {
        Map<String, Object> claims = subject.claims();
        // A claim of the wrong type is treated as absent, except person_type:
        // absent defaults to "human", but a wrongly typed one is unknown
        // (null), so it can never pass requireHuman.
        Object personType = claims.getOrDefault("person_type", "human");
        Object act = claims.get("act");
        return new GatedContext(
            subject.id(),
            string(claims, "email"),
            string(claims, "role"),
            personType instanceof String s ? s : null,
            string(claims, "auth_method"),
            Boolean.TRUE.equals(claims.get("mfa_verified")),
            Boolean.TRUE.equals(claims.get("email_verified")),
            string(claims, "client_id"),
            string(claims, "scope"),
            string(claims, "delegation_id"),
            act instanceof Map<?, ?> m ? (Map<String, Object>) m : null,
            claims
        );
    }

    private static String string(Map<String, Object> claims, String name) {
        return claims.get(name) instanceof String s ? s : null;
    }
}
