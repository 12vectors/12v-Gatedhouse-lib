// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

/**
 * Thrown by {@link Gatedhouse#verifyToken(String)} when a JWT fails verification.
 * The {@link #reason} enables callers to branch on the failure mode —
 * critical for client applications that need to distinguish "token expired,
 * try refresh" from "token forged, reject and re-authenticate".
 */
public final class TokenVerificationException extends RuntimeException {

    public enum Reason {
        /** {@code exp} is in the past, or absent. Caller should refresh
         *  or redirect the user back to SSO. */
        EXPIRED,

        /** {@code nbf} is in the future. Token not valid yet — clock skew? */
        NOT_YET_VALID,

        /** Cryptographic signature did not verify. Token was tampered with
         *  or signed by an unknown party. Reject and log a security event. */
        INVALID_SIGNATURE,

        /** {@code iss} did not match the configured issuer. Wrong source. */
        INVALID_ISSUER,

        /** {@code aud} did not include the configured audience. Token was
         *  not issued for this application. */
        INVALID_AUDIENCE,

        /** Token is structurally malformed (not a valid JWS compact form). */
        MALFORMED,

        /** Header {@code kid} did not match any key in the issuer's JWKS,
         *  even after a refresh. May be a forged token or stale keyset. */
        UNKNOWN_KEY,

        /** Could not reach the JWKS endpoint to fetch verification keys.
         *  Transient infrastructure error — caller may retry. */
        JWKS_UNAVAILABLE,

        /** Verification failed for an unexpected reason; see cause. */
        OTHER
    }

    private final Reason reason;

    public TokenVerificationException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public TokenVerificationException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
