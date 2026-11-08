// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/**
 * Configuration for the JWT verification path. Pass to
 * {@link GatedhouseConfig.Builder#tokenVerifier(TokenVerifierConfig)} when
 * you want {@code gh.tokenVerifier()} to be available.
 *
 * <p>For a Sphinx deployment, {@link #jwksUri} is typically
 * {@code https://<sphinx-host>/api/sphinx/v1/.well-known/jwks.json},
 * {@link #issuer} matches Sphinx's {@code JWT_ISSUER}, and
 * {@link #audience} matches its {@code JWT_AUDIENCE}.
 *
 * <p>Fetching the JWKS is bounded by {@link #jwksTimeout()} (default
 * {@link #DEFAULT_JWKS_TIMEOUT}): no network wait while fetching exceeds it.
 * A fetch that fails or times out surfaces as a
 * {@link TokenVerificationException} with reason
 * {@link TokenVerificationException.Reason#JWKS_UNAVAILABLE}.
 */
public final class TokenVerifierConfig {

    /** The JWKS fetch timeout used when none is given: 5 seconds. */
    public static final Duration DEFAULT_JWKS_TIMEOUT = Duration.ofSeconds(5);

    private final URI jwksUri;
    private final String issuer;
    private final String audience;
    private final Duration jwksTimeout;

    private TokenVerifierConfig(Builder builder) {
        this.jwksUri = Objects.requireNonNull(builder.jwksUri, "jwksUri");
        this.issuer = Objects.requireNonNull(builder.issuer, "issuer");
        this.audience = Objects.requireNonNull(builder.audience, "audience");
        this.jwksTimeout = builder.jwksTimeout;
    }

    /** The longest any single network wait may take while fetching the JWKS. */
    public Duration jwksTimeout() {
        return jwksTimeout;
    }

    public URI jwksUri() {
        return jwksUri;
    }

    public String issuer() {
        return issuer;
    }

    public String audience() {
        return audience;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {

        private URI jwksUri;
        private String issuer;
        private String audience;
        private Duration jwksTimeout = DEFAULT_JWKS_TIMEOUT;

        private Builder() {
        }

        /** The longest any single network wait may take while fetching the JWKS; must be positive. */
        public Builder jwksTimeout(Duration jwksTimeout) {
            if (jwksTimeout == null || jwksTimeout.isZero() || jwksTimeout.isNegative()) {
                throw new IllegalArgumentException("jwksTimeout must be positive, got " + jwksTimeout);
            }
            if (jwksTimeout.toMillis() > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("jwksTimeout is too large: " + jwksTimeout);
            }
            this.jwksTimeout = jwksTimeout;
            return this;
        }

        public Builder jwksUri(URI jwksUri) {
            this.jwksUri = jwksUri;
            return this;
        }

        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder audience(String audience) {
            this.audience = audience;
            return this;
        }

        public TokenVerifierConfig build() {
            return new TokenVerifierConfig(this);
        }
    }
}
