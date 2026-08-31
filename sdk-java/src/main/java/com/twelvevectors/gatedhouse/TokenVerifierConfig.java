// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.net.URI;
import java.util.Objects;

/**
 * Configuration for the JWT verification path. Pass to
 * {@link GatedhouseConfig.Builder#tokenVerifier(TokenVerifierConfig)} when
 * you want {@code gh.tokenVerifier()} to be available.
 *
 * <p>For a Sphinx deployment, {@link #jwksUri} is
 * {@code https://<sphinx-host>/api/sphinx/v1/auth/jwks},
 * {@link #issuer} is the literal {@code "sphinx"} (Sphinx access tokens
 * carry {@code iss="sphinx"}; its {@code OIDC_ISSUER} URL applies only to
 * OIDC id_tokens), and {@link #audience} is your app's {@code client_id}
 * as registered in Sphinx (access tokens set {@code aud} to the client id).
 */
public final class TokenVerifierConfig {

    private final URI jwksUri;
    private final String issuer;
    private final String audience;

    private TokenVerifierConfig(Builder builder) {
        this.jwksUri = Objects.requireNonNull(builder.jwksUri, "jwksUri");
        this.issuer = Objects.requireNonNull(builder.issuer, "issuer");
        this.audience = Objects.requireNonNull(builder.audience, "audience");
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

        private Builder() {
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
