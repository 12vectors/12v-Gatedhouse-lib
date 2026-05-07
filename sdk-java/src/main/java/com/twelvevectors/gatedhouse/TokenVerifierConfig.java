package com.twelvevectors.gatedhouse;

import java.net.URI;
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
