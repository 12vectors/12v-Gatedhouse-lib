package com.twelvevectors.gatedhouse;

import java.net.URI;
import java.util.Objects;

/**
 * Configuration for the JWT verification path. Pass to
 * {@link GatedhouseConfig.Builder#tokenVerifier(TokenVerifierConfig)} when
 * you want {@code gh.tokenVerifier()} to be available.
 *
 * <p>For a Sphinx deployment, {@link #jwksUri} is
 * {@code https://<sphinx-host>/api/sphinx/v1/auth/jwks} (as advertised by Sphinx's
 * OIDC discovery document's {@code jwks_uri}). {@link #issuer} is the literal
 * {@code "sphinx"} — the {@code iss} Sphinx stamps on its OAuth access tokens, a fixed
 * value that does <em>not</em> vary with the deployment URL (it is not the OIDC issuer
 * URL, which appears only on id_tokens). {@link #audience} is your app's registered
 * {@code client_id} — the {@code aud} Sphinx sets on the access token issued to that client.
 */
public final class TokenVerifierConfig {

    private final URI jwksUri;
    private final String issuer;
    private final String audience;

    private TokenVerifierConfig(Builder builder) {
        this.jwksUri = Objects.requireNonNull(builder.jwksUri, "jwksUri");
        this.issuer = Objects.requireNonNull(builder.issuer, "issuer");
        this.audience = Objects.requireNonNull(builder.audience, "audience");
        // All signature trust is rooted in the keys fetched from jwksUri — a cleartext fetch would let
        // a network attacker substitute keys and forge tokens. Require TLS (loopback exempt for dev/test).
        SecureUrls.requireHttpsOrLoopback(this.jwksUri, "jwksUri");
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
