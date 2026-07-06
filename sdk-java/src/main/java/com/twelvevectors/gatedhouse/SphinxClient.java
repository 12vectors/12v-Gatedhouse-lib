package com.twelvevectors.gatedhouse;

import com.nimbusds.jose.util.JSONObjectUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/**
 * HTTP Client wrapper to orchestrate Sphinx SSO OAuth 2.0 endpoints.
 */
public final class SphinxClient {

    /** Bounds connection setup so an unreachable Sphinx can't hang caller threads (see per-request timeout too). */
    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build();
    /** Upper bound on a single token/introspection round-trip; generous for a healthy Sphinx. */
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    private final String baseUrl;
    private final String clientId;
    private final String clientSecret;

    public SphinxClient(String baseUrl, String clientId, String clientSecret) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        // This client transmits the client_secret and receives tokens — refuse a non-TLS base URL.
        SecureUrls.requireHttpsOrLoopback(this.baseUrl, "Sphinx baseUrl");
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    /**
     * Exchanges an authorization code for tokens (no PKCE). Prefer the 3-arg overload with a
     * {@code codeVerifier} — see {@link LoginFlow}, which binds the code to the initiating browser.
     */
    public TokenResponse exchangeCode(String code, String redirectUri) {
        return exchangeCode(code, redirectUri, null);
    }

    /**
     * Exchanges an authorization code for tokens, sending the PKCE {@code code_verifier} when present
     * (RFC 7636). Sphinx rejects the exchange unless {@code S256(codeVerifier)} matches the challenge
     * bound to the code — so a code minted for a different browser's flow cannot be redeemed here.
     */
    public TokenResponse exchangeCode(String code, String redirectUri, String codeVerifier) {
        String body = "grant_type=authorization_code"
            + "&code=" + encode(code)
            + "&redirect_uri=" + encode(redirectUri)
            + "&client_id=" + encode(clientId)
            + "&client_secret=" + encode(clientSecret)
            + (codeVerifier != null ? "&code_verifier=" + encode(codeVerifier) : "");
        return postToken(body);
    }

    /**
     * Requests tokens via client credentials grant.
     */
    public TokenResponse clientCredentials(String scope) {
        String body = "grant_type=client_credentials"
            + "&client_id=" + encode(clientId)
            + "&client_secret=" + encode(clientSecret);
        if (scope != null) {
            body += "&scope=" + encode(scope);
        }
        return postToken(body);
    }

    /**
     * Performs an OAuth 2.0 Token Exchange.
     */
    public TokenResponse tokenExchange(String subjectToken, String actorToken,
                                       String delegationId, String scope) {
        String body = "grant_type=" + encode("urn:ietf:params:oauth:grant-type:token-exchange")
            + "&subject_token=" + encode(subjectToken)
            + "&actor_token=" + encode(actorToken)
            + "&delegation_id=" + encode(delegationId);
        if (scope != null) {
            body += "&scope=" + encode(scope);
        }
        return postToken(body);
    }

    /**
     * Refreshes an access token using a refresh token.
     */
    public TokenResponse refreshToken(String refreshToken) {
        String body = "grant_type=refresh_token"
            + "&refresh_token=" + encode(refreshToken)
            + "&client_id=" + encode(clientId)
            + "&client_secret=" + encode(clientSecret);
        return postToken(body);
    }

    /**
     * Introspects an access token.
     */
    public Map<String, Object> introspect(String token) {
        try {
            String body = "token=" + encode(token);
            var req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/sphinx/v1/oauth/introspect"))
                .timeout(REQUEST_TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .build();
            var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
            // Fail closed on a non-200: an error/proxy body must never be handed back as if it were a
            // valid introspection result (a caller could read that as "token active").
            if (resp.statusCode() != 200) {
                throw new RuntimeException(
                    "Introspection failed (" + resp.statusCode() + "): " + oauthError(resp.body()));
            }
            return JSONObjectUtils.parse(resp.body());
        } catch (IOException | InterruptedException | java.text.ParseException e) {
            throw new RuntimeException("Introspection failed", e);
        }
    }

    /**
     * Builds a redirect URL to the standard Sphinx login page.
     */
    public String loginUrl(String appShortcode) {
        return baseUrl + "/login?app=" + encode(appShortcode);
    }

    /**
     * Builds a redirect URL to a federated Sphinx login provider.
     */
    public String federatedLoginUrl(String ssoConnectionId, String appShortcode) {
        String url = baseUrl + "/api/sphinx/v1/auth/federated/" + encode(ssoConnectionId);
        if (appShortcode != null) {
            url += "?app=" + encode(appShortcode);
        }
        return url;
    }

    private TokenResponse postToken(String body) {
        try {
            var req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/sphinx/v1/oauth/token"))
                .timeout(REQUEST_TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .build();
            var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                // Surface only the standardized OAuth error code, never the raw body — it may carry
                // tokens or internal diagnostics that would leak into the caller's logs.
                throw new RuntimeException(
                    "Token request failed (" + resp.statusCode() + "): " + oauthError(resp.body()));
            }
            Map<String, Object> json = JSONObjectUtils.parse(resp.body());
            Number expiresInNum = (Number) json.get("expires_in");
            return new TokenResponse(
                (String) json.get("access_token"),
                (String) json.get("refresh_token"),
                (String) json.get("token_type"),
                expiresInNum != null ? expiresInNum.intValue() : 0,
                (String) json.get("scope"),
                (String) json.get("issued_token_type")
            );
        } catch (IOException | InterruptedException | java.text.ParseException e) {
            throw new RuntimeException("Token request failed", e);
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** Extract only the short, standardized OAuth {@code error} code from an error body (never tokens). */
    private static String oauthError(String body) {
        try {
            Object err = JSONObjectUtils.parse(body).get("error");
            return err instanceof String s ? s : "unknown_error";
        } catch (java.text.ParseException e) {
            return "unparseable_error";
        }
    }

    public record TokenResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        int expiresIn,
        String scope,
        String issuedTokenType
    ) {}
}
