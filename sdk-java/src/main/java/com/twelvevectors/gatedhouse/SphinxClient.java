// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import com.nimbusds.jose.util.JSONObjectUtils;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * HTTP Client wrapper to orchestrate Sphinx SSO OAuth 2.0 endpoints.
 *
 * <p>Every call is bounded: no network wait (connecting, or waiting for data)
 * exceeds {@link #timeout()}, which defaults to {@link #DEFAULT_TIMEOUT}.
 * Failures are reported as {@link SphinxException}, whose kind tells a
 * timeout or an unreachable IdP apart from a refused request. The client
 * never retries. Create one instance and reuse it.
 */
public final class SphinxClient {

    /** The timeout used when none is given: 10 seconds. */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);

    private final String baseUrl;
    private final String clientId;
    private final String clientSecret;
    private final Duration timeout;
    private final HttpClient http;

    public SphinxClient(String baseUrl, String clientId, String clientSecret) {
        this(baseUrl, clientId, clientSecret, DEFAULT_TIMEOUT);
    }

    /**
     * @param timeout the longest any single network wait may take; must be positive
     */
    public SphinxClient(String baseUrl, String clientId, String clientSecret, Duration timeout) {
        if (timeout == null || timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("timeout must be positive, got " + timeout);
        }
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.timeout = timeout;
        this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
    }

    /** The longest any single network wait may take. */
    public Duration timeout() {
        return timeout;
    }

    /**
     * Exchanges an authorization code for tokens.
     */
    public TokenResponse exchangeCode(String code, String redirectUri) {
        String body = "grant_type=authorization_code"
            + "&code=" + encode(code)
            + "&redirect_uri=" + encode(redirectUri)
            + "&client_id=" + encode(clientId)
            + "&client_secret=" + encode(clientSecret);
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
        HttpResponse<String> resp =
            post("/api/sphinx/v1/oauth/introspect", "token=" + encode(token), "Introspection");
        // The introspection endpoint conveys inactive or invalid tokens in
        // the body, so the body is parsed whatever the status.
        return parseObject(resp.body(), "Introspection");
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
        HttpResponse<String> resp = post("/api/sphinx/v1/oauth/token", body, "Token request");
        if (resp.statusCode() != 200) {
            throw new SphinxException(SphinxException.Kind.HTTP_STATUS, resp.statusCode(),
                "Token request failed (" + resp.statusCode() + "): " + resp.body(), null);
        }
        Map<String, Object> json = parseObject(resp.body(), "Token request");
        try {
            Number expiresInNum = (Number) json.get("expires_in");
            return new TokenResponse(
                (String) json.get("access_token"),
                (String) json.get("refresh_token"),
                (String) json.get("token_type"),
                expiresInNum != null ? expiresInNum.intValue() : 0,
                (String) json.get("scope"),
                (String) json.get("issued_token_type")
            );
        } catch (ClassCastException e) {
            throw new SphinxException(SphinxException.Kind.INVALID_RESPONSE, null,
                "Token request returned a field of the wrong type", e);
        }
    }

    /**
     * POSTs a form and returns the response, mapping every failure to a
     * {@link SphinxException}. The JDK client bounds connecting
     * ({@code connectTimeout}) and waiting for the response headers (the
     * request timeout) but not reading the body, so the whole exchange is
     * also capped at three timeouts (connect + headers + body): a server that
     * stalls mid-body cannot hang the caller.
     */
    private HttpResponse<String> post(String path, String form, String op) {
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .timeout(timeout)
            .POST(HttpRequest.BodyPublishers.ofString(form))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .build();
        CompletableFuture<HttpResponse<String>> pending =
            http.sendAsync(req, HttpResponse.BodyHandlers.ofString());
        try {
            return pending.get(backstopMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            pending.cancel(true);
            throw timedOut(op, e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof HttpTimeoutException) {   // includes HttpConnectTimeoutException
                throw timedOut(op, cause);
            }
            throw new SphinxException(SphinxException.Kind.TRANSPORT, null,
                op + " failed: " + cause, cause);
        } catch (InterruptedException e) {
            pending.cancel(true);
            Thread.currentThread().interrupt();
            throw new SphinxException(SphinxException.Kind.TRANSPORT, null, op + " interrupted", e);
        }
    }

    private long backstopMillis() {
        try {
            return timeout.multipliedBy(3).toMillis();
        } catch (ArithmeticException e) {
            return Long.MAX_VALUE;
        }
    }

    private SphinxException timedOut(String op, Throwable cause) {
        return new SphinxException(SphinxException.Kind.TIMEOUT, null,
            op + " timed out (timeout " + timeout.toMillis() + " ms)", cause);
    }

    private static Map<String, Object> parseObject(String body, String op) {
        try {
            return JSONObjectUtils.parse(body);
        } catch (java.text.ParseException e) {
            throw new SphinxException(SphinxException.Kind.INVALID_RESPONSE, null,
                op + " returned a response that is not a JSON object", e);
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
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
