// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import com.nimbusds.jose.util.JSONObjectUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * HTTP Client wrapper to orchestrate Sphinx SSO OAuth 2.0 endpoints.
 */
public final class SphinxClient {

    private static final HttpClient HTTP = HttpClient.newHttpClient();

    private final String baseUrl;
    private final String clientId;
    private final String clientSecret;

    public SphinxClient(String baseUrl, String clientId, String clientSecret) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
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
        try {
            String body = "token=" + encode(token);
            var req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/sphinx/v1/oauth/introspect"))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .build();
            var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
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
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .build();
            var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new RuntimeException("Token request failed (" + resp.statusCode() + "): " + resp.body());
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

    public record TokenResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        int expiresIn,
        String scope,
        String issuedTokenType
    ) {}
}
