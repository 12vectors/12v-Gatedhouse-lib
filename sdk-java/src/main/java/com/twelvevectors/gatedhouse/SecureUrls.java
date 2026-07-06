package com.twelvevectors.gatedhouse;

import java.net.URI;

/**
 * Internal URL-scheme guard. Security-sensitive endpoints (the Sphinx base URL and the JWKS URI)
 * carry credentials or root the token-verification trust chain, so they must be reached over TLS.
 * HTTPS is required; plain HTTP is permitted only for loopback hosts so local development and tests
 * still work. Not part of the public API.
 */
final class SecureUrls {

    private SecureUrls() {}

    static void requireHttpsOrLoopback(String url, String what) {
        if (url == null) {
            throw new IllegalArgumentException(what + " must not be null");
        }
        requireHttpsOrLoopback(URI.create(url), what);
    }

    static void requireHttpsOrLoopback(URI uri, String what) {
        String scheme = uri.getScheme();
        if ("https".equalsIgnoreCase(scheme)) {
            return;
        }
        String host = uri.getHost();
        boolean loopback = host != null && (host.equalsIgnoreCase("localhost")
            || host.equals("127.0.0.1") || host.equals("::1") || host.equals("[::1]"));
        if ("http".equalsIgnoreCase(scheme) && loopback) {
            return;
        }
        throw new IllegalArgumentException(
            what + " must use https (http is allowed only for localhost): " + uri);
    }
}
