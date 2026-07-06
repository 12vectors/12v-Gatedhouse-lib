package com.twelvevectors.gatedhouse;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Login-CSRF-safe hosted-login flow for Sphinx (F12). Binds the authorization code to the browser
 * that started the flow using <b>PKCE</b> — not {@code state} (see docs/PROPOSAL-login-csrf-fix.md:
 * {@code state} is the legacy double-submit token; PKCE is the cryptographic, IdP-enforced binding).
 *
 * <ul>
 *   <li>{@link #beginLogin} — generate a PKCE {@code code_verifier}, stash it in a signed, HttpOnly,
 *       {@code SameSite=Lax} cookie bound to THIS browser, and return the {@code /oauth/authorize}
 *       URL carrying only the {@code S256(verifier)} challenge (no {@code state}).</li>
 *   <li>{@link #completeLogin} — require this browser's cookie, then redeem the code <em>with</em> the
 *       verifier. Sphinx rejects any code whose challenge doesn't match, so an injected foreign code
 *       fails <b>before</b> the app adopts any identity. Throws {@link LoginCsrfException} otherwise.</li>
 * </ul>
 *
 * <p>Placement matters: call {@code completeLogin} <em>before</em> touching the session, and rotate
 * the session id ({@code req.changeSessionId()}) on elevation to defeat fixation.
 */
public final class LoginFlow {

    private static final String COOKIE = "gh_login";
    private static final int TTL_SECONDS = 600; // 10 min

    private final String authorizeUrl;
    private final String clientId;
    private final String redirectUri;
    private final String scope;
    private final byte[] signingKey;
    private final SphinxClient client;
    private final SecureRandom random = new SecureRandom();

    /**
     * @param sphinxBaseUrl base URL of Sphinx (e.g. {@code https://auth.example.com})
     * @param clientId      the app's OAuth client_id
     * @param redirectUri   the app's registered callback (must match exactly at Sphinx)
     * @param scope         requested scope (e.g. {@code "openid email"})
     * @param signingKey    HMAC key for the browser-bound cookie — use the client secret or a
     *                      dedicated random key; it never leaves the app
     * @param client        the {@link SphinxClient} used to redeem the code
     */
    public LoginFlow(String sphinxBaseUrl, String clientId, String redirectUri, String scope,
                     byte[] signingKey, SphinxClient client) {
        String base = sphinxBaseUrl.endsWith("/")
            ? sphinxBaseUrl.substring(0, sphinxBaseUrl.length() - 1) : sphinxBaseUrl;
        // The login flow rides over the Sphinx base URL — refuse a non-TLS endpoint.
        SecureUrls.requireHttpsOrLoopback(base, "Sphinx base URL");
        this.authorizeUrl = base + "/oauth/authorize";
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.signingKey = signingKey.clone();
        this.client = client;
    }

    /** Begin: bind a PKCE verifier to this browser; return the Sphinx authorize URL to redirect to. */
    public String beginLogin(HttpServletResponse resp) {
        String verifier = randomUrlSafe(64);
        String challenge = challengeFor(verifier);
        setCookie(resp, sign(verifier), TTL_SECONDS);
        return authorizeUrl
            + "?response_type=code"
            + "&client_id=" + enc(clientId)
            + "&redirect_uri=" + enc(redirectUri)
            + "&scope=" + enc(scope)
            + "&code_challenge=" + enc(challenge)
            + "&code_challenge_method=S256";
        // No state parameter — PKCE is the CSRF binding.
    }

    /**
     * Consume the deep-link target set by {@link GatedhouseWebFilter}: read and clear the
     * {@code gh_return} cookie and return a <em>validated</em> same-origin relative path to redirect
     * to after login, or {@code defaultHome} when there is no (valid) return target.
     *
     * <p>Open-redirect safe: only a path beginning with a single {@code '/'} is accepted. Absolute
     * URLs ({@code http://}, {@code https://}), protocol-relative ({@code //host}), backslash tricks
     * ({@code /\evil.com}) and anything with control characters are rejected in favour of
     * {@code defaultHome}.
     */
    public String consumeReturnTo(HttpServletRequest req, HttpServletResponse resp, String defaultHome) {
        String raw = readReturnCookie(req);
        clearReturnCookie(resp);
        String safe = sanitizeReturnTo(raw);
        return safe != null ? safe : defaultHome;
    }

    private static String readReturnCookie(HttpServletRequest req) {
        if (req.getCookies() == null) return null;
        for (Cookie c : req.getCookies()) {
            if (GatedhouseWebFilter.RETURN_COOKIE.equals(c.getName())) return c.getValue();
        }
        return null;
    }

    private static void clearReturnCookie(HttpServletResponse resp) {
        Cookie c = new Cookie(GatedhouseWebFilter.RETURN_COOKIE, "");
        c.setHttpOnly(true);
        c.setSecure(true);
        c.setPath("/");
        c.setMaxAge(0);
        c.setAttribute("SameSite", "Lax");
        resp.addCookie(c);
    }

    /** Package-private for unit tests. Returns the path if it is a safe same-origin relative path, else null. */
    static String sanitizeReturnTo(String raw) {
        if (raw == null || raw.isEmpty()) return null;
        // Must be an absolute-path reference: exactly one leading '/'.
        if (raw.charAt(0) != '/') return null;
        if (raw.length() >= 2 && (raw.charAt(1) == '/' || raw.charAt(1) == '\\')) return null; // //host or /\host
        // No scheme, no control chars / whitespace that could smuggle a second header or a new target.
        for (int i = 0; i < raw.length(); i++) {
            char ch = raw.charAt(i);
            if (ch <= 0x20 || ch == 0x7f || ch == '\\') return null;
        }
        if (raw.contains("://")) return null;
        return raw;
    }

    /** Complete: require this browser's verifier cookie, then redeem the code with it. */
    public SphinxClient.TokenResponse completeLogin(HttpServletRequest req, HttpServletResponse resp) {
        String verifier = readVerifier(req);
        clearCookie(resp);
        if (verifier == null) {
            throw new LoginCsrfException("no login in progress for this browser");
        }
        String code = req.getParameter("code");
        if (code == null || code.isBlank()) {
            throw new LoginCsrfException("callback is missing the authorization code");
        }
        SphinxClient.TokenResponse tokens = client.exchangeCode(code, redirectUri, verifier);
        // Anti-fixation: rotate the session id on this privilege elevation so a pre-login (possibly
        // attacker-fixed) session id can't be reused post-login. Guarded — no-op if the app hasn't
        // created a session yet. Idempotent with an app that also rotates.
        if (req.getSession(false) != null) {
            req.changeSessionId();
        }
        return tokens;
    }

    // ── PKCE + signed cookie ("verifier.hmac"); package-private for unit tests ─────

    /** RFC 7636 S256: {@code BASE64URL(SHA256(ASCII(verifier)))}. Matches Sphinx's challenge check. */
    String challengeFor(String verifier) {
        return base64Url(sha256(verifier.getBytes(StandardCharsets.US_ASCII)));
    }

    String sign(String verifier) {
        return verifier + "." + base64Url(hmac(verifier.getBytes(StandardCharsets.US_ASCII)));
    }

    /** Verify a signed cookie value; returns the verifier, or {@code null} if absent/forged/tampered. */
    String verifyCookieValue(String raw) {
        if (raw == null) return null;
        int dot = raw.lastIndexOf('.');
        if (dot <= 0) return null;
        String verifier = raw.substring(0, dot);
        String mac = raw.substring(dot + 1);
        String expected = base64Url(hmac(verifier.getBytes(StandardCharsets.US_ASCII)));
        return constantTimeEquals(mac, expected) ? verifier : null;
    }

    private String readVerifier(HttpServletRequest req) {
        if (req.getCookies() == null) return null;
        for (Cookie c : req.getCookies()) {
            if (COOKIE.equals(c.getName())) return verifyCookieValue(c.getValue());
        }
        return null;
    }

    private static void setCookie(HttpServletResponse resp, String value, int maxAge) {
        Cookie c = new Cookie(COOKIE, value);
        c.setHttpOnly(true);
        c.setSecure(true);
        c.setPath("/");
        c.setMaxAge(maxAge);
        c.setAttribute("SameSite", "Lax"); // rides the top-level callback navigation
        resp.addCookie(c);
    }

    private static void clearCookie(HttpServletResponse resp) {
        setCookie(resp, "", 0);
    }

    // ── crypto helpers (all JDK stdlib) ───────────────────────────────────────────

    private byte[] hmac(byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(signingKey, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    private static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private String randomUrlSafe(int nBytes) {
        byte[] b = new byte[nBytes];
        random.nextBytes(b);
        return base64Url(b);
    }

    private static String base64Url(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static String enc(String v) {
        return java.net.URLEncoder.encode(v, StandardCharsets.UTF_8);
    }
}
