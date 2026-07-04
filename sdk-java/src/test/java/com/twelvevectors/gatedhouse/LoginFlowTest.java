package com.twelvevectors.gatedhouse;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * F12 — the security core of {@link LoginFlow}: the PKCE challenge must be RFC-7636 S256 (so Sphinx
 * accepts it), and the browser-bound cookie must be unforgeable without the HMAC key.
 */
class LoginFlowTest {

    private static LoginFlow flow(String key) {
        return new LoginFlow("https://auth.example.com", "app-client", "https://app.example.com/cb",
            "openid email", key.getBytes(StandardCharsets.UTF_8),
            new SphinxClient("https://auth.example.com", "app-client", "app-secret"));
    }

    @Test
    void challengeIsRfc7636S256() {
        // RFC 7636, Appendix B — the canonical verifier→challenge test vector.
        String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assertEquals(expected, flow("k").challengeFor(verifier),
            "challenge must be BASE64URL(SHA256(ASCII(verifier))) — matches Sphinx's PKCE check");
    }

    @Test
    void signedCookieRoundTrips() {
        var f = flow("signing-key-1");
        String verifier = "abc123ABC456def789";
        assertEquals(verifier, f.verifyCookieValue(f.sign(verifier)));
    }

    @Test
    void tamperedCookieIsRejected() {
        var f = flow("signing-key-1");
        String signed = f.sign("abc123");
        // Flip the last character of the MAC.
        char last = signed.charAt(signed.length() - 1);
        String tampered = signed.substring(0, signed.length() - 1) + (last == 'A' ? 'B' : 'A');
        assertNull(f.verifyCookieValue(tampered), "a tampered MAC must not verify");
    }

    @Test
    void cookieForgedWithWrongKeyIsRejected() {
        String signed = flow("real-key").sign("abc123");
        assertNull(flow("attacker-key").verifyCookieValue(signed),
            "a cookie signed with a different key must not verify (attacker can't forge it)");
    }

    @Test
    void malformedCookieIsRejected() {
        var f = flow("k");
        assertNull(f.verifyCookieValue(null));
        assertNull(f.verifyCookieValue("no-dot-here"));
        assertNull(f.verifyCookieValue(".onlymac"));
    }

    // ── deep-link return target (open-redirect safety) ────────────────────────────

    @Test
    void returnToAcceptsSameOriginRelativePaths() {
        assertEquals("/dashboard", LoginFlow.sanitizeReturnTo("/dashboard"));
        assertEquals("/reports/42?tab=usage", LoginFlow.sanitizeReturnTo("/reports/42?tab=usage"));
        assertEquals("/", LoginFlow.sanitizeReturnTo("/"));
    }

    @Test
    void returnToRejectsOpenRedirects() {
        // Absolute URLs, protocol-relative, and backslash tricks must all be refused.
        assertNull(LoginFlow.sanitizeReturnTo("https://evil.com/phish"));
        assertNull(LoginFlow.sanitizeReturnTo("http://evil.com"));
        assertNull(LoginFlow.sanitizeReturnTo("//evil.com/phish"));
        assertNull(LoginFlow.sanitizeReturnTo("/\\evil.com"));
        assertNull(LoginFlow.sanitizeReturnTo("javascript:alert(1)"));
        assertNull(LoginFlow.sanitizeReturnTo("dashboard")); // no leading slash → not a path reference
    }

    @Test
    void returnToRejectsControlCharsAndBlanks() {
        assertNull(LoginFlow.sanitizeReturnTo(null));
        assertNull(LoginFlow.sanitizeReturnTo(""));
        assertNull(LoginFlow.sanitizeReturnTo("/path\nSet-Cookie: x=y")); // header smuggling
        assertNull(LoginFlow.sanitizeReturnTo("/path with space")); // 0x20 rejected
    }
}
