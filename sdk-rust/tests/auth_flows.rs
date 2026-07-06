//! Parity tests for the Sphinx SSO auth flows ported from the Java reference:
//! SecureUrls (M4/M5, tested via the public constructors that enforce it),
//! LoginFlow PKCE + cookie + return-to (F12), and the InMemoryPermissionCache
//! generation fence (H1).

use gatedhouse::error::LoginError;
use gatedhouse::login_flow::LoginFlow;
use gatedhouse::permission_cache::PermissionCache;
use gatedhouse::sphinx_client::SphinxClient;
use gatedhouse::types::EffectivePermission;
use gatedhouse::{InMemoryPermissionCache, TokenVerifierConfig};

const SIGNING_KEY: &[u8] = b"signing-key-1";

fn flow_with_key(key: &[u8]) -> LoginFlow {
    let client = SphinxClient::new("https://auth.example.com", "app-client", "app-secret");
    LoginFlow::new(
        "https://auth.example.com",
        "app-client",
        "https://app.example.com/cb",
        "openid email",
        key,
        client,
    )
}

fn flow() -> LoginFlow {
    flow_with_key(SIGNING_KEY)
}

// ── SecureUrls (M4/M5) via the enforcing constructors ─────────────────────

#[test]
#[should_panic(expected = "must use https")]
fn sphinx_client_rejects_plaintext_base_url() {
    SphinxClient::new("http://sphinx.example.com", "c", "s");
}

#[test]
fn sphinx_client_accepts_https_and_loopback() {
    SphinxClient::new("https://sphinx.example.com", "c", "s");
    SphinxClient::new("http://localhost:8080", "c", "s");
}

#[test]
#[should_panic(expected = "must use https")]
fn token_verifier_config_rejects_plaintext_jwks() {
    TokenVerifierConfig::new("http://sphinx/jwks", "i", "a");
}

// ── LoginFlow PKCE + cookie (F12) ─────────────────────────────────────────

#[test]
fn challenge_is_rfc7636_s256() {
    // RFC 7636 Appendix B canonical vector — must match Sphinx's PKCE check.
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    assert_eq!(flow().challenge_for(verifier), expected);
}

#[test]
fn signed_cookie_round_trips() {
    let f = flow();
    let signed = f.sign("abc123ABC456def789");
    assert_eq!(
        f.verify_cookie_value(Some(&signed)).as_deref(),
        Some("abc123ABC456def789")
    );
}

#[test]
fn tampered_cookie_rejected() {
    let f = flow();
    let signed = f.sign("abc123");
    let mut chars: Vec<char> = signed.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    assert!(f.verify_cookie_value(Some(&tampered)).is_none());
}

#[test]
fn cookie_forged_with_wrong_key_rejected() {
    let signed = flow_with_key(b"real-key").sign("abc123");
    assert!(flow_with_key(b"attacker-key")
        .verify_cookie_value(Some(&signed))
        .is_none());
}

#[test]
fn malformed_cookie_rejected() {
    let f = flow();
    assert!(f.verify_cookie_value(None).is_none());
    assert!(f.verify_cookie_value(Some("no-dot-here")).is_none());
    assert!(f.verify_cookie_value(Some(".onlymac")).is_none());
}

#[test]
fn begin_login_url_carries_pkce_and_no_state() {
    let f = flow();
    let (url, cookie) = f.begin_login();
    assert!(url.starts_with("https://auth.example.com/oauth/authorize?"));
    assert!(url.contains("code_challenge="));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(!url.contains("state="));
    assert!(f.verify_cookie_value(Some(&cookie)).is_some());
    assert!(flow_with_key(b"other")
        .verify_cookie_value(Some(&cookie))
        .is_none());
}

#[test]
fn complete_login_requires_cookie_and_code() {
    let f = flow();
    assert!(matches!(
        f.complete_login(None, Some("somecode")),
        Err(LoginError::Csrf(_))
    ));
    let cookie = f.sign("v");
    assert!(matches!(
        f.complete_login(Some(&cookie), None),
        Err(LoginError::Csrf(_))
    ));
    assert!(matches!(
        f.complete_login(Some(&cookie), Some("   ")),
        Err(LoginError::Csrf(_))
    ));
}

// ── return-to open-redirect guard ────────────────────────────────────────

#[test]
fn return_to_accepts_same_origin_relative() {
    assert_eq!(
        LoginFlow::sanitize_return_to(Some("/dashboard")).as_deref(),
        Some("/dashboard")
    );
    assert_eq!(
        LoginFlow::sanitize_return_to(Some("/reports/42?tab=usage")).as_deref(),
        Some("/reports/42?tab=usage")
    );
    assert_eq!(LoginFlow::sanitize_return_to(Some("/")).as_deref(), Some("/"));
}

#[test]
fn return_to_rejects_open_redirects() {
    for bad in [
        "https://evil.com/p",
        "http://evil.com",
        "//evil.com/p",
        "/\\evil.com",
        "javascript:alert(1)",
        "dashboard",
        "/path with space",
        "/x\nSet-Cookie: y",
    ] {
        assert!(
            LoginFlow::sanitize_return_to(Some(bad)).is_none(),
            "should reject {bad:?}"
        );
    }
    assert!(LoginFlow::sanitize_return_to(None).is_none());
}

#[test]
fn consume_return_to_falls_back_to_default() {
    let f = flow();
    assert_eq!(f.consume_return_to(Some("//evil.com"), "/home"), "/home");
    assert_eq!(f.consume_return_to(Some("/dash"), "/home"), "/dash");
    assert_eq!(f.consume_return_to(None, "/home"), "/home");
}

// ── InMemoryPermissionCache generation fence (H1) ────────────────────────

fn perms() -> Vec<EffectivePermission> {
    vec![EffectivePermission::new(
        Some("svc".into()),
        Some("res".into()),
        Some("act".into()),
    )]
}

#[test]
fn cache_stores_when_no_race() {
    let cache = InMemoryPermissionCache::new();
    let got = cache.get_or_load("u", "o", &|| Ok(perms())).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(cache.size(), 1);
    assert_eq!(cache.miss_count(), 1);
    assert_eq!(cache.put_count(), 1);
    // Second read is a hit (loader must not run).
    let _ = cache.get_or_load("u", "o", &|| panic!("loader ran on a hit"));
    assert_eq!(cache.hit_count(), 1);
}

#[test]
fn cache_fence_on_invalidate_mid_load() {
    let cache = InMemoryPermissionCache::new();
    let got = cache
        .get_or_load("u", "o", &|| {
            cache.invalidate("u", "o"); // concurrent revoke, mid-load
            Ok(perms())
        })
        .unwrap();
    assert_eq!(got.len(), 1, "caller still gets its loaded value");
    assert_eq!(cache.size(), 0, "but the stale value must not be cached");
    assert_eq!(cache.put_count(), 0);
}

#[test]
fn cache_fence_on_invalidate_all_mid_load() {
    let cache = InMemoryPermissionCache::new();
    let _ = cache.get_or_load("u", "o", &|| {
        cache.invalidate_all();
        Ok(perms())
    });
    assert_eq!(cache.size(), 0);
}

#[test]
fn cache_stores_after_invalidation() {
    let cache = InMemoryPermissionCache::new();
    cache.invalidate_all();
    let _ = cache.get_or_load("u", "o", &|| Ok(perms()));
    assert_eq!(cache.size(), 1);
}
