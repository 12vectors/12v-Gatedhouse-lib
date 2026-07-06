"""Parity tests for the Sphinx SSO auth flows ported from the Java reference:
SecureUrls (M4/M5), LoginFlow PKCE + cookie + return-to (F12), and the
InMemoryPermissionCache generation fence (H1)."""

from __future__ import annotations

import pytest

from gatedhouse import (
    InMemoryPermissionCache,
    LoginCsrfError,
    LoginFlow,
    SphinxClient,
    TokenVerifierConfig,
)
from gatedhouse._secure_urls import require_https_or_loopback
from gatedhouse._sphinx_client import _oauth_error
from gatedhouse._types import EffectivePermission

SIGNING_KEY = b"signing-key-1"


def _flow(key: bytes = SIGNING_KEY) -> LoginFlow:
    client = SphinxClient("https://auth.example.com", "app-client", "app-secret")
    return LoginFlow(
        "https://auth.example.com", "app-client", "https://app.example.com/cb",
        "openid email", key, client,
    )


# ── SecureUrls (M4/M5) ────────────────────────────────────────────────────

def test_https_accepted():
    require_https_or_loopback("https://auth.example.com", "x")


def test_http_loopback_accepted():
    require_https_or_loopback("http://localhost:8080/x", "x")
    require_https_or_loopback("http://127.0.0.1/x", "x")


def test_http_non_loopback_rejected():
    with pytest.raises(ValueError):
        require_https_or_loopback("http://auth.example.com", "x")


def test_sphinx_client_rejects_plaintext_base_url():
    with pytest.raises(ValueError):
        SphinxClient("http://sphinx.example.com", "c", "s")
    SphinxClient("https://sphinx.example.com", "c", "s")  # ok


def test_token_verifier_config_rejects_plaintext_jwks():
    with pytest.raises(ValueError):
        TokenVerifierConfig(jwks_uri="http://sphinx/jwks", issuer="i", audience="a")
    TokenVerifierConfig(jwks_uri="https://sphinx/jwks", issuer="i", audience="a")  # ok


# ── LoginFlow PKCE + cookie (F12) ─────────────────────────────────────────

def test_challenge_is_rfc7636_s256():
    # RFC 7636 Appendix B canonical vector — must match Sphinx's PKCE check.
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert _flow().challenge_for(verifier) == expected


def test_signed_cookie_round_trips():
    f = _flow()
    assert f.verify_cookie_value(f.sign("abc123ABC456def789")) == "abc123ABC456def789"


def test_tampered_cookie_rejected():
    f = _flow()
    signed = f.sign("abc123")
    tampered = signed[:-1] + ("B" if signed[-1] == "A" else "A")
    assert f.verify_cookie_value(tampered) is None


def test_cookie_forged_with_wrong_key_rejected():
    signed = _flow(b"real-key").sign("abc123")
    assert _flow(b"attacker-key").verify_cookie_value(signed) is None


def test_malformed_cookie_rejected():
    f = _flow()
    assert f.verify_cookie_value(None) is None
    assert f.verify_cookie_value("no-dot-here") is None
    assert f.verify_cookie_value(".onlymac") is None


def test_begin_login_url_carries_pkce_and_no_state():
    f = _flow()
    url, cookie = f.begin_login()
    assert url.startswith("https://auth.example.com/oauth/authorize?")
    assert "code_challenge=" in url and "code_challenge_method=S256" in url
    assert "state=" not in url
    # the signed cookie round-trips under the same signing key
    assert f.verify_cookie_value(cookie) is not None
    # and is rejected under a different key
    assert _flow(b"other-key").verify_cookie_value(cookie) is None


def test_complete_login_requires_cookie_and_code():
    f = _flow()
    with pytest.raises(LoginCsrfError):
        f.complete_login(None, "somecode")
    with pytest.raises(LoginCsrfError):
        f.complete_login(f.sign("v"), None)
    with pytest.raises(LoginCsrfError):
        f.complete_login(f.sign("v"), "   ")


# ── return-to open-redirect guard ────────────────────────────────────────

def test_return_to_accepts_same_origin_relative():
    assert LoginFlow.sanitize_return_to("/dashboard") == "/dashboard"
    assert LoginFlow.sanitize_return_to("/reports/42?tab=usage") == "/reports/42?tab=usage"
    assert LoginFlow.sanitize_return_to("/") == "/"


def test_return_to_rejects_open_redirects():
    for bad in ("https://evil.com/p", "http://evil.com", "//evil.com/p", "/\\evil.com",
                "javascript:alert(1)", "dashboard", "/path with space", "/x\nSet-Cookie: y"):
        assert LoginFlow.sanitize_return_to(bad) is None


def test_consume_return_to_falls_back_to_default():
    f = _flow()
    assert f.consume_return_to("//evil.com", "/home") == "/home"
    assert f.consume_return_to("/dash", "/home") == "/dash"
    assert f.consume_return_to(None, "/home") == "/home"


# ── SphinxClient helpers ─────────────────────────────────────────────────

def test_oauth_error_extracts_code_only():
    assert _oauth_error('{"error":"invalid_grant","error_description":"secret detail"}') == "invalid_grant"
    assert _oauth_error("not json") == "unparseable_error"
    assert _oauth_error("{}") == "unknown_error"


def test_login_url_builders():
    c = SphinxClient("https://auth.example.com/", "c", "s")  # trailing slash trimmed
    assert c.login_url("myapp") == "https://auth.example.com/login?app=myapp"
    assert c.federated_login_url("conn1", "myapp").endswith("/auth/federated/conn1?app=myapp")


def test_introspect_hits_the_token_introspect_endpoint():
    # Pin the exact path Sphinx serves introspection at
    # (/api/sphinx/v1/oauth/token/introspect), so it can't silently drift.
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    captured: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            captured["path"] = self.path
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            body = b'{"active": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):  # silence
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port
    t = threading.Thread(target=server.handle_request, daemon=True)
    t.start()
    try:
        client = SphinxClient(f"http://127.0.0.1:{port}", "c", "s")
        result = client.introspect("some-token")
    finally:
        t.join(timeout=5)
        server.server_close()

    assert result == {"active": True}
    assert captured["path"] == "/api/sphinx/v1/oauth/token/introspect"


# ── InMemoryPermissionCache generation fence (H1) ────────────────────────

PERMS = [EffectivePermission("svc", "res", "act")]


def test_cache_stores_when_no_race():
    c = InMemoryPermissionCache()
    assert c.get_or_load("u", "o", lambda: PERMS) == PERMS
    assert c.size() == 1
    assert c.miss_count() == 1 and c.put_count() == 1
    c.get_or_load("u", "o", lambda: (_ for _ in ()).throw(AssertionError("no load on hit")))
    assert c.hit_count() == 1


def test_cache_fence_on_invalidate_mid_load():
    c = InMemoryPermissionCache()

    def loader():
        c.invalidate("u", "o")  # concurrent revoke, mid-load
        return PERMS

    assert c.get_or_load("u", "o", loader) == PERMS
    assert c.size() == 0 and c.put_count() == 0


def test_cache_fence_on_invalidate_all_mid_load():
    c = InMemoryPermissionCache()

    def loader():
        c.invalidate_all()
        return PERMS

    c.get_or_load("u", "o", loader)
    assert c.size() == 0


def test_cache_stores_after_invalidation():
    c = InMemoryPermissionCache()
    c.invalidate_all()
    c.get_or_load("u", "o", lambda: PERMS)
    assert c.size() == 1
