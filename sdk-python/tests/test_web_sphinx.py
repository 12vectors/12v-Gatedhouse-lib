# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Unit tests for the web & Sphinx SSO integration surface.

No database or network required — token verification is stubbed. Run with
``python -m unittest discover tests`` from ``sdk-python/``.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from gatedhouse import (
    AuthenticatedSubject,
    ForbiddenException,
    GatedContext,
    GatedhouseApiFilter,
    GatedhouseFactory,
    GatedhouseWebFilter,
    SphinxClient,
    TokenVerificationException,
    TokenVerifierConfig,
    UnauthorizedException,
)

_SUBJECT = AuthenticatedSubject(
    id="p1",
    issuer="i",
    audience="a",
    issued_at=None,
    expires_at=datetime.now(timezone.utc),
    token_type="access",
    claims={
        "email": "x@y.z",
        "role": "admin",
        "scope": "read write",
        "mfa_verified": True,
        "delegation_id": "d1",
        "act": {"sub": "agent"},
    },
)


class _StubGatedhouse:
    """Only the ``verify_token`` surface the filters touch."""

    def __init__(self, ok: bool) -> None:
        self._ok = ok

    def verify_token(self, token: str) -> AuthenticatedSubject:
        if self._ok:
            return _SUBJECT
        raise TokenVerificationException(
            TokenVerificationException.Reason.EXPIRED, "expired")


class _Recorder:
    """Captures the WSGI response a filter produces."""

    def __init__(self) -> None:
        self.status: str | None = None
        self.headers: list = []
        self.environ: dict = {}

    def app(self, environ, start_response):
        self.environ = environ
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]

    def start_response(self, status, headers, exc_info=None):
        self.status = status
        self.headers = headers


class GatedContextTest(unittest.TestCase):

    def test_claim_mapping_and_helpers(self):
        ctx = GatedContext.from_subject(_SUBJECT)
        self.assertEqual(ctx.person_id, "p1")
        self.assertTrue(ctx.is_admin())
        self.assertTrue(ctx.is_human())  # person_type defaults to "human"
        self.assertTrue(ctx.is_delegated())
        self.assertTrue(ctx.mfa_verified)
        self.assertFalse(ctx.email_verified)
        self.assertEqual(ctx.actor_claims, {"sub": "agent"})
        self.assertTrue(ctx.has_scope("write"))
        self.assertFalse(ctx.has_scope("writ"))

    def test_empty_claims(self):
        subject = AuthenticatedSubject(
            id="p2", issuer="i", audience="a", issued_at=None,
            expires_at=datetime.now(timezone.utc), token_type=None, claims={})
        ctx = GatedContext.from_subject(subject)
        self.assertFalse(ctx.is_admin())
        self.assertFalse(ctx.is_delegated())
        self.assertFalse(ctx.has_scope("read"))


class SphinxClientTest(unittest.TestCase):

    def test_url_builders(self):
        c = SphinxClient("https://sphinx.12v.sh/", "cid", "secret")
        self.assertEqual(c.login_url("my app"),
                         "https://sphinx.12v.sh/login?app=my+app")
        self.assertEqual(
            c.federated_login_url("conn1"),
            "https://sphinx.12v.sh/api/sphinx/v1/auth/federated/conn1")
        self.assertEqual(
            c.federated_login_url("conn1", "app"),
            "https://sphinx.12v.sh/api/sphinx/v1/auth/federated/conn1?app=app")


class JustTokenVerifierTest(unittest.TestCase):

    def test_database_operations_unsupported(self):
        gh = GatedhouseFactory.create_just_token_verifier(
            TokenVerifierConfig("https://x/jwks", "i", "a"))
        with self.assertRaises(NotImplementedError):
            gh.role_manager()
        with self.assertRaises(NotImplementedError):
            gh.has_permission("id", "org", "s", "r", "a")
        self.assertFalse(gh.is_cache_enabled())
        gh.set_cache_enabled(True)  # no cache exists — must stay disabled
        self.assertFalse(gh.is_cache_enabled())
        gh.invalidate_all_cache()  # no-op, must not raise
        gh.close()


class ApiFilterTest(unittest.TestCase):

    def test_valid_bearer_token_passes_through(self):
        rec = _Recorder()
        f = GatedhouseApiFilter(rec.app, _StubGatedhouse(True))
        f({"HTTP_AUTHORIZATION": "Bearer tok"}, rec.start_response)
        self.assertEqual(rec.status, "200 OK")
        self.assertTrue(rec.environ[GatedhouseApiFilter.CONTEXT_ATTR].is_admin())
        self.assertIn(("X-Frame-Options", "DENY"), rec.headers)

    def test_missing_header_is_401(self):
        rec = _Recorder()
        f = GatedhouseApiFilter(rec.app, _StubGatedhouse(True))
        body = b"".join(f({}, rec.start_response))
        self.assertEqual(rec.status, "401 Unauthorized")
        self.assertIn(b"Missing or invalid Bearer token", body)
        self.assertIn(("X-Content-Type-Options", "nosniff"), rec.headers)

    def test_invalid_token_is_401(self):
        rec = _Recorder()
        f = GatedhouseApiFilter(rec.app, _StubGatedhouse(False))
        body = b"".join(f({"HTTP_AUTHORIZATION": "Bearer bad"},
                          rec.start_response))
        self.assertEqual(rec.status, "401 Unauthorized")
        self.assertIn(b"Token verification failed", body)

    def test_require_helpers(self):
        ctx = GatedContext.from_subject(_SUBJECT)
        environ = {GatedhouseApiFilter.CONTEXT_ATTR: ctx}
        self.assertIs(GatedhouseApiFilter.require_admin(environ), ctx)
        self.assertIs(GatedhouseApiFilter.require_human(environ), ctx)
        self.assertIs(GatedhouseApiFilter.require_scope(environ, "read"), ctx)
        with self.assertRaises(ForbiddenException):
            GatedhouseApiFilter.require_scope(environ, "nope")
        with self.assertRaises(UnauthorizedException):
            GatedhouseApiFilter.get_context({})


class WebFilterTest(unittest.TestCase):

    def test_no_session_redirects_with_context_path(self):
        rec = _Recorder()
        w = GatedhouseWebFilter(rec.app, _StubGatedhouse(True))
        w({"SCRIPT_NAME": "/myapp"}, rec.start_response)
        self.assertEqual(rec.status, "302 Found")
        self.assertIn(("Location", "/myapp/auth/login"), rec.headers)

    def test_valid_session_token_passes_through(self):
        rec = _Recorder()
        w = GatedhouseWebFilter(rec.app, _StubGatedhouse(True))
        w({"gatedhouse.session": {"access_token": "tok"}}, rec.start_response)
        self.assertEqual(rec.status, "200 OK")
        self.assertIn(GatedhouseWebFilter.CONTEXT_ATTR, rec.environ)

    def test_invalid_token_cleared_and_redirected(self):
        rec = _Recorder()
        w = GatedhouseWebFilter(rec.app, _StubGatedhouse(False))
        session = {"access_token": "bad"}
        w({"gatedhouse.session": session, "SCRIPT_NAME": ""},
          rec.start_response)
        self.assertEqual(rec.status, "302 Found")
        self.assertNotIn("access_token", session)

    def test_absolute_login_path(self):
        rec = _Recorder()
        w = GatedhouseWebFilter(rec.app, _StubGatedhouse(False),
                                login_path="https://sso.example/login")
        w({"gatedhouse.session": {"access_token": "bad"}}, rec.start_response)
        self.assertIn(("Location", "https://sso.example/login"), rec.headers)


if __name__ == "__main__":
    unittest.main()
