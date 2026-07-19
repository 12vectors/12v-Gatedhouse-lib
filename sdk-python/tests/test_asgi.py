# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Unit tests for the ASGI security middleware.

No database, network, or ASGI framework required — token verification is
stubbed and the middleware is driven through the raw ASGI protocol. Run
with ``python -m unittest discover tests`` from ``sdk-python/``.
"""

from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timezone

from gatedhouse import AuthenticatedSubject, TokenVerificationException
from gatedhouse.asgi import (
    CONTEXT_ATTR,
    STATE_KEY,
    ForbiddenException,
    GatedhouseApiFilter,
    GatedhouseWebFilter,
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

    def __init__(self, ok: bool) -> None:
        self._ok = ok

    def verify_token(self, token: str) -> AuthenticatedSubject:
        if self._ok:
            return _SUBJECT
        raise TokenVerificationException(
            TokenVerificationException.Reason.EXPIRED, "expired")


class _Recorder:
    """Runs a middleware-wrapped app and captures the ASGI exchange."""

    def __init__(self) -> None:
        self.messages: list[dict] = []
        self.scope_seen: dict | None = None

    async def app(self, scope, receive, send):
        self.scope_seen = scope
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"ok"})

    def run(self, middleware, scope):
        async def receive():
            return {"type": "http.request", "body": b""}

        async def send(message):
            self.messages.append(message)

        asyncio.run(middleware(scope, receive, send))
        return self.messages

    @property
    def status(self):
        return self.messages[0]["status"]

    @property
    def headers(self):
        return dict(self.messages[0]["headers"])

    @property
    def body(self):
        return b"".join(m.get("body", b"") for m in self.messages
                        if m["type"] == "http.response.body")


def _http_scope(**extra) -> dict:
    scope = {"type": "http", "method": "GET", "path": "/", "headers": []}
    scope.update(extra)
    return scope


class ApiFilterTest(unittest.TestCase):

    def test_valid_bearer_token_passes_through(self):
        rec = _Recorder()
        f = GatedhouseApiFilter(rec.app, _StubGatedhouse(True))
        rec.run(f, _http_scope(headers=[(b"authorization", b"Bearer tok")]))
        self.assertEqual(rec.status, 200)
        self.assertTrue(rec.scope_seen[CONTEXT_ATTR].is_admin())
        self.assertTrue(rec.scope_seen["state"][STATE_KEY].is_admin())
        self.assertEqual(rec.headers[b"x-frame-options"], b"DENY")

    def test_missing_header_is_401(self):
        rec = _Recorder()
        f = GatedhouseApiFilter(rec.app, _StubGatedhouse(True))
        rec.run(f, _http_scope())
        self.assertEqual(rec.status, 401)
        self.assertIn(b"Missing or invalid Bearer token", rec.body)
        self.assertEqual(rec.headers[b"x-content-type-options"], b"nosniff")
        self.assertIsNone(rec.scope_seen)  # downstream app never ran

    def test_invalid_token_is_401(self):
        rec = _Recorder()
        f = GatedhouseApiFilter(rec.app, _StubGatedhouse(False))
        rec.run(f, _http_scope(headers=[(b"authorization", b"Bearer bad")]))
        self.assertEqual(rec.status, 401)
        self.assertIn(b"Token verification failed", rec.body)

    def test_lifespan_scope_passes_through(self):
        seen = {}

        async def app(scope, receive, send):
            seen.update(scope)

        f = GatedhouseApiFilter(app, _StubGatedhouse(False))
        asyncio.run(f({"type": "lifespan"}, None, None))
        self.assertEqual(seen, {"type": "lifespan"})

    def test_websocket_without_token_is_rejected(self):
        rec = _Recorder()
        f = GatedhouseApiFilter(rec.app, _StubGatedhouse(True))
        messages = rec.run(f, {"type": "websocket", "path": "/ws",
                               "headers": []})
        self.assertEqual(messages, [{"type": "websocket.close", "code": 1008}])
        self.assertIsNone(rec.scope_seen)  # app never invoked

    def test_websocket_with_bad_token_is_rejected(self):
        rec = _Recorder()
        f = GatedhouseApiFilter(rec.app, _StubGatedhouse(False))
        messages = rec.run(f, {"type": "websocket", "path": "/ws",
                               "headers": [(b"authorization", b"Bearer bad")]})
        self.assertEqual(messages, [{"type": "websocket.close", "code": 1008}])
        self.assertIsNone(rec.scope_seen)

    def test_websocket_with_valid_token_passes_through(self):
        rec = _Recorder()
        f = GatedhouseApiFilter(rec.app, _StubGatedhouse(True))
        rec.run(f, {"type": "websocket", "path": "/ws",
                    "headers": [(b"authorization", b"Bearer tok")]})
        self.assertIsNotNone(rec.scope_seen)
        self.assertTrue(rec.scope_seen[CONTEXT_ATTR].is_admin())

    def test_require_helpers(self):
        from gatedhouse import GatedContext
        ctx = GatedContext.from_subject(_SUBJECT)
        scope = {CONTEXT_ATTR: ctx}
        self.assertIs(GatedhouseApiFilter.require_admin(scope), ctx)
        self.assertIs(GatedhouseApiFilter.require_human(scope), ctx)
        self.assertIs(GatedhouseApiFilter.require_scope(scope, "read"), ctx)
        with self.assertRaises(ForbiddenException):
            GatedhouseApiFilter.require_scope(scope, "nope")
        with self.assertRaises(UnauthorizedException):
            GatedhouseApiFilter.get_context({})


class WebFilterTest(unittest.TestCase):

    def test_no_session_redirects_with_root_path(self):
        rec = _Recorder()
        w = GatedhouseWebFilter(rec.app, _StubGatedhouse(True))
        rec.run(w, _http_scope(root_path="/myapp"))
        self.assertEqual(rec.status, 302)
        self.assertEqual(rec.headers[b"location"], b"/myapp/auth/login")

    def test_valid_session_token_passes_through(self):
        rec = _Recorder()
        w = GatedhouseWebFilter(rec.app, _StubGatedhouse(True))
        rec.run(w, _http_scope(session={"access_token": "tok"}))
        self.assertEqual(rec.status, 200)
        self.assertIn(CONTEXT_ATTR, rec.scope_seen)

    def test_invalid_token_cleared_and_redirected(self):
        rec = _Recorder()
        w = GatedhouseWebFilter(rec.app, _StubGatedhouse(False))
        session = {"access_token": "bad"}
        rec.run(w, _http_scope(session=session))
        self.assertEqual(rec.status, 302)
        self.assertNotIn("access_token", session)

    def test_absolute_login_path(self):
        rec = _Recorder()
        w = GatedhouseWebFilter(rec.app, _StubGatedhouse(False),
                                login_path="https://sso.example/login")
        rec.run(w, _http_scope(session={"access_token": "bad"}))
        self.assertEqual(rec.headers[b"location"], b"https://sso.example/login")

    def test_websocket_without_session_is_rejected(self):
        rec = _Recorder()
        w = GatedhouseWebFilter(rec.app, _StubGatedhouse(True))
        messages = rec.run(w, {"type": "websocket", "path": "/ws",
                               "headers": []})
        self.assertEqual(messages, [{"type": "websocket.close", "code": 1008}])
        self.assertIsNone(rec.scope_seen)

    def test_websocket_invalid_token_evicted_and_rejected(self):
        rec = _Recorder()
        w = GatedhouseWebFilter(rec.app, _StubGatedhouse(False))
        session = {"access_token": "bad"}
        messages = rec.run(w, {"type": "websocket", "path": "/ws",
                               "headers": [], "session": session})
        self.assertEqual(messages, [{"type": "websocket.close", "code": 1008}])
        self.assertNotIn("access_token", session)

    def test_websocket_valid_session_token_passes_through(self):
        rec = _Recorder()
        w = GatedhouseWebFilter(rec.app, _StubGatedhouse(True))
        rec.run(w, {"type": "websocket", "path": "/ws", "headers": [],
                    "session": {"access_token": "tok"}})
        self.assertIsNotNone(rec.scope_seen)
        self.assertIn(CONTEXT_ATTR, rec.scope_seen)


if __name__ == "__main__":
    unittest.main()
