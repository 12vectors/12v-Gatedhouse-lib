# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Production behaviour, mirroring the Java filter, cache and pool tests:
auth responses, the bounded cache, JWKS fetch limits and the owned pool."""

from __future__ import annotations

import asyncio
import base64
import http.server
import json
import os
import threading
import time
import unittest
from datetime import timedelta
from unittest import mock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from gatedhouse import (
    AuthenticatedSubject,
    Database,
    GatedhouseDatabaseError,
    InMemoryPermissionCache,
    TokenVerificationException,
    TokenVerifierConfig,
)
from gatedhouse import _jwt_verification
from gatedhouse import asgi as gh_asgi
from gatedhouse._jwt_verification import JwtVerification
from gatedhouse._sql import classify
from gatedhouse._web import ForbiddenException, GatedhouseApiFilter, GatedhouseWebFilter

URL = os.environ.get("GATEDHOUSE_TEST_DATABASE_URL", "")
R = TokenVerificationException.Reason


class _Verifier:
    """A Gatedhouse stand-in whose verify_token succeeds or raises."""

    def __init__(self, failure: R | None = None, message: str = "x") -> None:
        self._failure, self._message = failure, message

    def verify_token(self, token: str) -> AuthenticatedSubject:
        if self._failure is not None:
            raise TokenVerificationException(self._failure, self._message)
        return AuthenticatedSubject(id="u", issuer="i", audience="a", issued_at=None,
                                    expires_at=None, token_type="Bearer", claims={})


def _call_wsgi(app, environ: dict) -> tuple[str, dict, bytes]:
    captured: dict = {}

    def start_response(status, headers, exc_info=None):
        captured["status"], captured["headers"] = status, dict(headers)

    body = b"".join(app(environ, start_response))
    return captured["status"], captured["headers"], body


def _ok_app(environ, start_response):
    start_response("200 OK", [])
    return [b"ok"]


class AuthResponseTest(unittest.TestCase):

    def test_bodies_are_byte_identical_to_the_java_sdk(self) -> None:
        status, headers, body = _call_wsgi(GatedhouseApiFilter(_ok_app, _Verifier()), {})
        self.assertEqual("401 Unauthorized", status)
        self.assertEqual("Bearer", headers["WWW-Authenticate"])
        self.assertEqual(b'{"error":"unauthorized","reason":"missing_token",'
                         b'"detail":"Missing or invalid Bearer token"}', body)

    def test_invalid_token_gets_a_stable_reason_and_no_internal_detail(self) -> None:
        f = GatedhouseApiFilter(_ok_app, _Verifier(R.INVALID_SIGNATURE, 'kid "x" from https://idp.internal'))
        status, _, body = _call_wsgi(f, {"HTTP_AUTHORIZATION": "Bearer t"})
        self.assertEqual("401 Unauthorized", status)
        self.assertEqual(b'{"error":"unauthorized","reason":"invalid_signature",'
                         b'"detail":"Token verification failed"}', body)

    def test_identity_provider_outage_is_503_not_401(self) -> None:
        f = GatedhouseApiFilter(_ok_app, _Verifier(R.JWKS_UNAVAILABLE))
        status, headers, body = _call_wsgi(f, {"HTTP_AUTHORIZATION": "Bearer t"})
        self.assertEqual("503 Service Unavailable", status)
        self.assertEqual("30", headers["Retry-After"])
        self.assertNotIn("WWW-Authenticate", headers)
        self.assertEqual(b'{"error":"unavailable","reason":"jwks_unavailable",'
                         b'"detail":"Token verification is temporarily unavailable"}', body)

    def test_bearer_scheme_is_case_insensitive(self) -> None:
        for header in ("bearer t", "BEARER t", "Bearer   t  "):
            status, _, _ = _call_wsgi(GatedhouseApiFilter(_ok_app, _Verifier()),
                                      {"HTTP_AUTHORIZATION": header})
            self.assertEqual("200 OK", status, header)
        status, _, _ = _call_wsgi(GatedhouseApiFilter(_ok_app, _Verifier()),
                                  {"HTTP_AUTHORIZATION": "Bearer   "})
        self.assertEqual("401 Unauthorized", status)

    def test_application_failures_propagate_and_helper_exceptions_keep_their_status(self) -> None:
        def broken(environ, start_response):
            raise RuntimeError("database down")

        with self.assertRaises(RuntimeError):
            _call_wsgi(GatedhouseApiFilter(broken, _Verifier()), {"HTTP_AUTHORIZATION": "Bearer t"})

        def admin_only(environ, start_response):
            raise ForbiddenException('Scope "admin" required')

        status, headers, body = _call_wsgi(GatedhouseApiFilter(admin_only, _Verifier()),
                                           {"HTTP_AUTHORIZATION": "Bearer t"})
        self.assertEqual("403 Forbidden", status)
        self.assertNotIn("WWW-Authenticate", headers)
        self.assertEqual(b'{"error":"forbidden","detail":"Scope \\"admin\\" required"}', body)

    def test_session_filter_keeps_the_session_through_an_outage(self) -> None:
        session = {"access_token": "tok"}
        f = GatedhouseWebFilter(_ok_app, _Verifier(R.JWKS_UNAVAILABLE))
        status, headers, _ = _call_wsgi(f, {"gatedhouse.session": session})
        self.assertEqual("503 Service Unavailable", status)
        self.assertNotIn("Location", headers)
        self.assertEqual({"access_token": "tok"}, session)

        f = GatedhouseWebFilter(_ok_app, _Verifier(R.EXPIRED))
        status, headers, _ = _call_wsgi(f, {"gatedhouse.session": session})
        self.assertEqual("302 Found", status)
        self.assertEqual({}, session)

    def test_asgi_outage_and_application_failures(self) -> None:
        sent: list = []

        async def send(message):
            sent.append(message)

        async def receive():
            return {"type": "http.request"}

        async def ok_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})

        async def broken(scope, receive, send):
            raise RuntimeError("database down")

        scope = {"type": "http", "headers": [(b"authorization", b"bearer t")]}
        asyncio.run(gh_asgi.GatedhouseApiFilter(ok_app, _Verifier(R.JWKS_UNAVAILABLE))(
            dict(scope), receive, send))
        self.assertEqual(503, sent[0]["status"])
        self.assertIn((b"retry-after", b"30"), sent[0]["headers"])

        with self.assertRaises(RuntimeError):
            asyncio.run(gh_asgi.GatedhouseApiFilter(broken, _Verifier())(dict(scope), receive, send))

        sent.clear()
        asyncio.run(gh_asgi.GatedhouseApiFilter(ok_app, _Verifier())(dict(scope), receive, send))
        self.assertEqual(200, sent[0]["status"], "lower-case scheme accepted")


class BoundedCacheTest(unittest.TestCase):

    def test_never_grows_beyond_its_bound_and_keeps_the_newest(self) -> None:
        cache = InMemoryPermissionCache(timedelta(minutes=1), max_entries=100)
        for i in range(5000):
            cache.put("user", f"org-{i}", [])
            self.assertLessEqual(cache.size(), 100)
        self.assertIsNotNone(cache.get("user", "org-4999"))
        self.assertIsNone(cache.get("user", "org-0"), "oldest evicted first")
        self.assertGreater(cache.eviction_count(), 0)

    def test_expired_entries_go_before_live_ones(self) -> None:
        now = [1_000_000.0]
        from datetime import datetime, timezone
        clock = lambda: datetime.fromtimestamp(now[0], tz=timezone.utc)  # noqa: E731
        cache = InMemoryPermissionCache(timedelta(seconds=60), clock, max_entries=10)
        for i in range(5):
            cache.put("old", f"org{i}", [])
        now[0] += 61
        for i in range(5):
            cache.put("live", f"org{i}", [])
        cache.put("one", "more", [])
        for i in range(5):
            self.assertIsNotNone(cache.get("live", f"org{i}"))
        self.assertEqual(6, cache.size())

    def test_rejects_an_empty_bound(self) -> None:
        with self.assertRaises(ValueError):
            InMemoryPermissionCache(max_entries=0)


def _b64(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class _JwksServer:
    """Serves a JWKS (or fails with 500) and counts requests."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = self.key.public_key().public_numbers()
        self.jwks = json.dumps({"keys": [{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
                                          "n": _b64(pub.n), "e": _b64(pub.e)}]}).encode()
        self.fail = False
        self.requests = 0
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                outer.requests += 1
                body = b"boom" if outer.fail else outer.jwks
                self.send_response(500 if outer.fail else 200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.uri = f"http://127.0.0.1:{self.server.server_address[1]}/jwks.json"

    def token(self, kid: str) -> str:
        return jwt.encode({"sub": "u", "iss": "iss", "aud": "aud", "exp": int(time.time()) + 600},
                          self.key, algorithm="RS256", headers={"kid": kid})

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class JwksFetchLimitTest(unittest.TestCase):

    def setUp(self) -> None:
        self.idp = _JwksServer()
        self.verifier = JwtVerification(TokenVerifierConfig(self.idp.uri, "iss", "aud"))

    def tearDown(self) -> None:
        self.idp.close()

    def test_valid_tokens_share_one_fetch(self) -> None:
        for _ in range(50):
            self.assertEqual("u", self.verifier.verify(self.idp.token("k1")).id)
        self.assertEqual(1, self.idp.requests)

    def test_forged_kids_cannot_flood_the_identity_provider(self) -> None:
        self.verifier.verify(self.idp.token("k1"))
        for i in range(50):
            with self.assertRaises(TokenVerificationException) as ctx:
                self.verifier.verify(self.idp.token(f"forged-{i}"))
            self.assertIs(R.UNKNOWN_KEY, ctx.exception.reason)
        self.assertEqual(1, self.idp.requests, "unknown kids within the interval refetched")

    def test_failed_fetches_are_rate_limited_too(self) -> None:
        self.idp.fail = True
        for _ in range(20):
            with self.assertRaises(TokenVerificationException) as ctx:
                self.verifier.verify(self.idp.token("k1"))
            self.assertIs(R.JWKS_UNAVAILABLE, ctx.exception.reason)
        self.assertEqual(1, self.idp.requests)

    def test_keys_expire_so_removed_keys_stop_validating(self) -> None:
        with mock.patch.object(_jwt_verification, "JWKS_CACHE_TTL", 0.2), \
                mock.patch.object(_jwt_verification, "JWKS_MIN_REFRESH_INTERVAL", 0.1):
            self.verifier.verify(self.idp.token("k1"))
            self.idp.jwks = self.idp.jwks.replace(b'"k1"', b'"k2"')   # the IdP rotates k1 out
            time.sleep(0.3)
            with self.assertRaises(TokenVerificationException) as ctx:
                self.verifier.verify(self.idp.token("k1"))
            self.assertIs(R.UNKNOWN_KEY, ctx.exception.reason)
            self.assertEqual(2, self.idp.requests)


@unittest.skipUnless(URL, "set GATEDHOUSE_TEST_DATABASE_URL to run the owned-pool tests")
class OwnedPoolTest(unittest.TestCase):

    def test_statements_are_bounded_and_a_timeout_is_unavailable(self) -> None:
        with Database.from_uri(URL, statement_timeout=0.3) as pool, pool.connection() as conn:
            self.assertEqual("300ms", conn.execute("SHOW statement_timeout").fetchone()[0])
            from psycopg import errors
            with self.assertRaises(errors.QueryCanceled) as ctx:
                conn.execute("SELECT pg_sleep(2)")
            self.assertIs(GatedhouseDatabaseError.Kind.UNAVAILABLE,
                          classify("x", ctx.exception).kind)
            conn.rollback()

    def test_recently_used_connections_skip_the_liveness_round_trip(self) -> None:
        from psycopg_pool import ConnectionPool
        real = ConnectionPool.check_connection
        checks = []

        def counting(conn):
            checks.append(1)
            real(conn)

        with mock.patch.object(ConnectionPool, "check_connection", staticmethod(counting)), \
                Database.from_uri(URL, max_size=1) as pool:
            with pool.connection():
                pass
            after_first = len(checks)
            for _ in range(20):
                with pool.connection() as conn:
                    conn.execute("SELECT 1")
            self.assertEqual(after_first, len(checks), "back-to-back use was pinged")
            time.sleep(PooledDatabaseWindow.value + 0.1)
            with pool.connection():
                pass
            self.assertEqual(after_first + 1, len(checks), "idle connection not checked")


class PooledDatabaseWindow:
    from gatedhouse import PooledDatabase
    value = PooledDatabase.ALIVE_BYPASS_WINDOW


if __name__ == "__main__":
    unittest.main()
