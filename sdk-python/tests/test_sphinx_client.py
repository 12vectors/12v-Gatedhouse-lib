# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Issue #4: every outbound HTTP call is bounded, and Sphinx failures are
typed. Mirrors the Java SphinxClientTest: each test stands up a local server
that misbehaves in one specific way."""

from __future__ import annotations

import base64
import http.server
import json
import socket
import threading
import time
import unittest

from gatedhouse import (
    GatedhouseFactory,
    SphinxClient,
    SphinxError,
    TokenVerificationException,
    TokenVerifierConfig,
)

SHORT = 0.5
Kind = SphinxError.Kind


class _Servers:
    """Misbehaving local servers, closed at test teardown."""

    def __init__(self) -> None:
        self._closers: list = []

    def close(self) -> None:
        for close in self._closers:
            close()

    def _listen(self) -> tuple[socket.socket, list[socket.socket]]:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        held: list[socket.socket] = []

        def close() -> None:
            server.close()
            for s in held:
                s.close()

        self._closers.append(close)
        return server, held

    def black_hole(self) -> str:
        """Accepts connections, then never sends a byte."""
        server, held = self._listen()

        def accept() -> None:
            try:
                while True:
                    held.append(server.accept()[0])  # keep it open, say nothing
            except OSError:
                pass

        threading.Thread(target=accept, daemon=True).start()
        return f"http://127.0.0.1:{server.getsockname()[1]}"

    def stalls_mid_body(self) -> str:
        """Sends a status line and headers promising a body, then stalls."""
        server, held = self._listen()

        def accept() -> None:
            try:
                while True:
                    conn = server.accept()[0]
                    held.append(conn)
                    conn.recv(8192)  # consume the request
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                 b"Content-Length: 100\r\n\r\n{\"access")  # ... and never finishes
            except OSError:
                pass

        threading.Thread(target=accept, daemon=True).start()
        return f"http://127.0.0.1:{server.getsockname()[1]}"

    @staticmethod
    def refusing() -> str:
        """A port with nothing listening on it."""
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return f"http://127.0.0.1:{s.getsockname()[1]}"

    def answering(self, status: int, body: str) -> str:
        """Answers every request with the given status and body."""
        payload = body.encode("utf-8")

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self._closers.append(lambda: (server.shutdown(), server.server_close()))
        return f"http://127.0.0.1:{server.server_address[1]}"


def _client(base_url: str) -> SphinxClient:
    return SphinxClient(base_url, "client", "secret", timeout=SHORT)


def _unverifiable_token_with_kid() -> str:
    """Well-formed RS256 JWT with a kid, so verification must fetch the JWKS."""
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "k1"}).encode())
    payload = b64(json.dumps({"sub": "x", "iss": "https://issuer", "aud": "app",
                              "exp": 4102444800}).encode())
    return f"{header}.{payload}.{b64(bytes(256))}"


class SphinxClientTimeoutTest(unittest.TestCase):

    def setUp(self) -> None:
        self.servers = _Servers()

    def tearDown(self) -> None:
        self.servers.close()

    # ---- timeouts -------------------------------------------------------

    def test_default_timeout_is_ten_seconds(self) -> None:
        self.assertEqual(SphinxClient.DEFAULT_TIMEOUT, 10.0)
        self.assertEqual(SphinxClient("http://x", "c", "s").timeout, 10.0)

    def test_timeout_must_be_positive(self) -> None:
        for bad in (0, -1, None, True, "10"):
            with self.subTest(timeout=bad), self.assertRaises(ValueError):
                SphinxClient("http://x", "c", "s", timeout=bad)  # type: ignore[arg-type]

    def test_unresponsive_token_endpoint_times_out_instead_of_hanging(self) -> None:
        client = _client(self.servers.black_hole())
        start = time.monotonic()
        with self.assertRaises(SphinxError) as ctx:
            client.exchange_code("code", "http://cb")
        elapsed = time.monotonic() - start
        self.assertIs(ctx.exception.kind, Kind.TIMEOUT)
        self.assertIsNone(ctx.exception.status_code)
        self.assertTrue(0.4 <= elapsed < 3, f"timed out after {elapsed:.2f} s")

    def test_unresponsive_introspection_endpoint_times_out(self) -> None:
        with self.assertRaises(SphinxError) as ctx:
            _client(self.servers.black_hole()).introspect("tok")
        self.assertIs(ctx.exception.kind, Kind.TIMEOUT)

    def test_body_that_stalls_midway_times_out(self) -> None:
        client = _client(self.servers.stalls_mid_body())
        start = time.monotonic()
        with self.assertRaises(SphinxError) as ctx:
            client.refresh_token("rt")
        elapsed = time.monotonic() - start
        self.assertIs(ctx.exception.kind, Kind.TIMEOUT)
        self.assertLess(elapsed, 3, f"gave up after {elapsed:.2f} s")

    # ---- other failure kinds -------------------------------------------

    def test_unreachable_endpoint_is_transport(self) -> None:
        with self.assertRaises(SphinxError) as ctx:
            _client(self.servers.refusing()).client_credentials()
        self.assertIs(ctx.exception.kind, Kind.TRANSPORT)

    def test_refused_token_request_is_http_status_with_code_and_body(self) -> None:
        base = self.servers.answering(400, '{"error":"invalid_grant"}')
        with self.assertRaises(SphinxError) as ctx:
            _client(base).exchange_code("used-code", "http://cb")
        self.assertIs(ctx.exception.kind, Kind.HTTP_STATUS)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("invalid_grant", str(ctx.exception))

    def test_non_json_token_response_is_invalid_response(self) -> None:
        with self.assertRaises(SphinxError) as ctx:
            _client(self.servers.answering(200, "<html>proxy error</html>")).refresh_token("rt")
        self.assertIs(ctx.exception.kind, Kind.INVALID_RESPONSE)

    def test_still_a_runtime_error_for_existing_handlers(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            _client(self.servers.refusing()).refresh_token("rt")
        self.assertIsInstance(ctx.exception, SphinxError)

    # ---- unchanged success paths ----------------------------------------

    def test_successful_token_response_is_parsed(self) -> None:
        base = self.servers.answering(
            200, '{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":3600}')
        t = _client(base).exchange_code("code", "http://cb")
        self.assertEqual((t.access_token, t.refresh_token, t.expires_in), ("at", "rt", 3600))

    def test_introspection_still_parses_the_body_of_a_non_success_status(self) -> None:
        result = _client(self.servers.answering(401, '{"active":false}')).introspect("tok")
        self.assertIs(result["active"], False)

    # ---- JWKS -----------------------------------------------------------

    def test_default_jwks_timeout_is_five_seconds(self) -> None:
        self.assertEqual(TokenVerifierConfig("http://x/jwks", "i", "a").jwks_timeout, 5.0)
        self.assertEqual(TokenVerifierConfig.DEFAULT_JWKS_TIMEOUT, 5.0)

    def test_unresponsive_jwks_endpoint_fails_fast_as_jwks_unavailable(self) -> None:
        config = TokenVerifierConfig(self.servers.black_hole() + "/jwks.json",
                                     "https://issuer", "app", jwks_timeout=SHORT)
        gh = GatedhouseFactory.create_just_token_verifier(config)
        start = time.monotonic()
        with self.assertRaises(TokenVerificationException) as ctx:
            gh.verify_token(_unverifiable_token_with_kid())
        elapsed = time.monotonic() - start
        self.assertIs(ctx.exception.reason, TokenVerificationException.Reason.JWKS_UNAVAILABLE)
        self.assertLess(elapsed, 3, f"JWKS fetch gave up after {elapsed:.2f} s")


if __name__ == "__main__":
    unittest.main()
