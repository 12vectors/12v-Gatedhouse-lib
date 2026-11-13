# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""``SphinxClient.create_person`` against a stub Sphinx (wire contract
APP-PROV-1). Mirrors the Java ``SphinxProvisioningTest``."""

from __future__ import annotations

import http.server
import json
import socket
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from gatedhouse import ProvisionedPerson, SphinxClient, SphinxError

K = SphinxError.Kind
TOKEN_PATH = "/api/sphinx/v1/oauth/token"
PERSONS_PATH = "/api/sphinx/v1/persons"

CREATED = {
    "data": {"id": "per_01J", "email": "jane@cicero-client.com", "email_verified": False,
             "display_name": "Jane Doe", "phone": "+35799123456", "phone_verified": False,
             "allow_auto_link": True, "status": "pending_verification",
             "failed_login_attempts": 0, "last_login_at": None, "last_login_method": None,
             "created_at": "2026-11-12T10:00:00Z"},
    "meta": {"password_reset_sent": True},
}


class _StubSphinx:
    """Records requests; answers each path with the configured response."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.lock = threading.Lock()
        self.tokens_issued = 0
        self.token_status, self.token_body = 200, None   # None: a fresh token each time
        self.expires_in = 3600
        self.token_delay = 0.0
        self.persons_status, self.persons_body = 201, json.dumps(CREATED)
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
                with outer.lock:
                    outer.requests.append({"path": self.path, "headers": dict(self.headers),
                                           "body": body})
                if self.path == TOKEN_PATH:
                    time.sleep(outer.token_delay)
                    with outer.lock:
                        outer.tokens_issued += 1
                        n = outer.tokens_issued
                    status = outer.token_status
                    answer = outer.token_body or json.dumps(
                        {"access_token": f"tok-{n}", "token_type": "Bearer",
                         "expires_in": outer.expires_in, "scope": "persons:create"})
                else:
                    status, answer = outer.persons_status, outer.persons_body
                raw = answer.encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def to(self, path: str) -> list[dict]:
        with self.lock:
            return [r for r in self.requests if r["path"] == path]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class CreatePersonTest(unittest.TestCase):

    def setUp(self) -> None:
        self.sphinx = _StubSphinx()
        self.now = 1000.0
        self.client = SphinxClient(self.sphinx.url, "sph_app", "sps_secret", timeout=2)
        self.client._monotonic = lambda: self.now

    def tearDown(self) -> None:
        self.sphinx.close()

    def refusal(self, email: str = "jane@cicero-client.com") -> SphinxError:
        with self.assertRaises(SphinxError) as ctx:
            self.client.create_person(email)
        return ctx.exception

    # ---- happy path ---------------------------------------------------------

    def test_mints_an_app_token_then_posts_the_person_as_json(self) -> None:
        p = self.client.create_person("jane@cicero-client.com", display_name="Jane Doe",
                                      phone="+357 99 123456", email_verified=False,
                                      allow_auto_link=True)
        token = self.sphinx.to(TOKEN_PATH)[0]
        self.assertEqual("grant_type=client_credentials&client_id=sph_app"
                         "&client_secret=sps_secret&scope=persons%3Acreate", token["body"])
        post = self.sphinx.to(PERSONS_PATH)[0]
        self.assertEqual("Bearer tok-1", post["headers"]["Authorization"])
        self.assertEqual("application/json", post["headers"]["Content-Type"])
        self.assertEqual("application/json", post["headers"]["Accept"])
        self.assertEqual({"email": "jane@cicero-client.com", "display_name": "Jane Doe",
                          "phone": "+357 99 123456", "email_verified": False,
                          "allow_auto_link": True}, json.loads(post["body"]))
        self.assertEqual(ProvisionedPerson(
            id="per_01J", email="jane@cicero-client.com", email_verified=False,
            display_name="Jane Doe", phone="+35799123456", phone_verified=False,
            allow_auto_link=True, status="pending_verification",
            created_at=datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc),
            password_reset_sent=True), p)

    def test_unset_optional_fields_are_omitted_not_null(self) -> None:
        self.client.create_person("jane@cicero-client.com")
        self.assertEqual({"email": "jane@cicero-client.com"},
                         json.loads(self.sphinx.to(PERSONS_PATH)[0]["body"]))

    def test_null_display_name_and_phone_are_none(self) -> None:
        created = json.loads(json.dumps(CREATED))
        created["data"].update(display_name=None, phone=None)
        self.sphinx.persons_body = json.dumps(created)
        p = self.client.create_person("jane@cicero-client.com")
        self.assertIsNone(p.display_name)
        self.assertIsNone(p.phone)

    def test_created_at_accepts_what_java_instant_parse_accepts(self) -> None:
        for text, expected in (
                ("2026-11-12T10:00:00.123456789Z",
                 datetime(2026, 11, 12, 10, 0, 0, 123456, tzinfo=timezone.utc)),
                ("2026-11-12T12:00:00+02:00", datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc))):
            created = json.loads(json.dumps(CREATED))
            created["data"]["created_at"] = text
            self.sphinx.persons_body = json.dumps(created)
            self.assertEqual(expected, self.client.create_person("j@x.com").created_at, text)

    # ---- token caching ------------------------------------------------------

    def test_second_call_reuses_the_token_so_makes_one_request(self) -> None:
        self.client.create_person("jane@cicero-client.com")
        before = len(self.sphinx.requests)
        self.client.create_person("jane@cicero-client.com")
        self.assertEqual(1, len(self.sphinx.requests) - before, "only the POST")
        self.assertEqual(1, len(self.sphinx.to(TOKEN_PATH)))

    def test_token_is_replaced_sixty_seconds_before_it_expires(self) -> None:
        self.client.create_person("jane@cicero-client.com")
        self.now += 3600 - 60 - 0.001
        self.client.create_person("jane@cicero-client.com")
        self.assertEqual(1, len(self.sphinx.to(TOKEN_PATH)), "still inside the usable window")
        self.now += 0.001
        self.client.create_person("jane@cicero-client.com")
        self.assertEqual(2, len(self.sphinx.to(TOKEN_PATH)))
        self.assertEqual("Bearer tok-2", self.sphinx.to(PERSONS_PATH)[2]["headers"]["Authorization"])

    def test_a_token_too_short_lived_for_the_margin_is_used_once(self) -> None:
        self.sphinx.expires_in = 60
        self.client.create_person("jane@cicero-client.com")
        self.client.create_person("jane@cicero-client.com")
        self.assertEqual(2, len(self.sphinx.to(TOKEN_PATH)))

    def test_concurrent_callers_share_one_mint(self) -> None:
        self.sphinx.token_delay = 0.3
        go = threading.Event()

        def call() -> ProvisionedPerson:
            go.wait()
            return self.client.create_person("jane@cicero-client.com")

        with ThreadPoolExecutor(8) as pool:
            futures = [pool.submit(call) for _ in range(8)]
            go.set()
            for f in futures:
                f.result(timeout=10)
        self.assertEqual(1, len(self.sphinx.to(TOKEN_PATH)))
        self.assertEqual(8, len(self.sphinx.to(PERSONS_PATH)))

    # ---- edge cases (spec table) ----------------------------------------------

    def test_app_not_privileged_is_unauthorized_client_and_nothing_is_posted(self) -> None:
        self.sphinx.token_status = 400
        self.sphinx.token_body = '{"error":"unauthorized_client","detail":"not privileged"}'
        e = self.refusal()
        self.assertEqual((K.HTTP_STATUS, 400, "unauthorized_client"),
                         (e.kind, e.status_code, e.error_code))
        self.assertEqual([], self.sphinx.to(PERSONS_PATH))

    def test_wrong_secret_or_revoked_app_is_invalid_client(self) -> None:
        self.sphinx.token_status = 401
        self.sphinx.token_body = '{"error":"invalid_client","detail":"Invalid client credentials"}'
        e = self.refusal()
        self.assertEqual((401, "invalid_client"), (e.status_code, e.error_code))

    def test_forbidden_keeps_the_cached_token(self) -> None:
        self.client.create_person("jane@cicero-client.com")
        self.sphinx.persons_status = 403
        self.sphinx.persons_body = '{"error":"forbidden","detail":"domain not accepted"}'
        e = self.refusal()
        self.assertEqual((403, "forbidden"), (e.status_code, e.error_code))
        self.sphinx.persons_status, self.sphinx.persons_body = 201, json.dumps(CREATED)
        self.client.create_person("jane@cicero-client.com")
        self.assertEqual(1, len(self.sphinx.to(TOKEN_PATH)), "403 must not drop a valid token")

    def test_unauthorized_drops_the_cached_token_without_retrying(self) -> None:
        self.client.create_person("jane@cicero-client.com")
        self.sphinx.persons_status = 401
        self.sphinx.persons_body = '{"error":"unauthorized","detail":"Invalid or expired token"}'
        self.assertEqual(401, self.refusal().status_code)
        self.assertEqual(2, len(self.sphinx.to(PERSONS_PATH)), "no automatic retry")
        self.assertEqual(1, len(self.sphinx.to(TOKEN_PATH)), "no automatic re-mint")
        self.sphinx.persons_status, self.sphinx.persons_body = 201, json.dumps(CREATED)
        self.client.create_person("jane@cicero-client.com")
        self.assertEqual(2, len(self.sphinx.to(TOKEN_PATH)), "the next call mints a fresh token")
        self.assertEqual("Bearer tok-2", self.sphinx.to(PERSONS_PATH)[2]["headers"]["Authorization"])

    def test_existing_email_is_conflict(self) -> None:
        self.sphinx.persons_status = 409
        self.sphinx.persons_body = '{"error":"conflict","detail":"exists"}'
        e = self.refusal()
        self.assertEqual((409, "conflict"), (e.status_code, e.error_code))

    def test_invalid_email_or_phone_is_bad_request_with_its_code(self) -> None:
        for code in ("invalid_email", "invalid_phone", "bad_request"):
            self.sphinx.persons_status = 400
            self.sphinx.persons_body = json.dumps({"error": code, "detail": "x"})
            e = self.refusal()
            self.assertEqual((400, code), (e.status_code, e.error_code))

    def test_missing_or_blank_email_is_rejected_before_any_request(self) -> None:
        for email in (None, "", "   ", 42):
            with self.assertRaises(ValueError):
                self.client.create_person(email)  # type: ignore[arg-type]
        self.assertEqual([], self.sphinx.requests)

    def test_non_json_error_body_has_no_error_code(self) -> None:
        self.sphinx.persons_status, self.sphinx.persons_body = 502, "<html>Bad Gateway</html>"
        e = self.refusal()
        self.assertEqual((502, None), (e.status_code, e.error_code))

    def test_malformed_success_body_is_invalid_response(self) -> None:
        def variant(**data) -> str:
            created = json.loads(json.dumps(CREATED))
            created["data"].update(data)
            return json.dumps(created)

        for body in ("not json", "{}", '{"data":{},"meta":{}}',
                     variant(created_at="yesterday"), variant(email_verified="no"),
                     json.dumps({"data": CREATED["data"]})):
            self.sphinx.persons_body = body
            self.assertIs(K.INVALID_RESPONSE, self.refusal().kind, body)

    def test_token_response_without_access_token_is_invalid_response(self) -> None:
        self.sphinx.token_body = '{"token_type":"Bearer","expires_in":3600}'
        self.assertIs(K.INVALID_RESPONSE, self.refusal().kind)
        self.assertEqual([], self.sphinx.to(PERSONS_PATH))

    def test_unresponsive_sphinx_times_out(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        held: list[socket.socket] = []

        def accept() -> None:
            try:
                while True:
                    held.append(listener.accept()[0])
            except OSError:
                pass

        threading.Thread(target=accept, daemon=True).start()
        try:
            client = SphinxClient(f"http://127.0.0.1:{listener.getsockname()[1]}",
                                  "sph_app", "sps_secret", timeout=0.3)
            with self.assertRaises(SphinxError) as ctx:
                client.create_person("jane@cicero-client.com")
            self.assertIs(K.TIMEOUT, ctx.exception.kind)
        finally:
            listener.close()
            for s in held:
                s.close()

    def test_unreachable_sphinx_is_transport(self) -> None:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        client = SphinxClient(f"http://127.0.0.1:{port}", "sph_app", "sps_secret", timeout=0.5)
        with self.assertRaises(SphinxError) as ctx:
            client.create_person("jane@cicero-client.com")
        self.assertIs(K.TRANSPORT, ctx.exception.kind)

    def test_existing_token_calls_now_carry_the_error_code_too(self) -> None:
        self.sphinx.token_status = 400
        self.sphinx.token_body = '{"error":"invalid_grant","detail":"code already used"}'
        with self.assertRaises(SphinxError) as ctx:
            self.client.exchange_code("code", "http://cb")
        self.assertEqual("invalid_grant", ctx.exception.error_code)
        self.assertNotIn("sps_secret", str(ctx.exception), "the secret is never in a message")


if __name__ == "__main__":
    unittest.main()
