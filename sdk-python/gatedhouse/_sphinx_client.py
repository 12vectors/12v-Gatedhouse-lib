# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""HTTP client wrapper to orchestrate Sphinx SSO OAuth 2.0 endpoints.

Stdlib-only (``urllib``), mirroring the Java ``SphinxClient`` which uses
``java.net.http.HttpClient``.
"""

from __future__ import annotations

import json
import re
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib import error as _urlerror
from urllib import parse as _urlparse
from urllib import request as _urlrequest

from ._exceptions import SphinxError

_Kind = SphinxError.Kind

#: The timeout used when none is given, in seconds.
DEFAULT_TIMEOUT = 10.0

#: The scope of the app token ``create_person`` uses.
PROVISIONING_SCOPE = "persons:create"

#: A cached app token is replaced this many seconds before it expires.
TOKEN_EXPIRY_MARGIN = 60


@dataclass(frozen=True, slots=True)
class ProvisionedPerson:
    """A person created by :meth:`SphinxClient.create_person`, as Sphinx
    reports it. ``id`` is Sphinx's person id (``per_…``); ``status`` is e.g.
    ``pending_verification`` until the person sets a password;
    ``password_reset_sent`` says whether Sphinx emailed the set-password link
    (if not, the person can use "Forgot password")."""

    id: str
    email: str
    email_verified: bool
    display_name: str | None
    phone: str | None
    phone_verified: bool
    allow_auto_link: bool
    status: str
    created_at: datetime
    password_reset_sent: bool


@dataclass(frozen=True, slots=True)
class _AppToken:
    value: str
    expires_at: float   # on the client's monotonic clock


@dataclass(frozen=True, slots=True)
class TokenResponse:
    """Parsed body of a successful Sphinx token-endpoint response."""

    access_token: str | None
    refresh_token: str | None
    token_type: str | None
    expires_in: int
    scope: str | None
    issued_token_type: str | None


class SphinxClient:
    """HTTP client wrapper to orchestrate Sphinx SSO OAuth 2.0 endpoints.

    Every call is bounded: no network wait (connecting, or waiting for data)
    exceeds ``timeout`` seconds (default :data:`DEFAULT_TIMEOUT`). Failures
    raise :class:`SphinxError`, whose ``kind`` tells a timeout or an
    unreachable IdP apart from a refused request. The client never retries.
    """

    DEFAULT_TIMEOUT = DEFAULT_TIMEOUT

    def __init__(self, base_url: str, client_id: str, client_secret: str,
                 *, timeout: float = DEFAULT_TIMEOUT) -> None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not timeout > 0:
            raise ValueError(f"timeout must be a positive number of seconds, got {timeout!r}")
        self._base_url = base_url[:-1] if base_url.endswith("/") else base_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = float(timeout)
        self._monotonic = time.monotonic   # replaced in tests
        self._app_token_lock = threading.Lock()
        self._app_token: _AppToken | None = None

    @property
    def timeout(self) -> float:
        """The longest any single network wait may take, in seconds."""
        return self._timeout

    def exchange_code(self, code: str, redirect_uri: str) -> TokenResponse:
        """Exchanges an authorization code for tokens."""
        return self._post_token({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        })

    def client_credentials(self, scope: str | None = None) -> TokenResponse:
        """Requests tokens via client credentials grant."""
        params = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if scope is not None:
            params["scope"] = scope
        return self._post_token(params)

    def token_exchange(self, subject_token: str, actor_token: str,
                       delegation_id: str, scope: str | None = None) -> TokenResponse:
        """Performs an OAuth 2.0 Token Exchange."""
        params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "actor_token": actor_token,
            "delegation_id": delegation_id,
        }
        if scope is not None:
            params["scope"] = scope
        return self._post_token(params)

    def refresh_token(self, refresh_token: str) -> TokenResponse:
        """Refreshes an access token using a refresh token."""
        return self._post_token({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        })

    def introspect(self, token: str) -> dict[str, Any]:
        """Introspects an access token."""
        _, body = self._post_form(
            "/api/sphinx/v1/oauth/introspect", {"token": token}, "Introspection")
        # The introspection endpoint conveys inactive or invalid tokens in
        # the body, so the body is parsed whatever the status.
        return _parse_object(body, "Introspection")

    def create_person(self, email: str, *, display_name: str | None = None,
                      phone: str | None = None, email_verified: bool | None = None,
                      allow_auto_link: bool | None = None) -> ProvisionedPerson:
        """Creates a person in Sphinx on behalf of this app. The app must be
        marked "Can provision users" by a Sphinx admin.

        ``email`` is required. Optional fields left as ``None`` are omitted
        from the request, so Sphinx applies its default: ``email_verified``
        false (``True`` means the app vouches for the address and the account
        is active at once), ``allow_auto_link`` true. ``phone`` is E.164
        (spaces and dashes allowed) and is stored unverified.

        Mints an app token (``client_credentials`` with scope
        ``persons:create``) and caches it in this instance until
        :data:`TOKEN_EXPIRY_MARGIN` seconds before it expires, so later calls
        make one request. Thread-safe; concurrent callers share one mint. A
        401 from Sphinx drops the cached token (the next call mints a new
        one); a 403 keeps it. Never retries.

        Raises ``ValueError`` for a missing or blank email, before any
        request; otherwise :class:`SphinxError`: ``HTTP_STATUS`` with
        ``error_code`` e.g. ``unauthorized_client`` (app not privileged),
        ``conflict`` (email exists), ``forbidden`` (domain not accepted, or
        an admin domain), ``invalid_email``, ``invalid_phone``; ``TIMEOUT`` /
        ``TRANSPORT``; or ``INVALID_RESPONSE``. After a timeout or
        ``INVALID_RESPONSE`` the person may exist: a repeated call then
        answers ``conflict``.
        """
        if not isinstance(email, str) or not email.strip():
            raise ValueError("email is required")
        payload: dict[str, Any] = {"email": email}
        for key, value in (("display_name", display_name), ("phone", phone),
                           ("email_verified", email_verified),
                           ("allow_auto_link", allow_auto_link)):
            if value is not None:
                payload[key] = value
        token = self._get_app_token()
        req = _urlrequest.Request(
            self._base_url + "/api/sphinx/v1/persons",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {token.value}",
                     "Content-Type": "application/json",
                     "Accept": "application/json"},
            method="POST",
        )
        status, body = self._send(req, "Person creation")
        if status == 401:
            self._drop_app_token(token)
        if status != 201:
            raise _refused("Person creation", status, body)
        return _parse_provisioned_person(_parse_object(body, "Person creation"))

    def _get_app_token(self) -> _AppToken:
        """The cached app token, or a new one. At most one mint at a time."""
        cached = self._app_token
        if cached is not None and self._monotonic() < cached.expires_at:
            return cached
        with self._app_token_lock:
            cached = self._app_token
            now = self._monotonic()
            if cached is not None and now < cached.expires_at:
                return cached   # another thread minted it while we waited
            minted = self.client_credentials(PROVISIONING_SCOPE)
            if not isinstance(minted.access_token, str) or not minted.access_token:
                raise SphinxError(_Kind.INVALID_RESPONSE,
                                  "Token request returned no access_token")
            usable = minted.expires_in - TOKEN_EXPIRY_MARGIN
            token = _AppToken(minted.access_token, now + max(usable, 0))
            # A token too short-lived to outlast the margin is used once, not cached.
            self._app_token = token if usable > 0 else None
            return token

    def _drop_app_token(self, rejected: _AppToken) -> None:
        """Forgets ``rejected`` unless another thread has replaced it already."""
        with self._app_token_lock:
            if self._app_token is rejected:
                self._app_token = None

    def login_url(self, app_shortcode: str) -> str:
        """Builds a redirect URL to the standard Sphinx login page."""
        return f"{self._base_url}/login?app={_urlparse.quote_plus(app_shortcode)}"

    def federated_login_url(self, sso_connection_id: str,
                            app_shortcode: str | None = None) -> str:
        """Builds a redirect URL to a federated Sphinx login provider."""
        url = (f"{self._base_url}/api/sphinx/v1/auth/federated/"
               f"{_urlparse.quote_plus(sso_connection_id)}")
        if app_shortcode is not None:
            url += f"?app={_urlparse.quote_plus(app_shortcode)}"
        return url

    # ---- internals ---------------------------------------------------------

    def _post_form(self, path: str, params: dict[str, str],
                   op: str) -> tuple[int, str]:
        """POST a form; see :meth:`_send`."""
        req = _urlrequest.Request(
            self._base_url + path,
            data=_urlparse.urlencode(params).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        return self._send(req, op)

    def _send(self, req: _urlrequest.Request, op: str) -> tuple[int, str]:
        """Send a request; return ``(status, body)`` for any HTTP answer, and
        raise :class:`SphinxError` when there is none."""
        try:
            # urlopen's timeout bounds connecting and every read.
            with _urlrequest.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read()
                status = resp.status
        except _urlerror.HTTPError as e:  # an HTTP answer, just not 2xx
            try:
                return e.code, e.read().decode("utf-8", errors="replace")
            except (TimeoutError, socket.timeout) as read_err:
                raise self._timed_out(op) from read_err
        except (TimeoutError, socket.timeout) as e:  # timed out reading
            raise self._timed_out(op) from e
        except _urlerror.URLError as e:  # urllib wraps connect failures
            if isinstance(e.reason, (TimeoutError, socket.timeout)):
                raise self._timed_out(op) from e
            raise SphinxError(_Kind.TRANSPORT, f"{op} failed: {e.reason}") from e
        except OSError as e:  # reset mid-response, etc.
            raise SphinxError(_Kind.TRANSPORT, f"{op} failed: {e}") from e
        try:
            return status, raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise SphinxError(_Kind.INVALID_RESPONSE,
                              f"{op} returned a response that is not UTF-8") from e

    def _timed_out(self, op: str) -> SphinxError:
        return SphinxError(_Kind.TIMEOUT, f"{op} timed out (timeout {self._timeout:g} s)")

    def _post_token(self, params: dict[str, str]) -> TokenResponse:
        status, body = self._post_form(
            "/api/sphinx/v1/oauth/token", params, "Token request")
        if status != 200:
            raise _refused("Token request", status, body)
        payload = _parse_object(body, "Token request")
        expires_in = payload.get("expires_in")
        try:
            expires_in_seconds = int(expires_in) if expires_in is not None else 0
        except (TypeError, ValueError) as e:
            raise SphinxError(_Kind.INVALID_RESPONSE,
                              "Token request returned a non-numeric expires_in") from e
        return TokenResponse(
            access_token=payload.get("access_token"),
            refresh_token=payload.get("refresh_token"),
            token_type=payload.get("token_type"),
            expires_in=expires_in_seconds,
            scope=payload.get("scope"),
            issued_token_type=payload.get("issued_token_type"),
        )


def _refused(op: str, status: int, body: str) -> SphinxError:
    """An ``HTTP_STATUS`` error for an unsuccessful answer, with Sphinx's error code."""
    return SphinxError(_Kind.HTTP_STATUS, f"{op} failed ({status}): {body}",
                       status_code=status, error_code=_error_code_of(body))


def _error_code_of(body: str) -> str | None:
    """The ``error`` field of a JSON error body, or ``None`` for any other body."""
    try:
        payload = json.loads(body)
    except ValueError:
        return None
    code = payload.get("error") if isinstance(payload, dict) else None
    return code if isinstance(code, str) else None


def _parse_provisioned_person(payload: dict[str, Any]) -> ProvisionedPerson:
    data, meta = payload.get("data"), payload.get("meta")
    if not isinstance(data, dict) or not isinstance(meta, dict):
        raise _invalid("Person creation returned no data or meta object")
    return ProvisionedPerson(
        id=_required(data, "id", str),
        email=_required(data, "email", str),
        email_verified=_required(data, "email_verified", bool),
        display_name=_nullable_str(data, "display_name"),
        phone=_nullable_str(data, "phone"),
        phone_verified=_required(data, "phone_verified", bool),
        allow_auto_link=_required(data, "allow_auto_link", bool),
        status=_required(data, "status", str),
        created_at=_parse_instant(_required(data, "created_at", str)),
        password_reset_sent=_required(meta, "password_reset_sent", bool),
    )


def _required(data: dict[str, Any], name: str, kind: type) -> Any:
    value = data.get(name)
    if not isinstance(value, kind):
        raise _invalid(f"Person creation returned no {kind.__name__} {name}")
    return value


def _nullable_str(data: dict[str, Any], name: str) -> str | None:
    value = data.get(name)
    if value is not None and not isinstance(value, str):
        raise _invalid(f"Person creation returned a non-string {name}")
    return value


# An RFC 3339 instant, as Java's Instant.parse accepts it: 0-9 fractional
# digits and "Z" or an offset. Python 3.10's fromisoformat takes neither "Z"
# nor more than 6 digits, so the text is normalised first.
_INSTANT = re.compile(
    r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)")


def _parse_instant(text: str) -> datetime:
    match = _INSTANT.fullmatch(text)
    if match is None:
        raise _invalid("Person creation returned an invalid created_at")
    seconds, fraction, offset = match.groups()
    micros = (fraction or "").ljust(6, "0")[:6]
    try:
        parsed = datetime.fromisoformat(
            f"{seconds}.{micros}{'+00:00' if offset == 'Z' else offset}")
    except ValueError as e:
        raise _invalid("Person creation returned an invalid created_at") from e
    return parsed.astimezone(timezone.utc)


def _invalid(message: str) -> SphinxError:
    return SphinxError(_Kind.INVALID_RESPONSE, message)


def _parse_object(body: str, op: str) -> dict[str, Any]:
    try:
        payload = json.loads(body)
    except ValueError as e:
        raise SphinxError(_Kind.INVALID_RESPONSE,
                          f"{op} returned a response that is not JSON") from e
    if not isinstance(payload, dict):
        raise SphinxError(_Kind.INVALID_RESPONSE,
                          f"{op} returned JSON that is not an object")
    return payload
