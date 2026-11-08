# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""HTTP client wrapper to orchestrate Sphinx SSO OAuth 2.0 endpoints.

Stdlib-only (``urllib``), mirroring the Java ``SphinxClient`` which uses
``java.net.http.HttpClient``.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Any
from urllib import error as _urlerror
from urllib import parse as _urlparse
from urllib import request as _urlrequest

from ._exceptions import SphinxError

_Kind = SphinxError.Kind

#: The timeout used when none is given, in seconds.
DEFAULT_TIMEOUT = 10.0


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
        """POST a form; return ``(status, body)`` for any HTTP answer, and
        raise :class:`SphinxError` when there is none."""
        req = _urlrequest.Request(
            self._base_url + path,
            data=_urlparse.urlencode(params).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
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
            raise SphinxError(_Kind.HTTP_STATUS,
                              f"Token request failed ({status}): {body}",
                              status_code=status)
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
