"""HTTP client wrapper to orchestrate Sphinx SSO OAuth 2.0 endpoints.

Stdlib-only (``urllib``), mirroring the Java ``SphinxClient`` which uses
``java.net.http.HttpClient``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib import error as _urlerror
from urllib import parse as _urlparse
from urllib import request as _urlrequest


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
    """HTTP client wrapper to orchestrate Sphinx SSO OAuth 2.0 endpoints."""

    def __init__(self, base_url: str, client_id: str, client_secret: str) -> None:
        self._base_url = base_url[:-1] if base_url.endswith("/") else base_url
        self._client_id = client_id
        self._client_secret = client_secret

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
        try:
            body = self._post_form("/api/sphinx/v1/oauth/introspect", {"token": token})
            return json.loads(body)
        except _urlerror.HTTPError as e:
            # The introspection endpoint conveys inactive/invalid tokens in
            # the body; parse it regardless of status.
            try:
                return json.loads(e.read().decode("utf-8", errors="replace"))
            except ValueError as parse_err:
                raise RuntimeError("Introspection failed") from parse_err
        except (OSError, ValueError) as e:
            raise RuntimeError("Introspection failed") from e

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

    def _post_form(self, path: str, params: dict[str, str]) -> str:
        req = _urlrequest.Request(
            self._base_url + path,
            data=_urlparse.urlencode(params).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with _urlrequest.urlopen(req) as resp:
            return resp.read().decode("utf-8")

    def _post_token(self, params: dict[str, str]) -> TokenResponse:
        try:
            body = self._post_form("/api/sphinx/v1/oauth/token", params)
        except _urlerror.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Token request failed ({e.code}): {detail}") from e
        except OSError as e:
            raise RuntimeError("Token request failed") from e
        try:
            payload = json.loads(body)
        except ValueError as e:
            raise RuntimeError("Token request failed") from e
        expires_in = payload.get("expires_in")
        return TokenResponse(
            access_token=payload.get("access_token"),
            refresh_token=payload.get("refresh_token"),
            token_type=payload.get("token_type"),
            expires_in=int(expires_in) if expires_in is not None else 0,
            scope=payload.get("scope"),
            issued_token_type=payload.get("issued_token_type"),
        )
