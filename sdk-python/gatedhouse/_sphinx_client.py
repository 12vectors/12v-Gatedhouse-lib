"""Client for Sphinx SSO's OAuth 2.0 endpoints (mirrors Java ``SphinxClient``).

Uses only the standard library (``urllib``) — no third-party HTTP dependency.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from ._secure_urls import require_https_or_loopback

# Upper bound on a single token/introspection round-trip (connect + read),
# so an unresponsive Sphinx cannot hang the caller indefinitely (review M2).
_REQUEST_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class TokenResponse:
    """Parsed OAuth token-endpoint response."""

    access_token: str | None
    refresh_token: str | None
    token_type: str | None
    expires_in: int
    scope: str | None
    issued_token_type: str | None


class SphinxClient:
    """Thin wrapper over the Sphinx OAuth 2.0 token/introspection endpoints.

    Prefer :class:`LoginFlow` for the browser login flow; use ``SphinxClient``
    directly for machine-to-machine grants.
    """

    def __init__(self, base_url: str, client_id: str, client_secret: str) -> None:
        base = base_url[:-1] if base_url.endswith("/") else base_url
        # This client transmits the client_secret and receives tokens — refuse
        # a non-TLS base URL (review M5).
        require_https_or_loopback(base, "Sphinx baseUrl")
        self._base_url = base
        self._client_id = client_id
        self._client_secret = client_secret

    # ---- grants -----------------------------------------------------------

    def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> TokenResponse:
        """Exchange an authorization code for tokens, sending the PKCE
        ``code_verifier`` when present (RFC 7636)."""
        params = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if code_verifier is not None:
            params["code_verifier"] = code_verifier
        return self._post_token(params)

    def client_credentials(self, scope: str | None = None) -> TokenResponse:
        params = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if scope is not None:
            params["scope"] = scope
        return self._post_token(params)

    def token_exchange(
        self,
        subject_token: str,
        actor_token: str,
        delegation_id: str,
        scope: str | None = None,
    ) -> TokenResponse:
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
        params = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        return self._post_token(params)

    def introspect(self, token: str) -> dict:
        """Introspect an access token. Fails closed on a non-200 so an error /
        proxy body is never handed back as if it were a valid result (review L1)."""
        body = urllib.parse.urlencode({"token": token})
        status, text = self._post(
            self._base_url + "/api/sphinx/v1/oauth/token/introspect", body
        )
        if status != 200:
            raise RuntimeError(
                f"Introspection failed ({status}): {_oauth_error(text)}"
            )
        return json.loads(text)

    # ---- redirect URL builders -------------------------------------------

    def login_url(self, app_shortcode: str) -> str:
        return self._base_url + "/login?app=" + urllib.parse.quote(app_shortcode, safe="")

    def federated_login_url(
        self, sso_connection_id: str, app_shortcode: str | None = None
    ) -> str:
        url = (
            self._base_url
            + "/api/sphinx/v1/auth/federated/"
            + urllib.parse.quote(sso_connection_id, safe="")
        )
        if app_shortcode is not None:
            url += "?app=" + urllib.parse.quote(app_shortcode, safe="")
        return url

    # ---- internals --------------------------------------------------------

    def _post_token(self, params: dict) -> TokenResponse:
        body = urllib.parse.urlencode(params)
        status, text = self._post(self._base_url + "/api/sphinx/v1/oauth/token", body)
        if status != 200:
            # Surface only the standardized OAuth error code, never the raw body
            # — it may carry tokens or internal diagnostics (review L9).
            raise RuntimeError(
                f"Token request failed ({status}): {_oauth_error(text)}"
            )
        data = json.loads(text)
        expires_in = data.get("expires_in")
        return TokenResponse(
            access_token=data.get("access_token"),
            refresh_token=data.get("refresh_token"),
            token_type=data.get("token_type"),
            expires_in=int(expires_in) if isinstance(expires_in, (int, float)) else 0,
            scope=data.get("scope"),
            issued_token_type=data.get("issued_token_type"),
        )

    @staticmethod
    def _post(url: str, body: str) -> tuple[int, str]:
        req = urllib.request.Request(
            url,
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT_SECONDS) as resp:
                return resp.status, resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            # Non-2xx responses arrive here; return status + body for the caller
            # to map (mirrors Java reading resp.statusCode()/resp.body()).
            return e.code, e.read().decode("utf-8", "replace")


def _oauth_error(body: str) -> str:
    """Extract only the short, standardized OAuth ``error`` code (never tokens)."""
    try:
        err = json.loads(body).get("error")
        return err if isinstance(err, str) else "unknown_error"
    except (ValueError, AttributeError):
        return "unparseable_error"
