"""Login-CSRF-safe hosted-login flow for Sphinx (mirrors Java ``LoginFlow``).

Binds the authorization code to the browser that started the flow using **PKCE**
(not ``state``): ``begin_login`` mints a PKCE ``code_verifier``, stashes it in a
signed cookie value bound to that browser, and returns the ``/oauth/authorize``
URL; ``complete_login`` requires that cookie and redeems the code *with* the
verifier, so a code minted for a different browser's flow is rejected by Sphinx
before the app adopts any identity.

Framework-agnostic: unlike the Java SDK (which reads/writes servlet cookies
directly), this returns cookie *values* for the host to set/read with its own
web framework. Set the ``gh_login`` cookie ``HttpOnly``, ``Secure``,
``SameSite=Lax``, ``Max-Age = COOKIE_MAX_AGE_SECONDS``; on
``complete_login`` clear it and rotate the session id on elevation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import urllib.parse

from ._exceptions import LoginCsrfError
from ._secure_urls import require_https_or_loopback
from ._sphinx_client import SphinxClient, TokenResponse


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class LoginFlow:

    #: Cookie the host must set on ``begin_login`` and read on ``complete_login``.
    COOKIE_NAME = "gh_login"
    #: Cookie the host reads for the deep-link return target (set by the web filter).
    RETURN_COOKIE_NAME = "gh_return"
    #: Suggested ``Max-Age`` (seconds) for the ``gh_login`` cookie.
    COOKIE_MAX_AGE_SECONDS = 600

    def __init__(
        self,
        sphinx_base_url: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        signing_key: bytes,
        client: SphinxClient,
    ) -> None:
        base = sphinx_base_url[:-1] if sphinx_base_url.endswith("/") else sphinx_base_url
        require_https_or_loopback(base, "Sphinx base URL")
        self._authorize_url = base + "/oauth/authorize"
        self._client_id = client_id
        self._redirect_uri = redirect_uri
        self._scope = scope
        self._signing_key = bytes(signing_key)
        self._client = client

    def begin_login(self) -> tuple[str, str]:
        """Start a login: return ``(authorize_url, cookie_value)``. Redirect the
        browser to ``authorize_url`` and set the ``gh_login`` cookie to
        ``cookie_value`` (HttpOnly/Secure/SameSite=Lax)."""
        verifier = _b64url(os.urandom(64))
        challenge = self.challenge_for(verifier)
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": self._client_id,
                "redirect_uri": self._redirect_uri,
                "scope": self._scope,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        # No state parameter — PKCE is the CSRF binding.
        return self._authorize_url + "?" + query, self.sign(verifier)

    def complete_login(
        self, gh_login_cookie: str | None, code: str | None
    ) -> TokenResponse:
        """Require this browser's verifier cookie, then redeem the code with it.

        Raises :class:`LoginCsrfError` if the cookie is absent/forged or the code
        is missing. The host should clear the ``gh_login`` cookie and rotate the
        session id (anti-fixation) after a successful call."""
        verifier = self.verify_cookie_value(gh_login_cookie)
        if verifier is None:
            raise LoginCsrfError("no login in progress for this browser")
        if code is None or not code.strip():
            raise LoginCsrfError("callback is missing the authorization code")
        return self._client.exchange_code(code, self._redirect_uri, verifier)

    def consume_return_to(
        self, gh_return_cookie: str | None, default_home: str
    ) -> str:
        """Return an open-redirect-safe same-origin path from the ``gh_return``
        cookie, or *default_home*. The host should also clear the cookie."""
        safe = self.sanitize_return_to(gh_return_cookie)
        return safe if safe is not None else default_home

    # ---- PKCE + signed cookie ("verifier.hmac") ---------------------------

    def challenge_for(self, verifier: str) -> str:
        """RFC 7636 S256: ``BASE64URL(SHA256(ASCII(verifier)))``."""
        return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())

    def sign(self, verifier: str) -> str:
        return verifier + "." + _b64url(self._hmac(verifier))

    def verify_cookie_value(self, raw: str | None) -> str | None:
        """Return the verifier if the signed cookie is authentic, else ``None``."""
        if raw is None:
            return None
        dot = raw.rfind(".")
        if dot <= 0:
            return None
        verifier = raw[:dot]
        mac = raw[dot + 1 :]
        expected = _b64url(self._hmac(verifier))
        return verifier if hmac.compare_digest(mac, expected) else None

    def _hmac(self, verifier: str) -> bytes:
        return hmac.new(
            self._signing_key, verifier.encode("ascii"), hashlib.sha256
        ).digest()

    @staticmethod
    def sanitize_return_to(raw: str | None) -> str | None:
        """Return *raw* if it is a safe same-origin relative path, else ``None``."""
        if not raw:
            return None
        # Must be an absolute-path reference: exactly one leading '/'.
        if raw[0] != "/":
            return None
        if len(raw) >= 2 and raw[1] in ("/", "\\"):  # //host or /\host
            return None
        for ch in raw:
            if ord(ch) <= 0x20 or ord(ch) == 0x7F or ch == "\\":
                return None
        if "://" in raw:
            return None
        return raw
