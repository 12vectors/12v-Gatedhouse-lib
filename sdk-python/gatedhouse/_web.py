# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""WSGI security filters mirroring the Java servlet filters.

The Java reference implementation ships ``GatedhouseApiFilter`` and
``GatedhouseWebFilter`` as ``jakarta.servlet.Filter``s. Python's
platform-neutral equivalent is WSGI middleware (PEP 3333), so the same
names are provided here as WSGI wrappers with the same contract:

* ``GatedhouseApiFilter`` — guards REST endpoints. Validates
  ``Authorization: Bearer <token>`` and returns a ``401`` JSON body on
  failure.
* ``GatedhouseWebFilter`` — guards browser-facing pages. Reads the token
  from a session mapping and 302-redirects to a login path on failure.

Both stamp the verified :class:`GatedContext` into the WSGI ``environ``
under :data:`CONTEXT_ATTR` (the same key string Java uses for its request
attribute) and add the same security headers to every response.

Java's ``HttpSession`` has no WSGI counterpart, so ``GatedhouseWebFilter``
reads a ``MutableMapping`` the host's session middleware exposes in the
environ (``session_environ_key``, default ``"gatedhouse.session"``).

ASGI hosts (FastAPI, Starlette, Litestar, Quart) should use the native
counterparts in :mod:`gatedhouse.asgi` instead of adapting these.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable, Iterable, MutableMapping

from ._exceptions import TokenVerificationException
from ._gated_context import GatedContext
from ._gatedhouse import Gatedhouse

CONTEXT_ATTR = "com.twelvevectors.gatedhouse.context"

_SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
)

#: RFC 6750 challenge sent on every 401 response.
WWW_AUTHENTICATE_CHALLENGE = "Bearer"

_WsgiApp = Callable[..., Iterable[bytes]]


class UnauthorizedException(RuntimeError):
    """No verified context is present on the request."""


class ForbiddenException(RuntimeError):
    """The verified context lacks a required privilege."""


def _with_security_headers(start_response: Callable) -> Callable:
    """Wrap ``start_response`` to add the standard security headers to
    whatever the downstream app sends (app-provided values win)."""

    def wrapped(status: str, headers: list, exc_info: Any = None) -> Any:
        present = {name.lower() for name, _ in headers}
        extra = [(n, v) for n, v in _SECURITY_HEADERS if n.lower() not in present]
        return start_response(status, list(headers) + extra, exc_info)

    return wrapped


#: Seconds a client should wait before retrying after a 503.
RETRY_AFTER_SECONDS = 30


def bearer_token(authorization: str | None) -> str | None:
    """The token from an ``Authorization`` header, or ``None``. The scheme is
    matched case-insensitively (RFC 7235 section 2.1)."""
    if authorization is None or authorization[:7].lower() != "bearer ":
        return None
    return authorization[7:].strip() or None


def is_outage(e: TokenVerificationException) -> bool:
    """An identity-provider outage is our failure, not the caller's."""
    return e.reason is TokenVerificationException.Reason.JWKS_UNAVAILABLE


def error_body(error: str, reason: str | None, detail: str) -> bytes:
    """The JSON error body, byte-identical to the Java and Rust SDKs: 401
    bodies name a stable ``reason`` code, never the verifier's internal
    message (which can include the IdP's URL or network errors)."""
    payload: dict[str, str] = {"error": error}
    if reason is not None:
        payload["reason"] = reason
    payload["detail"] = detail
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


UNAVAILABLE_BODY = error_body("unavailable", "jwks_unavailable",
                              "Token verification is temporarily unavailable")


def _send_json_error(start_response: Callable, status: str, error: str,
                     detail: str, reason: str | None = None,
                     exc_info: Any = None) -> Iterable[bytes]:
    body = error_body(error, reason, detail)
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
        *_SECURITY_HEADERS,
    ]
    # RFC 7235 §4.1 requires a challenge on 401 only; 403 and 503 stay bare.
    if status.startswith("401"):
        headers.append(("WWW-Authenticate", WWW_AUTHENTICATE_CHALLENGE))
    if status.startswith("503"):
        headers.append(("Retry-After", str(RETRY_AFTER_SECONDS)))
    start_response(status, headers, exc_info)
    return [body]


def _send_unavailable(start_response: Callable) -> Iterable[bytes]:
    return _send_json_error(start_response, "503 Service Unavailable", "unavailable",
                            "Token verification is temporarily unavailable",
                            reason="jwks_unavailable")


class GatedhouseApiFilter:
    """API security middleware enforcing ``Authorization: Bearer`` token
    validation. A missing or invalid token gets a 401 JSON response with a
    stable ``reason`` code; an identity-provider outage gets a 503 with
    ``Retry-After``. ``ForbiddenException`` / ``UnauthorizedException``
    raised by the application (via ``require_admin`` etc.) become 403 / 401;
    every other application exception propagates unchanged."""

    CONTEXT_ATTR = CONTEXT_ATTR

    def __init__(self, app: _WsgiApp, gatedhouse: Gatedhouse) -> None:
        if gatedhouse is None:
            raise TypeError("gatedhouse must not be None")
        self._app = app
        self._gatedhouse = gatedhouse

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        token = bearer_token(environ.get("HTTP_AUTHORIZATION"))
        if token is None:
            return _send_json_error(start_response, "401 Unauthorized",
                                    "unauthorized", "Missing or invalid Bearer token",
                                    reason="missing_token")

        # Only verification is guarded. Other errors from verify_token (e.g.
        # no verifier configured) are server faults and propagate.
        try:
            subject = self._gatedhouse.verify_token(token)
        except TokenVerificationException as e:
            if is_outage(e):
                return _send_unavailable(start_response)
            return _send_json_error(start_response, "401 Unauthorized",
                                    "unauthorized", "Token verification failed",
                                    reason=e.reason.value)

        environ[CONTEXT_ATTR] = GatedContext.from_subject(subject)
        # The application runs outside the verification guard; only this
        # module's helper exceptions are translated.
        try:
            return self._app(environ, _with_security_headers(start_response))
        except ForbiddenException as e:
            return _send_json_error(start_response, "403 Forbidden", "forbidden",
                                    str(e), exc_info=sys.exc_info())
        except UnauthorizedException as e:
            return _send_json_error(start_response, "401 Unauthorized", "unauthorized",
                                    str(e), exc_info=sys.exc_info())

    # ---- request helpers (mirror the Java statics) -------------------------

    @staticmethod
    def get_context(environ: dict) -> GatedContext:
        """Extracts the verified GatedContext from the request environ."""
        ctx = environ.get(CONTEXT_ATTR)
        if ctx is None:
            raise UnauthorizedException("Authentication required")
        return ctx

    @staticmethod
    def require_admin(environ: dict) -> GatedContext:
        """Asserts that the authenticated context has admin privileges."""
        ctx = GatedhouseApiFilter.get_context(environ)
        if not ctx.is_admin():
            raise ForbiddenException("Admin access required")
        return ctx

    @staticmethod
    def require_human(environ: dict) -> GatedContext:
        """Asserts that the authenticated identity is a human user."""
        ctx = GatedhouseApiFilter.get_context(environ)
        if not ctx.is_human():
            raise ForbiddenException("Human identity required")
        return ctx

    @staticmethod
    def require_scope(environ: dict, scope: str) -> GatedContext:
        """Asserts that the authenticated context carries a specific scope."""
        ctx = GatedhouseApiFilter.get_context(environ)
        if not ctx.has_scope(scope):
            raise ForbiddenException(f"Scope '{scope}' required")
        return ctx


class GatedhouseWebFilter:
    """Web security middleware that guards HTML pages using session-based
    token verification. On failure, 302-redirects the browser to a
    configurable login path (absolute or relative)."""

    CONTEXT_ATTR = CONTEXT_ATTR
    DEFAULT_LOGIN_PATH = "/auth/login"
    DEFAULT_SESSION_TOKEN_ATTR = "access_token"
    DEFAULT_SESSION_ENVIRON_KEY = "gatedhouse.session"

    def __init__(self, app: _WsgiApp, gatedhouse: Gatedhouse,
                 login_path: str = DEFAULT_LOGIN_PATH,
                 session_token_attr: str = DEFAULT_SESSION_TOKEN_ATTR,
                 session_environ_key: str = DEFAULT_SESSION_ENVIRON_KEY) -> None:
        if gatedhouse is None:
            raise TypeError("gatedhouse must not be None")
        self._app = app
        self._gatedhouse = gatedhouse
        self._login_path = login_path
        self._session_token_attr = session_token_attr
        self._session_environ_key = session_environ_key

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        session: MutableMapping | None = environ.get(self._session_environ_key)
        token = session.get(self._session_token_attr) if session is not None else None

        if token is None or not str(token).strip():
            return self._login_redirect(environ, start_response)

        try:
            subject = self._gatedhouse.verify_token(str(token).strip())
        except TokenVerificationException as e:
            if is_outage(e):
                # The identity provider is down: keep the session (the token
                # may be perfectly valid) and do not bounce the user to a
                # login page that cannot work either.
                return _send_unavailable(start_response)
            # Token is invalid or expired: remove it from the session and
            # redirect.
            if session is not None:
                session.pop(self._session_token_attr, None)
            return self._login_redirect(environ, start_response)

        environ[CONTEXT_ATTR] = GatedContext.from_subject(subject)
        return self._app(environ, _with_security_headers(start_response))

    def _login_redirect(self, environ: dict,
                        start_response: Callable) -> Iterable[bytes]:
        if self._login_path.startswith(("http://", "https://", "//")):
            target = self._login_path
        else:
            # SCRIPT_NAME is WSGI's analog of the servlet context path.
            target = environ.get("SCRIPT_NAME", "") + self._login_path
        headers = [
            ("Location", target),
            ("Content-Length", "0"),
            *_SECURITY_HEADERS,
        ]
        start_response("302 Found", headers)
        return [b""]
