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


def _send_json_error(start_response: Callable, status: str,
                     error: str, detail: str) -> Iterable[bytes]:
    body = json.dumps({"error": error, "detail": detail}).encode("utf-8")
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
        *_SECURITY_HEADERS,
    ]
    start_response(status, headers)
    return [body]


class GatedhouseApiFilter:
    """API security middleware enforcing ``Authorization: Bearer`` token
    validation. On failure, returns a clean 401 JSON response."""

    CONTEXT_ATTR = CONTEXT_ATTR

    def __init__(self, app: _WsgiApp, gatedhouse: Gatedhouse) -> None:
        if gatedhouse is None:
            raise TypeError("gatedhouse must not be None")
        self._app = app
        self._gatedhouse = gatedhouse

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        auth = environ.get("HTTP_AUTHORIZATION")
        if auth is None or not auth.startswith("Bearer "):
            return _send_json_error(start_response, "401 Unauthorized",
                                    "unauthorized",
                                    "Missing or invalid Bearer token")

        token = auth[7:].strip()
        try:
            subject = self._gatedhouse.verify_token(token)
        except TokenVerificationException as e:
            return _send_json_error(start_response, "401 Unauthorized",
                                    "unauthorized",
                                    f"Token verification failed: {e}")
        except Exception:
            return _send_json_error(start_response, "401 Unauthorized",
                                    "unauthorized", "Authentication failed")

        environ[CONTEXT_ATTR] = GatedContext.from_subject(subject)
        return self._app(environ, _with_security_headers(start_response))

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
            subject = self._gatedhouse.verify_token(token)
        except TokenVerificationException:
            # Token is invalid or expired — remove it from the session
            # and redirect.
            if session is not None:
                session.pop(self._session_token_attr, None)
            return self._login_redirect(environ, start_response)
        except Exception:
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
