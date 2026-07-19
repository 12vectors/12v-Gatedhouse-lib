# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""ASGI security middleware mirroring the Java servlet filters.

The WSGI filters in :mod:`gatedhouse` cover PEP 3333 hosts; this module
provides the same two guards for the ASGI world (FastAPI, Starlette,
Litestar, Quart, raw uvicorn apps) so downstream applications don't have
to improvise their own token middleware. The contract is identical to
the WSGI and Java implementations:

* ``GatedhouseApiFilter`` — guards REST endpoints. Validates
  ``Authorization: Bearer <token>`` and returns the same ``401`` JSON
  body (``{"error": "unauthorized", "detail": ...}``) on failure.
* ``GatedhouseWebFilter`` — guards browser-facing pages. Reads the token
  from the ASGI session (``scope["session"]``, as populated by e.g.
  Starlette's ``SessionMiddleware``) and 302-redirects to a login path
  on failure, clearing an invalid token from the session first.

Both stamp the verified :class:`~gatedhouse.GatedContext` into the ASGI
scope under :data:`CONTEXT_ATTR` (the same key string the Java and WSGI
implementations use) and additionally under ``scope["state"]`` as
``gatedhouse_context`` so Starlette/FastAPI handlers can read
``request.state.gatedhouse_context`` directly. The same three security
headers are added to every response.

Token verification may fetch JWKS over the network, so it runs in the
default thread-pool executor rather than blocking the event loop.

**WebSocket scopes are guarded fail-closed.** A WebSocket handshake
reaching ``GatedhouseApiFilter`` must carry a valid ``Authorization:
Bearer`` header, and one reaching ``GatedhouseWebFilter`` must have a
valid session token; otherwise the handshake is rejected with
``websocket.close`` (policy code 1008) and the downstream app is never
invoked. Only ``lifespan`` scopes pass through unauthenticated.

**Middleware ordering matters for the web filter.** Session eviction on
an invalid token only persists if this middleware runs *inside* the
session middleware. With Starlette/FastAPI, ``add_middleware`` wraps
newest-outermost, so add the Gatedhouse filter *first* and
``SessionMiddleware`` *after* it::

    app.add_middleware(GatedhouseWebFilter, gatedhouse=gh)  # inner
    app.add_middleware(SessionMiddleware, secret_key=...)   # outer

Pure ASGI, stdlib-only — no Starlette or FastAPI dependency. Usage::

    app.add_middleware(GatedhouseApiFilter, gatedhouse=gh)   # Starlette/FastAPI
    app = GatedhouseApiFilter(app, gh)                       # raw ASGI
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Awaitable, Callable, MutableMapping

from ._exceptions import TokenVerificationException
from ._gated_context import GatedContext
from ._gatedhouse import Gatedhouse
from ._web import ForbiddenException, UnauthorizedException

__all__ = [
    "CONTEXT_ATTR",
    "STATE_KEY",
    "ForbiddenException",
    "GatedhouseApiFilter",
    "GatedhouseWebFilter",
    "UnauthorizedException",
]

CONTEXT_ATTR = "com.twelvevectors.gatedhouse.context"
STATE_KEY = "gatedhouse_context"

_SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
)

_Scope = MutableMapping[str, Any]
_Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
_Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
_AsgiApp = Callable[[_Scope, _Receive, _Send], Awaitable[None]]


def _header(scope: _Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers") or ():
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _wrap_send_with_security_headers(send: _Send) -> _Send:
    """Add the standard security headers to whatever the downstream app
    sends (app-provided values win)."""

    async def wrapped(message: MutableMapping[str, Any]) -> None:
        if message["type"] == "http.response.start":
            headers = list(message.get("headers") or [])
            present = {k.lower() for k, _ in headers}
            headers.extend(
                (n, v) for n, v in _SECURITY_HEADERS if n not in present
            )
            message = {**message, "headers": headers}
        await send(message)

    return wrapped


async def _send_json_error(send: _Send, status: int,
                           error: str, detail: str) -> None:
    body = json.dumps({"error": error, "detail": detail}).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"content-length", str(len(body)).encode("latin-1")),
            *_SECURITY_HEADERS,
        ],
    })
    await send({"type": "http.response.body", "body": body})


async def _reject_websocket(receive: _Receive, send: _Send) -> None:
    """Refuse a WebSocket handshake: consume ``websocket.connect`` and
    close with policy-violation code 1008 without invoking the app.
    Servers translate a pre-accept close into a rejected handshake."""
    await receive()
    await send({"type": "websocket.close", "code": 1008})


async def _send_redirect(send: _Send, location: str) -> None:
    await send({
        "type": "http.response.start",
        "status": 302,
        "headers": [
            (b"location", location.encode("latin-1")),
            (b"content-length", b"0"),
            *_SECURITY_HEADERS,
        ],
    })
    await send({"type": "http.response.body", "body": b""})


def _attach_context(scope: _Scope, ctx: GatedContext) -> None:
    scope[CONTEXT_ATTR] = ctx
    state = scope.setdefault("state", {})
    if isinstance(state, MutableMapping):
        state[STATE_KEY] = ctx
    else:  # Starlette lifespan State object
        setattr(state, STATE_KEY, ctx)


async def _verify_off_loop(gatedhouse: Gatedhouse, token: str) -> Any:
    """Run the (potentially JWKS-fetching, blocking) verification in the
    default executor so the event loop stays responsive."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, gatedhouse.verify_token, token)


class GatedhouseApiFilter:
    """ASGI API security middleware enforcing ``Authorization: Bearer``
    token validation. On failure, returns a clean 401 JSON response."""

    CONTEXT_ATTR = CONTEXT_ATTR

    def __init__(self, app: _AsgiApp, gatedhouse: Gatedhouse) -> None:
        if gatedhouse is None:
            raise TypeError("gatedhouse must not be None")
        self._app = app
        self._gatedhouse = gatedhouse

    async def __call__(self, scope: _Scope, receive: _Receive,
                       send: _Send) -> None:
        if scope["type"] == "websocket":
            # Fail closed: the handshake must carry a valid Bearer token.
            await self._handle_websocket(scope, receive, send)
            return
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        auth = _header(scope, b"authorization")
        if auth is None or not auth.startswith("Bearer "):
            await _send_json_error(send, 401, "unauthorized",
                                   "Missing or invalid Bearer token")
            return

        token = auth[7:].strip()
        try:
            subject = await _verify_off_loop(self._gatedhouse, token)
        except TokenVerificationException as e:
            await _send_json_error(send, 401, "unauthorized",
                                   f"Token verification failed: {e}")
            return
        except Exception:
            await _send_json_error(send, 401, "unauthorized",
                                   "Authentication failed")
            return

        _attach_context(scope, GatedContext.from_subject(subject))
        await self._app(scope, receive, _wrap_send_with_security_headers(send))

    async def _handle_websocket(self, scope: _Scope, receive: _Receive,
                                send: _Send) -> None:
        auth = _header(scope, b"authorization")
        if auth is None or not auth.startswith("Bearer "):
            await _reject_websocket(receive, send)
            return
        try:
            subject = await _verify_off_loop(self._gatedhouse,
                                             auth[7:].strip())
        except Exception:
            await _reject_websocket(receive, send)
            return
        _attach_context(scope, GatedContext.from_subject(subject))
        await self._app(scope, receive, send)

    # ---- request helpers (mirror the Java statics) -------------------------

    @staticmethod
    def get_context(scope: _Scope) -> GatedContext:
        """Extracts the verified GatedContext from the ASGI scope."""
        ctx = scope.get(CONTEXT_ATTR)
        if ctx is None:
            raise UnauthorizedException("Authentication required")
        return ctx

    @staticmethod
    def require_admin(scope: _Scope) -> GatedContext:
        """Asserts that the authenticated context has admin privileges."""
        ctx = GatedhouseApiFilter.get_context(scope)
        if not ctx.is_admin():
            raise ForbiddenException("Admin access required")
        return ctx

    @staticmethod
    def require_human(scope: _Scope) -> GatedContext:
        """Asserts that the authenticated identity is a human user."""
        ctx = GatedhouseApiFilter.get_context(scope)
        if not ctx.is_human():
            raise ForbiddenException("Human identity required")
        return ctx

    @staticmethod
    def require_scope(scope: _Scope, required_scope: str) -> GatedContext:
        """Asserts that the authenticated context carries a specific scope."""
        ctx = GatedhouseApiFilter.get_context(scope)
        if not ctx.has_scope(required_scope):
            raise ForbiddenException(f"Scope '{required_scope}' required")
        return ctx


class GatedhouseWebFilter:
    """ASGI web security middleware that guards HTML pages using
    session-based token verification. On failure, 302-redirects the
    browser to a configurable login path (absolute or relative)."""

    CONTEXT_ATTR = CONTEXT_ATTR
    DEFAULT_LOGIN_PATH = "/auth/login"
    DEFAULT_SESSION_TOKEN_ATTR = "access_token"
    DEFAULT_SESSION_SCOPE_KEY = "session"

    def __init__(self, app: _AsgiApp, gatedhouse: Gatedhouse,
                 login_path: str = DEFAULT_LOGIN_PATH,
                 session_token_attr: str = DEFAULT_SESSION_TOKEN_ATTR,
                 session_scope_key: str = DEFAULT_SESSION_SCOPE_KEY) -> None:
        if gatedhouse is None:
            raise TypeError("gatedhouse must not be None")
        self._app = app
        self._gatedhouse = gatedhouse
        self._login_path = login_path
        self._session_token_attr = session_token_attr
        self._session_scope_key = session_scope_key

    async def __call__(self, scope: _Scope, receive: _Receive,
                       send: _Send) -> None:
        is_websocket = scope["type"] == "websocket"
        if not is_websocket and scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        session: MutableMapping[str, Any] | None = scope.get(
            self._session_scope_key)
        token = (session.get(self._session_token_attr)
                 if session is not None else None)

        if token is None or not str(token).strip():
            await self._deny(scope, receive, send, is_websocket)
            return

        try:
            subject = await _verify_off_loop(self._gatedhouse, token)
        except TokenVerificationException:
            # Token is invalid or expired — remove it from the session
            # before denying.
            if session is not None:
                session.pop(self._session_token_attr, None)
            await self._deny(scope, receive, send, is_websocket)
            return
        except Exception:
            await self._deny(scope, receive, send, is_websocket)
            return

        _attach_context(scope, GatedContext.from_subject(subject))
        if is_websocket:
            await self._app(scope, receive, send)
        else:
            await self._app(scope, receive,
                            _wrap_send_with_security_headers(send))

    async def _deny(self, scope: _Scope, receive: _Receive, send: _Send,
                    is_websocket: bool) -> None:
        # A browser gets a login redirect; a WebSocket handshake cannot
        # be redirected, so it is rejected fail-closed.
        if is_websocket:
            await _reject_websocket(receive, send)
        else:
            await self._login_redirect(scope, send)

    async def _login_redirect(self, scope: _Scope, send: _Send) -> None:
        if self._login_path.startswith(("http://", "https://", "//")):
            target = self._login_path
        else:
            # root_path is ASGI's analog of the servlet context path.
            target = scope.get("root_path", "") + self._login_path
        await _send_redirect(send, target)
