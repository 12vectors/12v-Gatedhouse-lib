"""FastAPI/Starlette middleware and dependency injection for Gatedhouse."""

from __future__ import annotations

import logging
from typing import Any, Callable, Awaitable, TYPE_CHECKING

from gatedhouse.core.types import GatedContext, PermissionCheckResult

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("gatedhouse.middleware.fastapi")


class GatehouseMiddleware:
    """ASGI middleware that populates request.state.gated_context."""

    def __init__(
        self,
        app: ASGIApp,
        gatedhouse: Any,  # Gatedhouse instance — avoids circular import
    ) -> None:
        self.app = app
        self._gatedhouse = gatedhouse

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        from starlette.requests import Request
        from starlette.responses import JSONResponse

        request = Request(scope, receive, send)

        # Extract JWT from Authorization header
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            await self.app(scope, receive, send)
            return

        token = auth_header[7:]

        try:
            ctx = await self._gatedhouse.build_context(token, dict(request.headers))
            request.state.gated_context = ctx
        except Exception:
            logger.exception("Failed to build GatedContext")
            response = JSONResponse({"error": "Unauthorized"}, status_code=401)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


def require_permission(required: str) -> Callable:
    """FastAPI dependency that checks a single permission."""
    from fastapi import Depends, HTTPException, Request

    async def _check(request: Request) -> GatedContext:
        ctx: GatedContext | None = getattr(request.state, "gated_context", None)
        if ctx is None:
            raise HTTPException(status_code=401, detail="Unauthorized")

        from gatedhouse.core.permissions.checker import PermissionChecker
        checker = PermissionChecker()
        result = checker.check(ctx, required)
        if not result.allowed:
            raise HTTPException(status_code=403, detail="Forbidden")
        return ctx

    return _check


def require_all_permissions(*required: str) -> Callable:
    """FastAPI dependency that checks all permissions."""
    from fastapi import HTTPException, Request

    async def _check(request: Request) -> GatedContext:
        ctx: GatedContext | None = getattr(request.state, "gated_context", None)
        if ctx is None:
            raise HTTPException(status_code=401, detail="Unauthorized")

        from gatedhouse.core.permissions.checker import PermissionChecker
        checker = PermissionChecker()
        if not checker.check_all(ctx, list(required)):
            raise HTTPException(status_code=403, detail="Forbidden")
        return ctx

    return _check


def require_any_permission(*required: str) -> Callable:
    """FastAPI dependency that checks any permission."""
    from fastapi import HTTPException, Request

    async def _check(request: Request) -> GatedContext:
        ctx: GatedContext | None = getattr(request.state, "gated_context", None)
        if ctx is None:
            raise HTTPException(status_code=401, detail="Unauthorized")

        from gatedhouse.core.permissions.checker import PermissionChecker
        checker = PermissionChecker()
        if not checker.check_any(ctx, list(required)):
            raise HTTPException(status_code=403, detail="Forbidden")
        return ctx

    return _check


def get_context() -> Callable:
    """FastAPI dependency that returns the GatedContext (optional)."""
    from fastapi import Request

    async def _get(request: Request) -> GatedContext | None:
        return getattr(request.state, "gated_context", None)

    return _get
