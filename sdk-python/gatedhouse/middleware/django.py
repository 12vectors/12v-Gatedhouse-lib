"""Django middleware for Gatedhouse authorization."""

from __future__ import annotations

import logging
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse

logger = logging.getLogger("gatedhouse.middleware.django")


class GatehouseMiddleware:
    """Django middleware that populates request.gated_context."""

    def __init__(self, get_response: Callable) -> None:
        self.get_response = get_response
        self._gatedhouse: Any = None

    def configure(self, gatedhouse: Any) -> None:
        """Configure with a Gatedhouse instance."""
        self._gatedhouse = gatedhouse

    def __call__(self, request: HttpRequest) -> HttpResponse:
        import asyncio
        from django.http import JsonResponse

        if self._gatedhouse is None:
            return self.get_response(request)

        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth_header.startswith("Bearer "):
            request.gated_context = None  # type: ignore[attr-defined]
            return self.get_response(request)

        token = auth_header[7:]
        headers = {
            k.lower().replace("http_", "").replace("_", "-"): v
            for k, v in request.META.items()
            if k.startswith("HTTP_")
        }

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    ctx = pool.submit(
                        asyncio.run,
                        self._gatedhouse.build_context(token, headers),
                    ).result()
            else:
                ctx = loop.run_until_complete(
                    self._gatedhouse.build_context(token, headers)
                )
            request.gated_context = ctx  # type: ignore[attr-defined]
        except Exception:
            logger.exception("Failed to build GatedContext")
            return JsonResponse({"error": "Unauthorized"}, status=401)

        return self.get_response(request)


def require_permission(required: str) -> Callable:
    """Django decorator that checks a single permission."""
    from functools import wraps
    from django.http import JsonResponse

    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            ctx = getattr(request, "gated_context", None)
            if ctx is None:
                return JsonResponse({"error": "Unauthorized"}, status=401)

            from gatedhouse.core.permissions.checker import PermissionChecker
            checker = PermissionChecker()
            result = checker.check(ctx, required)
            if not result.allowed:
                return JsonResponse({"error": "Forbidden"}, status=403)

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
