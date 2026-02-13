"""ABAC policy engine — register and evaluate custom policies."""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

from gatedhouse.core.types import GatedContext

logger = logging.getLogger("gatedhouse.policies.engine")

PolicyFunction = Callable[[GatedContext, dict[str, Any]], bool | Awaitable[bool]]


class PolicyEngine:
    """Register and evaluate custom ABAC policies. Fail-closed."""

    def __init__(self) -> None:
        self._policies: dict[str, PolicyFunction] = {}

    def register(self, name: str, policy: PolicyFunction) -> None:
        """Register a policy function."""
        self._policies[name] = policy

    async def evaluate(
        self, name: str, ctx: GatedContext, resource: dict[str, Any]
    ) -> bool:
        """Evaluate a named policy. Returns False if policy not found (fail-closed)."""
        policy = self._policies.get(name)
        if not policy:
            logger.warning("Policy '%s' not found, denying", name)
            return False

        try:
            result = policy(ctx, resource)
            if hasattr(result, "__await__"):
                return await result  # type: ignore[misc]
            return bool(result)
        except Exception:
            logger.exception("Policy '%s' evaluation failed, denying", name)
            return False

    def has_policy(self, name: str) -> bool:
        return name in self._policies
