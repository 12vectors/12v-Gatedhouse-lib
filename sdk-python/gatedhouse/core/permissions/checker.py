"""Permission checker — the core authorization decision point.

Evaluates whether a GatedContext has a required permission,
respecting identity type, delegation constraints, and wildcards.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from gatedhouse.core.types import GatedContext, PermissionCheckResult
from gatedhouse.core.permissions.matcher import has_permission, intersect_permissions

logger = logging.getLogger("gatedhouse.permission-checker")


class PermissionChecker:
    """Core authorization decision engine."""

    def check(self, ctx: GatedContext, required: str) -> PermissionCheckResult:
        """Check a single permission against the context."""
        # Suspended memberships always fail
        if ctx.membership.status == "suspended":
            return PermissionCheckResult(allowed=False)

        # Delegated agent: three-way intersection
        if ctx.delegation is not None:
            return self._check_delegated(ctx, required)

        # Scoped identity (API key or client credentials): intersect with scopes
        if ctx.scopes is not None and len(ctx.scopes) > 0:
            return self._check_scoped(ctx, required)

        # Standard RBAC check
        return self._check_standard(ctx, required)

    def check_many(
        self, ctx: GatedContext, required: list[str]
    ) -> dict[str, PermissionCheckResult]:
        """Check multiple permissions, returning a map of results."""
        return {perm: self.check(ctx, perm) for perm in required}

    def check_all(self, ctx: GatedContext, required: list[str]) -> bool:
        """Check that all required permissions are satisfied."""
        return all(self.check(ctx, perm).allowed for perm in required)

    def check_any(self, ctx: GatedContext, required: list[str]) -> bool:
        """Check that any of the required permissions are satisfied."""
        return any(self.check(ctx, perm).allowed for perm in required)

    def _check_standard(
        self, ctx: GatedContext, required: str
    ) -> PermissionCheckResult:
        if has_permission(ctx.permissions, required):
            source = self._find_source(ctx.permissions, required)
            return PermissionCheckResult(allowed=True, source=source)
        return PermissionCheckResult(allowed=False)

    def _check_scoped(
        self, ctx: GatedContext, required: str
    ) -> PermissionCheckResult:
        assert ctx.scopes is not None
        effective = intersect_permissions(list(ctx.permissions), list(ctx.scopes))
        if has_permission(effective, required):
            return PermissionCheckResult(allowed=True, source="scoped")
        return PermissionCheckResult(allowed=False)

    def _check_delegated(
        self, ctx: GatedContext, required: str
    ) -> PermissionCheckResult:
        assert ctx.delegation is not None
        delegation = ctx.delegation

        # Check delegation expiry
        expires_at = datetime.fromisoformat(delegation.expires_at.replace("Z", "+00:00"))
        if expires_at < datetime.now(timezone.utc):
            logger.debug("Delegation %s expired", delegation.id)
            return PermissionCheckResult(allowed=False)

        # Check uses remaining
        if delegation.uses_remaining is not None and delegation.uses_remaining <= 0:
            logger.debug("Delegation %s uses exhausted", delegation.id)
            return PermissionCheckResult(allowed=False)

        # Three-way intersection:
        # Effective = DelegationScopes ∩ AgentPermissions(ctx.permissions)
        effective = intersect_permissions(
            list(delegation.scopes), list(ctx.permissions)
        )

        if has_permission(effective, required):
            return PermissionCheckResult(
                allowed=True, source=f"delegation:{delegation.id}"
            )

        return PermissionCheckResult(allowed=False)

    @staticmethod
    def _find_source(permissions: tuple[str, ...], required: str) -> str:
        for perm in permissions:
            if perm == required:
                return f"permission:{perm}"
        return "wildcard"
