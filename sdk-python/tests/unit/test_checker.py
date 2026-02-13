"""Tests for the PermissionChecker."""

from datetime import datetime, timezone, timedelta

from gatedhouse.core.permissions.checker import PermissionChecker
from gatedhouse.core.types import (
    DelegationContext,
    GatedContext,
    Identity,
    MembershipContext,
    OrgContext,
)


def _make_ctx(
    permissions: tuple[str, ...] = (),
    status: str = "active",
    scopes: tuple[str, ...] | None = None,
    delegation: DelegationContext | None = None,
) -> GatedContext:
    return GatedContext(
        identity=Identity(id="per_test", type="human", auth_method="password"),
        org=OrgContext(id="org_test"),
        membership=MembershipContext(
            id="mbr_test", entity_type="person", is_owner=False,
            status=status, groups=(),
        ),
        roles=(),
        permissions=permissions,
        scopes=scopes,
        delegation=delegation,
    )


class TestPermissionChecker:
    def setup_method(self) -> None:
        self.checker = PermissionChecker()

    def test_standard_allow(self) -> None:
        ctx = _make_ctx(permissions=("files:documents:read",))
        result = self.checker.check(ctx, "files:documents:read")
        assert result.allowed is True

    def test_standard_deny(self) -> None:
        ctx = _make_ctx(permissions=("files:documents:read",))
        result = self.checker.check(ctx, "files:documents:delete")
        assert result.allowed is False

    def test_suspended_deny(self) -> None:
        ctx = _make_ctx(permissions=("*:*:*",), status="suspended")
        result = self.checker.check(ctx, "files:documents:read")
        assert result.allowed is False

    def test_wildcard_allow(self) -> None:
        ctx = _make_ctx(permissions=("files:*:*",))
        result = self.checker.check(ctx, "files:documents:delete")
        assert result.allowed is True

    def test_superadmin_allow(self) -> None:
        ctx = _make_ctx(permissions=("*:*:*",))
        result = self.checker.check(ctx, "any:resource:action")
        assert result.allowed is True

    def test_empty_permissions_deny(self) -> None:
        ctx = _make_ctx(permissions=())
        result = self.checker.check(ctx, "files:documents:read")
        assert result.allowed is False

    def test_scoped_allow(self) -> None:
        ctx = _make_ctx(
            permissions=("files:documents:read", "files:documents:write", "billing:invoices:read"),
            scopes=("files:documents:read", "billing:*:*"),
        )
        result = self.checker.check(ctx, "files:documents:read")
        assert result.allowed is True

    def test_scoped_deny_not_in_scope(self) -> None:
        ctx = _make_ctx(
            permissions=("files:documents:read", "files:documents:write"),
            scopes=("files:documents:read",),
        )
        result = self.checker.check(ctx, "files:documents:write")
        assert result.allowed is False

    def test_delegation_allow(self) -> None:
        ctx = _make_ctx(
            permissions=("files:*:*",),
            delegation=DelegationContext(
                id="dlg_01",
                delegator_id="per_test",
                delegator_membership_id="mbr_test",
                scopes=("files:documents:write",),
                constraints={},
                expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                uses_remaining=None,
            ),
        )
        result = self.checker.check(ctx, "files:documents:write")
        assert result.allowed is True

    def test_delegation_deny_expired(self) -> None:
        ctx = _make_ctx(
            permissions=("files:*:*",),
            delegation=DelegationContext(
                id="dlg_03",
                delegator_id="per_test",
                delegator_membership_id="mbr_test",
                scopes=("files:documents:write",),
                constraints={},
                expires_at=(datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
                uses_remaining=None,
            ),
        )
        result = self.checker.check(ctx, "files:documents:write")
        assert result.allowed is False

    def test_delegation_deny_exhausted(self) -> None:
        ctx = _make_ctx(
            permissions=("files:*:*",),
            delegation=DelegationContext(
                id="dlg_04",
                delegator_id="per_test",
                delegator_membership_id="mbr_test",
                scopes=("files:documents:write",),
                constraints={},
                expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                uses_remaining=0,
            ),
        )
        result = self.checker.check(ctx, "files:documents:write")
        assert result.allowed is False

    def test_delegation_deny_outside_scope(self) -> None:
        ctx = _make_ctx(
            permissions=("files:*:*",),
            delegation=DelegationContext(
                id="dlg_02",
                delegator_id="per_test",
                delegator_membership_id="mbr_test",
                scopes=("files:documents:read",),
                constraints={},
                expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                uses_remaining=None,
            ),
        )
        result = self.checker.check(ctx, "files:documents:write")
        assert result.allowed is False

    def test_check_all(self) -> None:
        ctx = _make_ctx(permissions=("files:documents:read", "files:documents:write"))
        assert self.checker.check_all(ctx, ["files:documents:read", "files:documents:write"]) is True
        assert self.checker.check_all(ctx, ["files:documents:read", "files:documents:delete"]) is False

    def test_check_any(self) -> None:
        ctx = _make_ctx(permissions=("files:documents:read",))
        assert self.checker.check_any(ctx, ["files:documents:read", "files:documents:delete"]) is True
        assert self.checker.check_any(ctx, ["files:documents:write", "files:documents:delete"]) is False
