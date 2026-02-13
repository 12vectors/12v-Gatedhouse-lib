"""Tests for the ABAC policy engine."""

import pytest

from gatedhouse.core.policies.engine import PolicyEngine
from gatedhouse.core.types import GatedContext, Identity, MembershipContext, OrgContext


def _make_ctx() -> GatedContext:
    return GatedContext(
        identity=Identity(id="per_test", type="human", auth_method="password"),
        org=OrgContext(id="org_test"),
        membership=MembershipContext(
            id="mbr_test", entity_type="person", is_owner=False,
            status="active", groups=(),
        ),
    )


class TestPolicyEngine:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        self.engine = PolicyEngine()

    @pytest.mark.asyncio
    async def test_register_and_evaluate(self) -> None:
        self.engine.register("is_owner", lambda ctx, res: ctx.membership.is_owner)
        result = await self.engine.evaluate("is_owner", _make_ctx(), {})
        assert result is False

    @pytest.mark.asyncio
    async def test_unknown_policy_denied(self) -> None:
        result = await self.engine.evaluate("nonexistent", _make_ctx(), {})
        assert result is False

    @pytest.mark.asyncio
    async def test_policy_exception_denied(self) -> None:
        def failing_policy(ctx: GatedContext, res: dict) -> bool:
            raise RuntimeError("boom")

        self.engine.register("failing", failing_policy)
        result = await self.engine.evaluate("failing", _make_ctx(), {})
        assert result is False

    @pytest.mark.asyncio
    async def test_async_policy(self) -> None:
        async def async_policy(ctx: GatedContext, res: dict) -> bool:
            return True

        self.engine.register("async_check", async_policy)
        result = await self.engine.evaluate("async_check", _make_ctx(), {})
        assert result is True

    def test_has_policy(self) -> None:
        self.engine.register("exists", lambda ctx, res: True)
        assert self.engine.has_policy("exists") is True
        assert self.engine.has_policy("not_exists") is False
