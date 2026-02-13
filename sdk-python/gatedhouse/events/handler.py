"""Event handler — processes Citadel and Sphinx events to keep local caches in sync."""

from __future__ import annotations

import logging
from datetime import datetime

from gatedhouse.core.config import ResolvedConfig
from gatedhouse.core.membership.cache import MembershipCache
from gatedhouse.core.delegation.cache import DelegationCache
from gatedhouse.core.roles.repository import RoleRepository
from gatedhouse.core.roles.assignment import RoleAssignmentManager
from gatedhouse.core.roles.resolver import PermissionResolver
from gatedhouse.core.types import CachedDelegation, CachedMembership, GatehouseEvent
from gatedhouse.events import types as ET

logger = logging.getLogger("gatedhouse.events.handler")


class EventHandlerRegistry:
    """Processes incoming events to keep local caches in sync."""

    def __init__(
        self,
        membership_cache: MembershipCache,
        delegation_cache: DelegationCache,
        role_repo: RoleRepository,
        role_assignments: RoleAssignmentManager,
        permission_resolver: PermissionResolver,
        config: ResolvedConfig,
    ) -> None:
        self._membership_cache = membership_cache
        self._delegation_cache = delegation_cache
        self._role_repo = role_repo
        self._role_assignments = role_assignments
        self._permission_resolver = permission_resolver
        self._config = config

    async def handle(self, event: GatehouseEvent) -> None:
        """Process an incoming event. Idempotent by design."""
        handlers = {
            ET.ORG_CREATED: self._handle_org_created,
            ET.ORG_DELETED: self._handle_org_deleted,
            ET.ORG_SUSPENDED: self._handle_org_suspended,
            ET.ORG_REACTIVATED: self._handle_org_reactivated,
            ET.MEMBERSHIP_CREATED: self._handle_membership_created,
            ET.MEMBERSHIP_UPDATED: self._handle_membership_updated,
            ET.MEMBERSHIP_SUSPENDED: self._handle_membership_suspended,
            ET.MEMBERSHIP_REACTIVATED: self._handle_membership_reactivated,
            ET.MEMBERSHIP_REMOVED: self._handle_membership_removed,
            ET.GROUP_MEMBER_ADDED: self._handle_group_member_added,
            ET.GROUP_MEMBER_REMOVED: self._handle_group_member_removed,
            ET.GROUP_DELETED: self._handle_group_deleted,
            ET.DELEGATION_CREATED: self._handle_delegation_created,
            ET.DELEGATION_REVOKED: self._handle_delegation_revoked,
            ET.DELEGATION_EXPIRED: self._handle_delegation_expired,
            ET.DELEGATION_EXHAUSTED: self._handle_delegation_exhausted,
            ET.AGENT_DEACTIVATED: self._handle_agent_deactivated,
        }

        handler = handlers.get(event.type)
        if handler:
            await handler(event)
        else:
            logger.debug("Unknown event type %s, ignoring", event.type)

    # ─── Organization Handlers ──────────────────────────────────────

    async def _handle_org_created(self, event: GatehouseEvent) -> None:
        org_id = event.data["org_id"]
        logger.info("Handling org.created: %s", org_id)
        await self._role_repo.seed_base_roles(org_id, self._config.base_roles)

    async def _handle_org_deleted(self, event: GatehouseEvent) -> None:
        org_id = event.data["org_id"]
        logger.info("Handling org.deleted: %s — purging all data", org_id)
        await self._membership_cache.remove_all_for_org(org_id)
        await self._role_assignments.delete_all_for_org(org_id)
        await self._role_assignments.delete_all_group_roles_for_org(org_id)
        await self._role_repo.delete_all_for_org(org_id)
        await self._delegation_cache.remove_all_for_org(org_id)

    async def _handle_org_suspended(self, event: GatehouseEvent) -> None:
        org_id = event.data["org_id"]
        logger.info("Handling org.suspended: %s", org_id)
        await self._membership_cache.suspend_all_for_org(org_id)

    async def _handle_org_reactivated(self, event: GatehouseEvent) -> None:
        org_id = event.data["org_id"]
        logger.info("Handling org.reactivated: %s", org_id)
        await self._membership_cache.reactivate_all_for_org(org_id)

    # ─── Membership Handlers ───────────────────────────────────────

    async def _handle_membership_created(self, event: GatehouseEvent) -> None:
        data = event.data
        membership_id = data["membership_id"]
        org_id = data["org_id"]
        groups = data.get("groups", [])

        logger.info("Handling membership.created: %s in %s", membership_id, org_id)

        await self._membership_cache.upsert(CachedMembership(
            membership_id=membership_id,
            org_id=org_id,
            entity_type=data["entity_type"],
            entity_id=data["entity_id"],
            is_owner=data.get("is_owner", False),
            status=data.get("status", "active"),
            groups=groups,
        ))

        if self._config.default_role:
            await self._role_assignments.assign(
                membership_id, self._config.default_role, org_id
            )

        if data.get("is_owner"):
            await self._role_assignments.assign(membership_id, "owner", org_id)

        await self._permission_resolver.rebuild_for_membership(
            membership_id, org_id, groups
        )

    async def _handle_membership_updated(self, event: GatehouseEvent) -> None:
        data = event.data
        membership_id = data["membership_id"]
        org_id = data["org_id"]
        groups = data.get("groups", [])

        logger.info("Handling membership.updated: %s", membership_id)

        await self._membership_cache.upsert(CachedMembership(
            membership_id=membership_id,
            org_id=org_id,
            entity_type=data["entity_type"],
            entity_id=data["entity_id"],
            is_owner=data.get("is_owner", False),
            status=data.get("status", "active"),
            groups=groups,
        ))

        await self._permission_resolver.rebuild_for_membership(
            membership_id, org_id, groups
        )

    async def _handle_membership_suspended(self, event: GatehouseEvent) -> None:
        membership_id = event.data["membership_id"]
        logger.info("Handling membership.suspended: %s", membership_id)
        await self._membership_cache.update_status(membership_id, "suspended")

    async def _handle_membership_reactivated(self, event: GatehouseEvent) -> None:
        membership_id = event.data["membership_id"]
        logger.info("Handling membership.reactivated: %s", membership_id)
        await self._membership_cache.update_status(membership_id, "active")

    async def _handle_membership_removed(self, event: GatehouseEvent) -> None:
        membership_id = event.data["membership_id"]
        logger.info("Handling membership.removed: %s", membership_id)
        await self._membership_cache.remove(membership_id)
        await self._role_assignments.delete_all_for_membership(membership_id)
        await self._permission_resolver.clear_for_membership(membership_id)

    # ─── Group Handlers ────────────────────────────────────────────

    async def _handle_group_member_added(self, event: GatehouseEvent) -> None:
        membership_id = event.data["membership_id"]
        group_id = event.data["group_id"]
        org_id = event.data["org_id"]

        logger.info("Handling group.member.added: %s -> %s", membership_id, group_id)

        await self._membership_cache.add_group(membership_id, group_id)
        cached = await self._membership_cache.find_by_id(membership_id)
        if cached:
            await self._permission_resolver.rebuild_for_membership(
                membership_id, org_id, cached.groups
            )

    async def _handle_group_member_removed(self, event: GatehouseEvent) -> None:
        membership_id = event.data["membership_id"]
        group_id = event.data["group_id"]
        org_id = event.data["org_id"]

        logger.info("Handling group.member.removed: %s from %s", membership_id, group_id)

        await self._membership_cache.remove_group(membership_id, group_id)
        cached = await self._membership_cache.find_by_id(membership_id)
        if cached:
            await self._permission_resolver.rebuild_for_membership(
                membership_id, org_id, cached.groups
            )

    async def _handle_group_deleted(self, event: GatehouseEvent) -> None:
        group_id = event.data["group_id"]
        org_id = event.data["org_id"]

        logger.info("Handling group.deleted: %s", group_id)

        await self._membership_cache.remove_group_from_all(group_id)
        await self._role_assignments.delete_all_for_group(group_id)

        memberships = await self._membership_cache.list_by_org(org_id)
        for m in memberships:
            await self._permission_resolver.rebuild_for_membership(
                m.membership_id, org_id, m.groups
            )

    # ─── Delegation Handlers ───────────────────────────────────────

    async def _handle_delegation_created(self, event: GatehouseEvent) -> None:
        data = event.data
        logger.info("Handling delegation.created: %s", data["delegation_id"])

        await self._delegation_cache.upsert(CachedDelegation(
            delegation_id=data["delegation_id"],
            agent_id=data["agent_id"],
            delegator_id=data["delegator_id"],
            delegator_membership_id=data["delegator_membership_id"],
            org_id=data["org_id"],
            scopes=data.get("scopes", []),
            constraints=data.get("constraints", {}),
            max_uses=data.get("max_uses"),
            use_count=0,
            status="active",
            expires_at=datetime.fromisoformat(data["expires_at"]),
        ))

    async def _handle_delegation_revoked(self, event: GatehouseEvent) -> None:
        delegation_id = event.data["delegation_id"]
        logger.info("Handling delegation.revoked: %s", delegation_id)
        await self._delegation_cache.update_status(delegation_id, "revoked")

    async def _handle_delegation_expired(self, event: GatehouseEvent) -> None:
        delegation_id = event.data["delegation_id"]
        logger.info("Handling delegation.expired: %s", delegation_id)
        await self._delegation_cache.update_status(delegation_id, "expired")

    async def _handle_delegation_exhausted(self, event: GatehouseEvent) -> None:
        delegation_id = event.data["delegation_id"]
        logger.info("Handling delegation.exhausted: %s", delegation_id)
        await self._delegation_cache.update_status(delegation_id, "exhausted")

    async def _handle_agent_deactivated(self, event: GatehouseEvent) -> None:
        agent_id = event.data["agent_id"]
        logger.info("Handling agent.deactivated: %s", agent_id)
        await self._delegation_cache.revoke_all_for_agent(agent_id)
