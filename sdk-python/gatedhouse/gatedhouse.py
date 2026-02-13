"""Main Gatedhouse orchestrator — wires all components together."""

from __future__ import annotations

import logging
from typing import Any

from gatedhouse.core.config import GatehouseConfig, ResolvedConfig, resolve_config
from gatedhouse.core.types import GatedContext, Identity, MembershipContext, OrgContext
from gatedhouse.core.permissions.checker import PermissionChecker
from gatedhouse.core.permissions.matcher import has_permission
from gatedhouse.core.roles.repository import RoleRepository
from gatedhouse.core.roles.assignment import RoleAssignmentManager
from gatedhouse.core.roles.resolver import PermissionResolver
from gatedhouse.core.membership.cache import MembershipCache
from gatedhouse.core.membership.resolver import MembershipResolver
from gatedhouse.core.delegation.cache import DelegationCache
from gatedhouse.core.delegation.resolver import DelegationResolver
from gatedhouse.core.policies.engine import PolicyEngine
from gatedhouse.database.connection import DatabaseConnection
from gatedhouse.database.migrations import MigrationRunner
from gatedhouse.events.handler import EventHandlerRegistry
from gatedhouse.events.adapters import EventBusAdapter, InMemoryEventBus, NoopEventBus
from gatedhouse.jwt.verifier import JwtVerifier
from gatedhouse.audit.logger import AuditLogger
from gatedhouse.metrics.collector import DefaultMetricsCollector

logger = logging.getLogger("gatedhouse")


class Gatedhouse:
    """Main orchestrator that wires all Gatedhouse components together."""

    def __init__(self, config: GatehouseConfig) -> None:
        self._raw_config = config
        self.config: ResolvedConfig = resolve_config(config)

        # Database
        self.db = DatabaseConnection(self.config)
        self.migrations = MigrationRunner(self.db, self.config.database.migrations_table)

        # JWT
        self.jwt_verifier = JwtVerifier(
            self.config.jwks_url, self.config.jwks_cache_ttl
        )

        # Core components
        self.checker = PermissionChecker()
        self.policy_engine = PolicyEngine()
        self.metrics = DefaultMetricsCollector()

        # Repositories
        self.role_repo = RoleRepository(self.db)
        self.role_assignments = RoleAssignmentManager(self.db)
        self.permission_resolver = PermissionResolver(
            self.db, self.role_repo, self.role_assignments
        )

        # Caches
        self.membership_cache = MembershipCache(self.db)
        self.membership_resolver = MembershipResolver(self.membership_cache)
        self.delegation_cache = DelegationCache(self.db)
        self.delegation_resolver = DelegationResolver(self.delegation_cache)

        # Event bus
        adapter_type = self.config.event_bus.adapter
        if adapter_type == "in_memory":
            self.event_bus: EventBusAdapter = InMemoryEventBus()
        else:
            self.event_bus = NoopEventBus()

        # Event handler
        self.event_handler = EventHandlerRegistry(
            membership_cache=self.membership_cache,
            delegation_cache=self.delegation_cache,
            role_repo=self.role_repo,
            role_assignments=self.role_assignments,
            permission_resolver=self.permission_resolver,
            config=self.config,
        )

        # Audit
        self.audit_logger = AuditLogger(self.config, self.event_bus)

    async def initialize(self) -> None:
        """Initialize database connection and run migrations."""
        await self.db.connect()
        applied = await self.migrations.up()
        if applied:
            logger.info("Applied %d migrations", len(applied))

        # Subscribe to events
        await self.event_bus.subscribe(
            ["citadel.*", "sphinx.*"],
            self.event_handler.handle,
        )

        logger.info("Gatedhouse initialized for service '%s'", self.config.service)

    async def shutdown(self) -> None:
        """Gracefully shut down all components."""
        await self.event_bus.disconnect()
        await self.db.close()
        logger.info("Gatedhouse shut down")

    async def build_context(
        self, token: str, headers: dict[str, str]
    ) -> GatedContext:
        """Build a GatedContext from a JWT token and request headers."""
        # Verify JWT
        identity = self.jwt_verifier.verify(token)
        if identity is None:
            raise PermissionError("Invalid or expired token")

        # Extract org context
        org_header = self.config.org_header.lower()
        org_id = headers.get(org_header)
        if self.config.org_required and not org_id:
            raise PermissionError(f"Missing required header: {self.config.org_header}")
        if not org_id:
            org_id = ""

        org = OrgContext(id=org_id)

        # Resolve membership
        membership_ctx = await self.membership_resolver.resolve(
            f"mbr_{identity.id}_{org_id}"
        )
        if membership_ctx is None:
            membership_ctx = MembershipContext(
                id=f"mbr_{identity.id}_{org_id}",
                entity_type="person" if identity.type == "human" else identity.type,
                is_owner=False,
                status="active",
                groups=(),
            )

        # Resolve permissions
        permissions = await self.permission_resolver.resolve_permissions(
            membership_ctx.id, org_id, list(membership_ctx.groups)
        )

        # Resolve roles
        roles = await self.permission_resolver.resolve_roles(
            membership_ctx.id, org_id, list(membership_ctx.groups)
        )

        # Resolve delegation (if agent)
        delegation = None
        if identity.type == "agent":
            delegation = await self.delegation_resolver.resolve(
                f"dlg_{identity.id}_{org_id}"
            )

        return GatedContext(
            identity=identity,
            org=org,
            membership=membership_ctx,
            roles=tuple(roles),
            permissions=tuple(permissions),
            delegation=delegation,
        )

    def check(self, ctx: GatedContext, required: str) -> bool:
        """Shorthand for permission check."""
        return self.checker.check(ctx, required).allowed
