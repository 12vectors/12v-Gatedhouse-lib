"""Permission resolver — walks the role inheritance DAG and computes
the effective permission set for a membership.

Materializes permissions into the gatedhouse_resolved_permissions table
for fast lookups at request time.
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

from gatedhouse.core.types import ResolvedPermission
from gatedhouse.database.connection import DatabaseConnection
from gatedhouse.core.roles.repository import RoleRepository
from gatedhouse.core.roles.assignment import RoleAssignmentManager

logger = logging.getLogger("gatedhouse.roles.resolver")

RoleSource = Callable[[str, str], Awaitable[list[str]]]


class PermissionResolver:
    """Resolves effective permissions through role inheritance DAG."""

    def __init__(
        self,
        db: DatabaseConnection,
        role_repo: RoleRepository,
        assignments: RoleAssignmentManager,
    ) -> None:
        self._db = db
        self._role_repo = role_repo
        self._assignments = assignments
        self._custom_sources: dict[str, RoleSource] = {}

    def add_source(self, name: str, source: RoleSource) -> None:
        """Register a custom role source for extending role resolution."""
        self._custom_sources[name] = source

    async def resolve_roles(
        self, membership_id: str, org_id: str, groups: list[str]
    ) -> list[str]:
        """Resolve all effective roles for a membership (direct + group + custom)."""
        role_set: set[str] = set()

        direct_roles = await self._assignments.get_role_ids(membership_id)
        role_set.update(direct_roles)

        group_roles = await self._assignments.get_role_ids_for_groups(groups)
        role_set.update(group_roles)

        for name, source in self._custom_sources.items():
            try:
                custom_roles = await source(membership_id, org_id)
                role_set.update(custom_roles)
            except Exception:
                logger.exception("Custom role source '%s' failed", name)

        return list(role_set)

    async def resolve_permissions(
        self, membership_id: str, org_id: str, groups: list[str]
    ) -> list[str]:
        """Resolve all effective permissions by walking the role inheritance DAG."""
        roles = await self.resolve_roles(membership_id, org_id, groups)
        permission_set: set[str] = set()
        visited: set[str] = set()

        for role_id in roles:
            await self._collect_permissions(org_id, role_id, permission_set, visited)

        return list(permission_set)

    async def rebuild_for_membership(
        self, membership_id: str, org_id: str, groups: list[str]
    ) -> list[str]:
        """Rebuild the materialized permission cache for a membership."""
        roles = await self.resolve_roles(membership_id, org_id, groups)
        permission_map: dict[str, str] = {}
        visited: set[str] = set()

        for role_id in roles:
            await self._collect_permissions_with_source(
                org_id, role_id, "direct", permission_map, visited
            )

        async with self._db.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "DELETE FROM gatedhouse_resolved_permissions WHERE membership_id = $1",
                    membership_id,
                )
                if permission_map:
                    await conn.executemany(
                        """INSERT INTO gatedhouse_resolved_permissions (membership_id, permission, source)
                           VALUES ($1, $2, $3)
                           ON CONFLICT (membership_id, permission) DO UPDATE SET source = EXCLUDED.source""",
                        [(membership_id, perm, src) for perm, src in permission_map.items()],
                    )

        logger.debug(
            "Permissions rebuilt for %s: %d permissions",
            membership_id, len(permission_map),
        )
        return list(permission_map.keys())

    async def get_cached_permissions(self, membership_id: str) -> list[ResolvedPermission]:
        """Get cached resolved permissions for a membership."""
        rows = await self._db.query(
            "SELECT * FROM gatedhouse_resolved_permissions WHERE membership_id = $1",
            membership_id,
        )
        return [
            ResolvedPermission(
                membership_id=r["membership_id"],
                permission=r["permission"],
                source=r["source"],
            )
            for r in rows
        ]

    async def clear_for_membership(self, membership_id: str) -> None:
        """Delete cached permissions for a membership."""
        await self._db.execute(
            "DELETE FROM gatedhouse_resolved_permissions WHERE membership_id = $1",
            membership_id,
        )

    async def _collect_permissions(
        self,
        org_id: str,
        role_id: str,
        permission_set: set[str],
        visited: set[str],
    ) -> None:
        if role_id in visited:
            return
        visited.add(role_id)

        role = await self._role_repo.resolve(org_id, role_id)
        if not role:
            logger.warning("Role not found during resolution: org=%s role=%s", org_id, role_id)
            return

        permission_set.update(role.permissions)

        for parent_role_id in role.inherits:
            await self._collect_permissions(org_id, parent_role_id, permission_set, visited)

    async def _collect_permissions_with_source(
        self,
        org_id: str,
        role_id: str,
        source_prefix: str,
        permission_map: dict[str, str],
        visited: set[str],
    ) -> None:
        if role_id in visited:
            return
        visited.add(role_id)

        role = await self._role_repo.resolve(org_id, role_id)
        if not role:
            return

        source = f"{source_prefix}:{role_id}"
        for perm in role.permissions:
            if perm not in permission_map:
                permission_map[perm] = source

        for parent_role_id in role.inherits:
            await self._collect_permissions_with_source(
                org_id, parent_role_id, "inherited", permission_map, visited
            )
