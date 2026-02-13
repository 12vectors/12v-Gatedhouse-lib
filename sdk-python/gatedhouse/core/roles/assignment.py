"""Role assignment manager — assign/revoke roles to memberships and groups."""

from __future__ import annotations

import logging

from gatedhouse.database.connection import DatabaseConnection

logger = logging.getLogger("gatedhouse.roles.assignment")


class RoleAssignmentManager:
    """Manages role-to-membership and role-to-group assignments."""

    def __init__(self, db: DatabaseConnection) -> None:
        self._db = db

    async def assign(
        self, membership_id: str, role_id: str, org_id: str, assigned_by: str | None = None
    ) -> None:
        await self._db.execute(
            """INSERT INTO gatedhouse_role_assignments (membership_id, role_id, org_id, assigned_by)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (membership_id, role_id) DO NOTHING""",
            membership_id, role_id, org_id, assigned_by,
        )

    async def revoke(self, membership_id: str, role_id: str) -> None:
        await self._db.execute(
            "DELETE FROM gatedhouse_role_assignments WHERE membership_id = $1 AND role_id = $2",
            membership_id, role_id,
        )

    async def get_role_ids(self, membership_id: str) -> list[str]:
        rows = await self._db.query(
            "SELECT role_id FROM gatedhouse_role_assignments WHERE membership_id = $1",
            membership_id,
        )
        return [r["role_id"] for r in rows]

    async def assign_to_group(
        self, group_id: str, role_id: str, org_id: str, assigned_by: str | None = None
    ) -> None:
        await self._db.execute(
            """INSERT INTO gatedhouse_group_roles (group_id, role_id, org_id, assigned_by)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (group_id, role_id) DO NOTHING""",
            group_id, role_id, org_id, assigned_by,
        )

    async def revoke_from_group(self, group_id: str, role_id: str) -> None:
        await self._db.execute(
            "DELETE FROM gatedhouse_group_roles WHERE group_id = $1 AND role_id = $2",
            group_id, role_id,
        )

    async def get_role_ids_for_groups(self, group_ids: list[str]) -> list[str]:
        if not group_ids:
            return []
        # Build parameterized IN clause
        placeholders = ", ".join(f"${i+1}" for i in range(len(group_ids)))
        rows = await self._db.query(
            f"SELECT DISTINCT role_id FROM gatedhouse_group_roles WHERE group_id IN ({placeholders})",
            *group_ids,
        )
        return [r["role_id"] for r in rows]

    async def delete_all_for_membership(self, membership_id: str) -> None:
        await self._db.execute(
            "DELETE FROM gatedhouse_role_assignments WHERE membership_id = $1",
            membership_id,
        )

    async def delete_all_for_org(self, org_id: str) -> None:
        await self._db.execute(
            "DELETE FROM gatedhouse_role_assignments WHERE org_id = $1", org_id
        )

    async def delete_all_group_roles_for_org(self, org_id: str) -> None:
        await self._db.execute(
            "DELETE FROM gatedhouse_group_roles WHERE org_id = $1", org_id
        )

    async def delete_all_for_group(self, group_id: str) -> None:
        await self._db.execute(
            "DELETE FROM gatedhouse_group_roles WHERE group_id = $1", group_id
        )
