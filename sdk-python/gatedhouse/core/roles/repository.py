"""Role repository — CRUD for role definitions with org + system scoping."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from gatedhouse.core.types import RoleDefinition, StoredRole
from gatedhouse.database.connection import DatabaseConnection

logger = logging.getLogger("gatedhouse.roles.repository")


class RoleRepository:
    """PostgreSQL-backed role storage."""

    def __init__(self, db: DatabaseConnection) -> None:
        self._db = db

    async def seed_base_roles(self, org_id: str, roles: list[RoleDefinition]) -> None:
        """Seed base roles for an organization (idempotent)."""
        for role in roles:
            await self._db.execute(
                """INSERT INTO gatedhouse_roles (id, org_id, name, description, permissions, inherits, is_system)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)
                   ON CONFLICT (id, org_id) DO NOTHING""",
                role.key, org_id, role.name, role.description,
                json.dumps(role.permissions), json.dumps(role.inherits or []),
                role.is_system,
            )

    async def create(self, org_id: str, role: RoleDefinition) -> StoredRole:
        """Create a new role definition."""
        row = await self._db.query_one(
            """INSERT INTO gatedhouse_roles (id, org_id, name, description, permissions, inherits, is_system)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING *""",
            role.key, org_id, role.name, role.description,
            json.dumps(role.permissions), json.dumps(role.inherits or []),
            role.is_system,
        )
        assert row is not None
        return self._to_stored(row)

    async def find_by_id(self, org_id: str, role_id: str) -> StoredRole | None:
        """Find a role by org and ID."""
        row = await self._db.query_one(
            "SELECT * FROM gatedhouse_roles WHERE org_id = $1 AND id = $2",
            org_id, role_id,
        )
        return self._to_stored(row) if row else None

    async def resolve(self, org_id: str, role_id: str) -> StoredRole | None:
        """Resolve a role, checking both org-specific and system roles."""
        # Try org-specific first
        role = await self.find_by_id(org_id, role_id)
        if role:
            return role
        # Try system role (org_id = '__system__')
        return await self.find_by_id("__system__", role_id)

    async def list_for_org(self, org_id: str) -> list[StoredRole]:
        """List all roles for an organization."""
        rows = await self._db.query(
            "SELECT * FROM gatedhouse_roles WHERE org_id = $1 ORDER BY name",
            org_id,
        )
        return [self._to_stored(r) for r in rows]

    async def update(
        self, org_id: str, role_id: str, role: RoleDefinition
    ) -> StoredRole | None:
        """Update a role definition."""
        row = await self._db.query_one(
            """UPDATE gatedhouse_roles
               SET name = $3, description = $4, permissions = $5, inherits = $6, updated_at = NOW()
               WHERE org_id = $1 AND id = $2
               RETURNING *""",
            org_id, role_id, role.name, role.description,
            json.dumps(role.permissions), json.dumps(role.inherits or []),
        )
        return self._to_stored(row) if row else None

    async def delete(self, org_id: str, role_id: str) -> bool:
        """Delete a role definition."""
        result = await self._db.execute(
            "DELETE FROM gatedhouse_roles WHERE org_id = $1 AND id = $2 AND is_system = FALSE",
            org_id, role_id,
        )
        return "DELETE 1" in result

    async def delete_all_for_org(self, org_id: str) -> None:
        """Delete all roles for an organization."""
        await self._db.execute(
            "DELETE FROM gatedhouse_roles WHERE org_id = $1", org_id
        )

    @staticmethod
    def _to_stored(row: dict) -> StoredRole:
        permissions = row["permissions"]
        if isinstance(permissions, str):
            permissions = json.loads(permissions)
        inherits = row["inherits"]
        if isinstance(inherits, str):
            inherits = json.loads(inherits)
        return StoredRole(
            id=row["id"],
            org_id=row["org_id"],
            name=row["name"],
            description=row.get("description"),
            permissions=permissions,
            inherits=inherits,
            is_system=row["is_system"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
