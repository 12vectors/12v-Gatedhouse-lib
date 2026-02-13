"""Delegation cache — PostgreSQL-backed cache for Sphinx delegation data."""

from __future__ import annotations

import json
import logging
from datetime import datetime

from gatedhouse.core.types import CachedDelegation
from gatedhouse.database.connection import DatabaseConnection

logger = logging.getLogger("gatedhouse.delegation.cache")


class DelegationCache:
    """PostgreSQL-backed delegation cache synced from Sphinx events."""

    def __init__(self, db: DatabaseConnection) -> None:
        self._db = db

    async def upsert(self, delegation: CachedDelegation) -> None:
        await self._db.execute(
            """INSERT INTO gatedhouse_delegation_cache
               (delegation_id, agent_id, delegator_id, delegator_membership_id,
                org_id, scopes, constraints, max_uses, use_count, status, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
               ON CONFLICT (delegation_id) DO UPDATE SET
               scopes = EXCLUDED.scopes,
               constraints = EXCLUDED.constraints,
               max_uses = EXCLUDED.max_uses,
               use_count = EXCLUDED.use_count,
               status = EXCLUDED.status,
               expires_at = EXCLUDED.expires_at,
               synced_at = NOW()""",
            delegation.delegation_id,
            delegation.agent_id,
            delegation.delegator_id,
            delegation.delegator_membership_id,
            delegation.org_id,
            json.dumps(delegation.scopes),
            json.dumps(delegation.constraints),
            delegation.max_uses,
            delegation.use_count,
            delegation.status,
            delegation.expires_at,
        )

    async def find_active(self, delegation_id: str) -> CachedDelegation | None:
        row = await self._db.query_one(
            """SELECT * FROM gatedhouse_delegation_cache
               WHERE delegation_id = $1 AND status = 'active'""",
            delegation_id,
        )
        return self._to_cached(row) if row else None

    async def update_status(self, delegation_id: str, status: str) -> None:
        await self._db.execute(
            "UPDATE gatedhouse_delegation_cache SET status = $2, synced_at = NOW() WHERE delegation_id = $1",
            delegation_id, status,
        )

    async def revoke_all_for_agent(self, agent_id: str) -> None:
        await self._db.execute(
            "UPDATE gatedhouse_delegation_cache SET status = 'revoked', synced_at = NOW() WHERE agent_id = $1",
            agent_id,
        )

    async def remove_all_for_org(self, org_id: str) -> None:
        await self._db.execute(
            "DELETE FROM gatedhouse_delegation_cache WHERE org_id = $1", org_id
        )

    @staticmethod
    def _to_cached(row: dict) -> CachedDelegation:
        scopes = row["scopes"]
        if isinstance(scopes, str):
            scopes = json.loads(scopes)
        constraints = row["constraints"]
        if isinstance(constraints, str):
            constraints = json.loads(constraints)
        return CachedDelegation(
            delegation_id=row["delegation_id"],
            agent_id=row["agent_id"],
            delegator_id=row["delegator_id"],
            delegator_membership_id=row["delegator_membership_id"],
            org_id=row["org_id"],
            scopes=scopes,
            constraints=constraints,
            max_uses=row["max_uses"],
            use_count=row["use_count"],
            status=row["status"],
            expires_at=row["expires_at"],
            synced_at=row.get("synced_at"),
        )
