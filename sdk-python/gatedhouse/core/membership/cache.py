"""Membership cache — PostgreSQL-backed cache for Citadel membership data."""

from __future__ import annotations

import json
import logging

from gatedhouse.core.types import CachedMembership
from gatedhouse.database.connection import DatabaseConnection

logger = logging.getLogger("gatedhouse.membership.cache")


class MembershipCache:
    """PostgreSQL-backed membership cache synced from Citadel events."""

    def __init__(self, db: DatabaseConnection) -> None:
        self._db = db

    async def upsert(self, membership: CachedMembership) -> None:
        await self._db.execute(
            """INSERT INTO gatedhouse_membership_cache
               (membership_id, org_id, entity_type, entity_id, is_owner, status, groups)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (membership_id) DO UPDATE SET
               org_id = EXCLUDED.org_id,
               entity_type = EXCLUDED.entity_type,
               entity_id = EXCLUDED.entity_id,
               is_owner = EXCLUDED.is_owner,
               status = EXCLUDED.status,
               groups = EXCLUDED.groups,
               synced_at = NOW()""",
            membership.membership_id,
            membership.org_id,
            membership.entity_type,
            membership.entity_id,
            membership.is_owner,
            membership.status,
            json.dumps(membership.groups),
        )

    async def find_by_id(self, membership_id: str) -> CachedMembership | None:
        row = await self._db.query_one(
            "SELECT * FROM gatedhouse_membership_cache WHERE membership_id = $1",
            membership_id,
        )
        return self._to_cached(row) if row else None

    async def update_status(self, membership_id: str, status: str) -> None:
        await self._db.execute(
            "UPDATE gatedhouse_membership_cache SET status = $2, synced_at = NOW() WHERE membership_id = $1",
            membership_id, status,
        )

    async def add_group(self, membership_id: str, group_id: str) -> None:
        await self._db.execute(
            """UPDATE gatedhouse_membership_cache
               SET groups = groups || $2::jsonb, synced_at = NOW()
               WHERE membership_id = $1
               AND NOT groups @> $2::jsonb""",
            membership_id, json.dumps([group_id]),
        )

    async def remove_group(self, membership_id: str, group_id: str) -> None:
        await self._db.execute(
            """UPDATE gatedhouse_membership_cache
               SET groups = (
                 SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)
                 FROM jsonb_array_elements(groups) AS elem
                 WHERE elem != $2::jsonb
               ), synced_at = NOW()
               WHERE membership_id = $1""",
            membership_id, json.dumps(group_id),
        )

    async def remove_group_from_all(self, group_id: str) -> None:
        await self._db.execute(
            """UPDATE gatedhouse_membership_cache
               SET groups = (
                 SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)
                 FROM jsonb_array_elements(groups) AS elem
                 WHERE elem != $1::jsonb
               ), synced_at = NOW()
               WHERE groups @> $1::jsonb""",
            json.dumps([group_id]),
        )

    async def remove(self, membership_id: str) -> None:
        await self._db.execute(
            "DELETE FROM gatedhouse_membership_cache WHERE membership_id = $1",
            membership_id,
        )

    async def remove_all_for_org(self, org_id: str) -> None:
        await self._db.execute(
            "DELETE FROM gatedhouse_membership_cache WHERE org_id = $1", org_id
        )

    async def suspend_all_for_org(self, org_id: str) -> None:
        await self._db.execute(
            "UPDATE gatedhouse_membership_cache SET status = 'suspended', synced_at = NOW() WHERE org_id = $1",
            org_id,
        )

    async def reactivate_all_for_org(self, org_id: str) -> None:
        await self._db.execute(
            "UPDATE gatedhouse_membership_cache SET status = 'active', synced_at = NOW() WHERE org_id = $1",
            org_id,
        )

    async def list_by_org(self, org_id: str) -> list[CachedMembership]:
        rows = await self._db.query(
            "SELECT * FROM gatedhouse_membership_cache WHERE org_id = $1",
            org_id,
        )
        return [self._to_cached(r) for r in rows]

    @staticmethod
    def _to_cached(row: dict) -> CachedMembership:
        groups = row["groups"]
        if isinstance(groups, str):
            groups = json.loads(groups)
        return CachedMembership(
            membership_id=row["membership_id"],
            org_id=row["org_id"],
            entity_type=row["entity_type"],
            entity_id=row["entity_id"],
            is_owner=row["is_owner"],
            status=row["status"],
            groups=groups,
            synced_at=row.get("synced_at"),
        )
