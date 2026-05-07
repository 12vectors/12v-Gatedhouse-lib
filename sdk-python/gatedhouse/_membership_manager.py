"""Library-owned identity↔org memberships."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from psycopg import errors as pg_errors

from ._database import Database
from ._enums import EntityType, MembershipStatus
from ._exceptions import GatedhouseDatabaseError
from ._permission_cache import PermissionCache


class MembershipManager(ABC):

    @abstractmethod
    def create_membership(self, identity_id: str, org_id: str,
                          entity_type: EntityType) -> None: ...

    @abstractmethod
    def delete_membership(self, identity_id: str, org_id: str) -> None: ...

    @abstractmethod
    def has_membership(self, identity_id: str, org_id: str) -> bool: ...

    @abstractmethod
    def set_status(self, identity_id: str, org_id: str,
                   status: MembershipStatus) -> None: ...

    @abstractmethod
    def get_status(self, identity_id: str, org_id: str) -> MembershipStatus | None: ...

    @abstractmethod
    def get_entity_type(self, identity_id: str, org_id: str) -> EntityType | None: ...


class DefaultMembershipManager(MembershipManager):

    def __init__(self, database: Database, cache: PermissionCache) -> None:
        self._database = database
        self._cache = cache

    def create_membership(self, identity_id: str, org_id: str,
                          entity_type: EntityType) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatedhouse.memberships "
                    "(id, identity_id, org_id, entity_type, status) "
                    "VALUES (%s, %s, %s, %s::gatedhouse.entity_type, "
                    "        'active'::gatedhouse.membership_status)",
                    (uuid.uuid4(), identity_id, org_id, entity_type.db_value),
                )
        except pg_errors.Error as e:
            raise _fail("create_membership", e) from e
        self._cache.invalidate(identity_id, org_id)

    def delete_membership(self, identity_id: str, org_id: str) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM gatedhouse.memberships "
                    "WHERE identity_id = %s AND org_id = %s",
                    (identity_id, org_id),
                )
        except pg_errors.Error as e:
            raise _fail("delete_membership", e) from e
        self._cache.invalidate(identity_id, org_id)

    def has_membership(self, identity_id: str, org_id: str) -> bool:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM gatedhouse.memberships "
                    "WHERE identity_id = %s AND org_id = %s",
                    (identity_id, org_id),
                )
                return cur.fetchone() is not None
        except pg_errors.Error as e:
            raise _fail("has_membership", e) from e

    def set_status(self, identity_id: str, org_id: str,
                   status: MembershipStatus) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "UPDATE gatedhouse.memberships "
                    "SET status = %s::gatedhouse.membership_status, "
                    "    updated_at = NOW() "
                    "WHERE identity_id = %s AND org_id = %s",
                    (status.db_value, identity_id, org_id),
                )
        except pg_errors.Error as e:
            raise _fail("set_status", e) from e
        self._cache.invalidate(identity_id, org_id)

    def get_status(self, identity_id: str, org_id: str) -> MembershipStatus | None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT status::TEXT FROM gatedhouse.memberships "
                    "WHERE identity_id = %s AND org_id = %s",
                    (identity_id, org_id),
                )
                row = cur.fetchone()
                if row is None:
                    return None
                return MembershipStatus.from_db_value(row[0])
        except pg_errors.Error as e:
            raise _fail("get_status", e) from e

    def get_entity_type(self, identity_id: str, org_id: str) -> EntityType | None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT entity_type::TEXT FROM gatedhouse.memberships "
                    "WHERE identity_id = %s AND org_id = %s",
                    (identity_id, org_id),
                )
                row = cur.fetchone()
                if row is None:
                    return None
                return EntityType.from_db_value(row[0])
        except pg_errors.Error as e:
            raise _fail("get_entity_type", e) from e


def _fail(op: str, cause: Exception) -> GatedhouseDatabaseError:
    return GatedhouseDatabaseError(f"MembershipManager.{op} failed: {cause}")
