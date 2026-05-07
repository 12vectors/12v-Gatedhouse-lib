"""Group definitions and group↔identity membership."""

from __future__ import annotations

from abc import ABC, abstractmethod

from psycopg import errors as pg_errors

from ._database import Database
from ._exceptions import GatedhouseDatabaseError
from ._permission_cache import PermissionCache


class GroupManager(ABC):

    # ---- group definitions (per org) -------------------------------------

    @abstractmethod
    def create_group(self, group_id: str, org_id: str, name: str | None,
                     description: str | None) -> None: ...

    @abstractmethod
    def delete_group(self, group_id: str, org_id: str) -> None: ...

    @abstractmethod
    def has_group(self, group_id: str, org_id: str) -> bool: ...

    @abstractmethod
    def list_groups(self, org_id: str) -> list[str]: ...

    # ---- group membership -------------------------------------------------

    @abstractmethod
    def add_identity_to_group(self, group_id: str, org_id: str,
                              identity_id: str) -> None: ...

    @abstractmethod
    def remove_identity_from_group(self, group_id: str, org_id: str,
                                   identity_id: str) -> None: ...

    @abstractmethod
    def get_group_members(self, group_id: str, org_id: str) -> list[str]: ...

    @abstractmethod
    def get_identity_groups(self, identity_id: str, org_id: str) -> list[str]: ...


class DefaultGroupManager(GroupManager):

    def __init__(self, database: Database, cache: PermissionCache) -> None:
        self._database = database
        self._cache = cache

    # ---- group definitions -----------------------------------------------

    def create_group(self, group_id: str, org_id: str, name: str | None,
                     description: str | None) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatedhouse.groups "
                    "(id, org_id, name, description) VALUES (%s, %s, %s, %s)",
                    (group_id, org_id, name, description),
                )
        except pg_errors.Error as e:
            raise _fail("create_group", e) from e

    def delete_group(self, group_id: str, org_id: str) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM gatedhouse.groups WHERE id = %s AND org_id = %s",
                    (group_id, org_id),
                )
        except pg_errors.Error as e:
            raise _fail("delete_group", e) from e
        # Cascade dropped group_memberships and group_roles for every member.
        self._cache.invalidate_all()

    def has_group(self, group_id: str, org_id: str) -> bool:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM gatedhouse.groups "
                    "WHERE id = %s AND org_id = %s",
                    (group_id, org_id),
                )
                return cur.fetchone() is not None
        except pg_errors.Error as e:
            raise _fail("has_group", e) from e

    def list_groups(self, org_id: str) -> list[str]:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM gatedhouse.groups "
                    "WHERE org_id = %s ORDER BY id",
                    (org_id,),
                )
                return [row[0] for row in cur.fetchall()]
        except pg_errors.Error as e:
            raise _fail("list_groups", e) from e

    # ---- group membership -------------------------------------------------

    def add_identity_to_group(self, group_id: str, org_id: str,
                              identity_id: str) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatedhouse.group_memberships "
                    "(group_id, org_id, identity_id) VALUES (%s, %s, %s)",
                    (group_id, org_id, identity_id),
                )
        except pg_errors.Error as e:
            raise _fail("add_identity_to_group", e) from e
        self._cache.invalidate(identity_id, org_id)

    def remove_identity_from_group(self, group_id: str, org_id: str,
                                   identity_id: str) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM gatedhouse.group_memberships "
                    "WHERE group_id = %s AND org_id = %s AND identity_id = %s",
                    (group_id, org_id, identity_id),
                )
        except pg_errors.Error as e:
            raise _fail("remove_identity_from_group", e) from e
        self._cache.invalidate(identity_id, org_id)

    def get_group_members(self, group_id: str, org_id: str) -> list[str]:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT identity_id FROM gatedhouse.group_memberships "
                    "WHERE group_id = %s AND org_id = %s ORDER BY identity_id",
                    (group_id, org_id),
                )
                return [row[0] for row in cur.fetchall()]
        except pg_errors.Error as e:
            raise _fail("get_group_members", e) from e

    def get_identity_groups(self, identity_id: str, org_id: str) -> list[str]:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT group_id FROM gatedhouse.group_memberships "
                    "WHERE identity_id = %s AND org_id = %s ORDER BY group_id",
                    (identity_id, org_id),
                )
                return [row[0] for row in cur.fetchall()]
        except pg_errors.Error as e:
            raise _fail("get_identity_groups", e) from e


def _fail(op: str, cause: Exception) -> GatedhouseDatabaseError:
    return GatedhouseDatabaseError(f"GroupManager.{op} failed: {cause}")
