"""Role definitions, permission grants, inheritance, and role assignments."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from psycopg import errors as pg_errors

from ._database import Database
from ._exceptions import GatedhouseDatabaseError
from ._permission_cache import PermissionCache


class RoleManager(ABC):

    # ---- role definitions -------------------------------------------------

    @abstractmethod
    def create_role(self, key: str, name: str, description: str | None) -> None: ...

    @abstractmethod
    def delete_role(self, key: str) -> None: ...

    @abstractmethod
    def has_role(self, key: str) -> bool: ...

    @abstractmethod
    def list_roles(self) -> list[str]: ...

    # ---- permission grants on a role -------------------------------------
    # service / resource / action may be None to denote a wildcard at that
    # level. (None, None, None) grants superuser-equivalent permission.

    @abstractmethod
    def grant_permission(self, role_key: str, service: str | None,
                         resource: str | None, action: str | None) -> None: ...

    @abstractmethod
    def revoke_permission(self, role_key: str, service: str | None,
                          resource: str | None, action: str | None) -> None: ...

    # ---- role inheritance -------------------------------------------------

    @abstractmethod
    def add_parent_role(self, child_key: str, parent_key: str) -> None: ...

    @abstractmethod
    def remove_parent_role(self, child_key: str, parent_key: str) -> None: ...

    @abstractmethod
    def get_parent_roles(self, child_key: str) -> list[str]: ...

    # ---- assignments to identities (per org) -----------------------------

    @abstractmethod
    def assign_to_identity(self, identity_id: str, org_id: str,
                           role_key: str) -> None: ...

    @abstractmethod
    def revoke_from_identity(self, identity_id: str, org_id: str,
                             role_key: str) -> None: ...

    @abstractmethod
    def get_identity_roles(self, identity_id: str, org_id: str) -> list[str]: ...

    # ---- assignments to groups (per org) ---------------------------------

    @abstractmethod
    def assign_to_group(self, group_id: str, org_id: str,
                        role_key: str) -> None: ...

    @abstractmethod
    def revoke_from_group(self, group_id: str, org_id: str,
                          role_key: str) -> None: ...

    @abstractmethod
    def get_group_roles(self, group_id: str, org_id: str) -> list[str]: ...


class DefaultRoleManager(RoleManager):

    def __init__(self, database: Database, cache: PermissionCache) -> None:
        self._database = database
        self._cache = cache

    # ---- role definitions -------------------------------------------------

    def create_role(self, key: str, name: str, description: str | None) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatedhouse.roles "
                    "(key, name, description, is_system) VALUES (%s, %s, %s, FALSE)",
                    (key, name, description),
                )
        except pg_errors.Error as e:
            raise _fail("create_role", e) from e

    def delete_role(self, key: str) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM gatedhouse.roles "
                    "WHERE key = %s AND is_system = FALSE",
                    (key,),
                )
        except pg_errors.Error as e:
            raise _fail("delete_role", e) from e
        # Cascade dropped every assignment of this role.
        self._cache.invalidate_all()

    def has_role(self, key: str) -> bool:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM gatedhouse.roles WHERE key = %s", (key,)
                )
                return cur.fetchone() is not None
        except pg_errors.Error as e:
            raise _fail("has_role", e) from e

    def list_roles(self) -> list[str]:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute("SELECT key FROM gatedhouse.roles ORDER BY key")
                return [row[0] for row in cur.fetchall()]
        except pg_errors.Error as e:
            raise _fail("list_roles", e) from e

    # ---- permission grants ------------------------------------------------

    def grant_permission(self, role_key: str, service: str | None,
                         resource: str | None, action: str | None) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatedhouse.role_permissions "
                    "(id, role_key, service, resource, action) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (uuid.uuid4(), role_key, service, resource, action),
                )
        except pg_errors.Error as e:
            raise _fail("grant_permission", e) from e
        # Affects every identity holding this role (directly, via group, or
        # via inheritance). Wholesale invalidate.
        self._cache.invalidate_all()

    def revoke_permission(self, role_key: str, service: str | None,
                          resource: str | None, action: str | None) -> None:
        try:
            # Match on COALESCE so NULLs (wildcards) compare correctly.
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM gatedhouse.role_permissions "
                    "WHERE role_key = %s "
                    "  AND COALESCE(service,  '') = COALESCE(%s, '') "
                    "  AND COALESCE(resource, '') = COALESCE(%s, '') "
                    "  AND COALESCE(action,   '') = COALESCE(%s, '')",
                    (role_key, service, resource, action),
                )
        except pg_errors.Error as e:
            raise _fail("revoke_permission", e) from e
        self._cache.invalidate_all()

    # ---- role inheritance -------------------------------------------------

    def add_parent_role(self, child_key: str, parent_key: str) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatedhouse.role_inherits "
                    "(child_key, parent_key) VALUES (%s, %s)",
                    (child_key, parent_key),
                )
        except pg_errors.Error as e:
            raise _fail("add_parent_role", e) from e
        self._cache.invalidate_all()

    def remove_parent_role(self, child_key: str, parent_key: str) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM gatedhouse.role_inherits "
                    "WHERE child_key = %s AND parent_key = %s",
                    (child_key, parent_key),
                )
        except pg_errors.Error as e:
            raise _fail("remove_parent_role", e) from e
        self._cache.invalidate_all()

    def get_parent_roles(self, child_key: str) -> list[str]:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT parent_key FROM gatedhouse.role_inherits "
                    "WHERE child_key = %s ORDER BY parent_key",
                    (child_key,),
                )
                return [row[0] for row in cur.fetchall()]
        except pg_errors.Error as e:
            raise _fail("get_parent_roles", e) from e

    # ---- assignments to identities ----------------------------------------

    def assign_to_identity(self, identity_id: str, org_id: str,
                           role_key: str) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatedhouse.role_assignments "
                    "(id, identity_id, org_id, role_key) "
                    "VALUES (%s, %s, %s, %s)",
                    (uuid.uuid4(), identity_id, org_id, role_key),
                )
        except pg_errors.Error as e:
            raise _fail("assign_to_identity", e) from e
        self._cache.invalidate(identity_id, org_id)

    def revoke_from_identity(self, identity_id: str, org_id: str,
                             role_key: str) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM gatedhouse.role_assignments "
                    "WHERE identity_id = %s AND org_id = %s AND role_key = %s",
                    (identity_id, org_id, role_key),
                )
        except pg_errors.Error as e:
            raise _fail("revoke_from_identity", e) from e
        self._cache.invalidate(identity_id, org_id)

    def get_identity_roles(self, identity_id: str, org_id: str) -> list[str]:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT role_key FROM gatedhouse.role_assignments "
                    "WHERE identity_id = %s AND org_id = %s ORDER BY role_key",
                    (identity_id, org_id),
                )
                return [row[0] for row in cur.fetchall()]
        except pg_errors.Error as e:
            raise _fail("get_identity_roles", e) from e

    # ---- assignments to groups --------------------------------------------

    def assign_to_group(self, group_id: str, org_id: str, role_key: str) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatedhouse.group_roles "
                    "(group_id, org_id, role_key) VALUES (%s, %s, %s)",
                    (group_id, org_id, role_key),
                )
        except pg_errors.Error as e:
            raise _fail("assign_to_group", e) from e
        # Affects every member of the group; cache doesn't index by group
        # membership, so wholesale invalidate.
        self._cache.invalidate_all()

    def revoke_from_group(self, group_id: str, org_id: str, role_key: str) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM gatedhouse.group_roles "
                    "WHERE group_id = %s AND org_id = %s AND role_key = %s",
                    (group_id, org_id, role_key),
                )
        except pg_errors.Error as e:
            raise _fail("revoke_from_group", e) from e
        self._cache.invalidate_all()

    def get_group_roles(self, group_id: str, org_id: str) -> list[str]:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT role_key FROM gatedhouse.group_roles "
                    "WHERE group_id = %s AND org_id = %s ORDER BY role_key",
                    (group_id, org_id),
                )
                return [row[0] for row in cur.fetchall()]
        except pg_errors.Error as e:
            raise _fail("get_group_roles", e) from e


def _fail(op: str, cause: Exception) -> GatedhouseDatabaseError:
    return GatedhouseDatabaseError(f"RoleManager.{op} failed: {cause}")
