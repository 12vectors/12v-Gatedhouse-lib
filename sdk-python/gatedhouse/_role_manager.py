# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Role definitions, permission grants, inheritance, and role assignments."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from . import _sql
from ._database import Database
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


#: Serializes role-inheritance edits across every process and instance sharing
#: the database (same key as the Java and Rust SDKs). Transaction-scoped:
#: released at commit or rollback, never left on a pooled connection.
INHERITANCE_LOCK_KEY = 0x6768726F6C65696E  # 'ghrolein'


class DefaultRoleManager(RoleManager):

    def __init__(self, database: Database, cache: PermissionCache) -> None:
        self._database = database
        self._cache = cache

    # ---- role definitions -------------------------------------------------

    def create_role(self, key: str, name: str, description: str | None) -> None:
        _sql.write(self._database, "RoleManager.create_role", lambda conn: _sql.execute(
            conn, "INSERT INTO gatedhouse.roles "
                "(key, name, description, is_system) VALUES (%s, %s, %s, FALSE)",
                (key, name, description)))

    def delete_role(self, key: str) -> None:
        _sql.write(self._database, "RoleManager.delete_role", lambda conn: _sql.execute(
            conn, "DELETE FROM gatedhouse.roles "
                "WHERE key = %s AND is_system = FALSE",
                (key,)))
        # Cascade dropped every assignment of this role.
        self._cache.invalidate_all()

    def has_role(self, key: str) -> bool:
        return _sql.read(self._database, "RoleManager.has_role", lambda conn: _sql.exists(
            conn, "SELECT 1 FROM gatedhouse.roles WHERE key = %s", (key,)))

    def list_roles(self) -> list[str]:
        return _sql.read(self._database, "RoleManager.list_roles", lambda conn: _sql.strings(
            conn, "SELECT key FROM gatedhouse.roles ORDER BY key"))

    # ---- permission grants ------------------------------------------------

    def grant_permission(self, role_key: str, service: str | None,
                         resource: str | None, action: str | None) -> None:
        _sql.write(self._database, "RoleManager.grant_permission", lambda conn: _sql.execute(
            conn, "INSERT INTO gatedhouse.role_permissions "
                "(id, role_key, service, resource, action) "
                "VALUES (%s, %s, %s, %s, %s)",
                (uuid.uuid4(), role_key, service, resource, action)))
        # Affects every identity holding this role (directly, via group, or
        # via inheritance). Wholesale invalidate.
        self._cache.invalidate_all()

    def revoke_permission(self, role_key: str, service: str | None,
                          resource: str | None, action: str | None) -> None:
        # Match on COALESCE so NULLs (wildcards) compare correctly.
        _sql.write(self._database, "RoleManager.revoke_permission", lambda conn: _sql.execute(
            conn, "DELETE FROM gatedhouse.role_permissions "
                "WHERE role_key = %s "
                "  AND COALESCE(service,  '') = COALESCE(%s, '') "
                "  AND COALESCE(resource, '') = COALESCE(%s, '') "
                "  AND COALESCE(action,   '') = COALESCE(%s, '')",
                (role_key, service, resource, action)))
        self._cache.invalidate_all()

    # ---- role inheritance -------------------------------------------------

    def add_parent_role(self, child_key: str, parent_key: str) -> None:
        """Inheritance must stay acyclic. The check and the insert run in one
        transaction under :data:`INHERITANCE_LOCK_KEY`, so concurrent calls
        adding ``A -> B`` and ``B -> A`` cannot both succeed.

        :raises ValueError: if the edge would create an inheritance cycle.
        """
        def add(conn) -> None:
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (INHERITANCE_LOCK_KEY,))
            # Would the new edge close a cycle? Only if the child is already
            # the parent itself or one of the parent's ancestors.
            if child_key != parent_key and _sql.exists(
                    conn,
                    "WITH RECURSIVE ancestors(key) AS ( "
                    "    SELECT %s::TEXT "
                    "    UNION "
                    "    SELECT ri.parent_key FROM gatedhouse.role_inherits ri "
                    "    JOIN ancestors a ON ri.child_key = a.key "
                    ") SELECT 1 FROM ancestors WHERE key = %s",
                    (parent_key, child_key)):
                raise ValueError(
                    f"Role '{child_key}' cannot inherit from '{parent_key}': "
                    f"'{parent_key}' already inherits from '{child_key}', so this "
                    "would create an inheritance cycle")
            _sql.execute(
                conn,
                "INSERT INTO gatedhouse.role_inherits (child_key, parent_key) "
                "VALUES (%s, %s)",
                (child_key, parent_key))

        _sql.write(self._database, "RoleManager.add_parent_role", add)
        self._cache.invalidate_all()

    def remove_parent_role(self, child_key: str, parent_key: str) -> None:
        _sql.write(self._database, "RoleManager.remove_parent_role", lambda conn: _sql.execute(
            conn, "DELETE FROM gatedhouse.role_inherits "
                "WHERE child_key = %s AND parent_key = %s",
                (child_key, parent_key)))
        self._cache.invalidate_all()

    def get_parent_roles(self, child_key: str) -> list[str]:
        return _sql.read(self._database, "RoleManager.get_parent_roles", lambda conn: _sql.strings(
            conn, "SELECT parent_key FROM gatedhouse.role_inherits "
                "WHERE child_key = %s ORDER BY parent_key",
                (child_key,)))

    # ---- assignments to identities ----------------------------------------

    def assign_to_identity(self, identity_id: str, org_id: str,
                           role_key: str) -> None:
        _sql.write(self._database, "RoleManager.assign_to_identity", lambda conn: _sql.execute(
            conn, "INSERT INTO gatedhouse.role_assignments "
                "(id, identity_id, org_id, role_key) "
                "VALUES (%s, %s, %s, %s)",
                (uuid.uuid4(), identity_id, org_id, role_key)))
        self._cache.invalidate(identity_id, org_id)

    def revoke_from_identity(self, identity_id: str, org_id: str,
                             role_key: str) -> None:
        _sql.write(self._database, "RoleManager.revoke_from_identity", lambda conn: _sql.execute(
            conn, "DELETE FROM gatedhouse.role_assignments "
                "WHERE identity_id = %s AND org_id = %s AND role_key = %s",
                (identity_id, org_id, role_key)))
        self._cache.invalidate(identity_id, org_id)

    def get_identity_roles(self, identity_id: str, org_id: str) -> list[str]:
        return _sql.read(self._database, "RoleManager.get_identity_roles", lambda conn: _sql.strings(
            conn, "SELECT role_key FROM gatedhouse.role_assignments "
                "WHERE identity_id = %s AND org_id = %s ORDER BY role_key",
                (identity_id, org_id)))

    # ---- assignments to groups --------------------------------------------

    def assign_to_group(self, group_id: str, org_id: str, role_key: str) -> None:
        _sql.write(self._database, "RoleManager.assign_to_group", lambda conn: _sql.execute(
            conn, "INSERT INTO gatedhouse.group_roles "
                "(group_id, org_id, role_key) VALUES (%s, %s, %s)",
                (group_id, org_id, role_key)))
        # Affects every member of the group; cache doesn't index by group
        # membership, so wholesale invalidate.
        self._cache.invalidate_all()

    def revoke_from_group(self, group_id: str, org_id: str, role_key: str) -> None:
        _sql.write(self._database, "RoleManager.revoke_from_group", lambda conn: _sql.execute(
            conn, "DELETE FROM gatedhouse.group_roles "
                "WHERE group_id = %s AND org_id = %s AND role_key = %s",
                (group_id, org_id, role_key)))
        self._cache.invalidate_all()

    def get_group_roles(self, group_id: str, org_id: str) -> list[str]:
        return _sql.read(self._database, "RoleManager.get_group_roles", lambda conn: _sql.strings(
            conn, "SELECT role_key FROM gatedhouse.group_roles "
                "WHERE group_id = %s AND org_id = %s ORDER BY role_key",
                (group_id, org_id)))
