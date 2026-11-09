# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Group definitions and group↔identity membership."""

from __future__ import annotations

from abc import ABC, abstractmethod

from . import _sql
from ._database import Database
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
        _sql.write(self._database, "GroupManager.create_group", lambda conn: _sql.execute(
            conn, "INSERT INTO gatedhouse.groups "
                "(id, org_id, name, description) VALUES (%s, %s, %s, %s)",
                (group_id, org_id, name, description)))

    def delete_group(self, group_id: str, org_id: str) -> None:
        _sql.write(self._database, "GroupManager.delete_group", lambda conn: _sql.execute(
            conn, "DELETE FROM gatedhouse.groups WHERE id = %s AND org_id = %s",
                (group_id, org_id)))
        # Cascade dropped group_memberships and group_roles for every member.
        self._cache.invalidate_all()

    def has_group(self, group_id: str, org_id: str) -> bool:
        return _sql.read(self._database, "GroupManager.has_group", lambda conn: _sql.exists(
            conn, "SELECT 1 FROM gatedhouse.groups "
                "WHERE id = %s AND org_id = %s",
                (group_id, org_id)))

    def list_groups(self, org_id: str) -> list[str]:
        return _sql.read(self._database, "GroupManager.list_groups", lambda conn: _sql.strings(
            conn, "SELECT id FROM gatedhouse.groups "
                "WHERE org_id = %s ORDER BY id",
                (org_id,)))

    # ---- group membership -------------------------------------------------

    def add_identity_to_group(self, group_id: str, org_id: str,
                              identity_id: str) -> None:
        _sql.write(self._database, "GroupManager.add_identity_to_group", lambda conn: _sql.execute(
            conn, "INSERT INTO gatedhouse.group_memberships "
                "(group_id, org_id, identity_id) VALUES (%s, %s, %s)",
                (group_id, org_id, identity_id)))
        self._cache.invalidate(identity_id, org_id)

    def remove_identity_from_group(self, group_id: str, org_id: str,
                                   identity_id: str) -> None:
        _sql.write(self._database, "GroupManager.remove_identity_from_group", lambda conn: _sql.execute(
            conn, "DELETE FROM gatedhouse.group_memberships "
                "WHERE group_id = %s AND org_id = %s AND identity_id = %s",
                (group_id, org_id, identity_id)))
        self._cache.invalidate(identity_id, org_id)

    def get_group_members(self, group_id: str, org_id: str) -> list[str]:
        return _sql.read(self._database, "GroupManager.get_group_members", lambda conn: _sql.strings(
            conn, "SELECT identity_id FROM gatedhouse.group_memberships "
                "WHERE group_id = %s AND org_id = %s ORDER BY identity_id",
                (group_id, org_id)))

    def get_identity_groups(self, identity_id: str, org_id: str) -> list[str]:
        return _sql.read(self._database, "GroupManager.get_identity_groups", lambda conn: _sql.strings(
            conn, "SELECT group_id FROM gatedhouse.group_memberships "
                "WHERE identity_id = %s AND org_id = %s ORDER BY group_id",
                (identity_id, org_id)))
