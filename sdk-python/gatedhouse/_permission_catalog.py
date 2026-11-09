# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Permission catalog (services / resources / actions) — the application
vocabulary. Mirrors the Java ``PermissionCatalog`` interface and
``DefaultPermissionCatalog`` impl."""

from __future__ import annotations

from abc import ABC, abstractmethod

from . import _sql
from ._database import Database
from ._permission_cache import PermissionCache


class PermissionCatalog(ABC):

    # ---- services ---------------------------------------------------------

    @abstractmethod
    def add_service(self, service: str, description: str | None) -> None: ...

    @abstractmethod
    def remove_service(self, service: str) -> None: ...

    @abstractmethod
    def has_service(self, service: str) -> bool: ...

    @abstractmethod
    def list_services(self) -> list[str]: ...

    # ---- resources --------------------------------------------------------

    @abstractmethod
    def add_resource(self, service: str, resource: str,
                     description: str | None) -> None: ...

    @abstractmethod
    def remove_resource(self, service: str, resource: str) -> None: ...

    @abstractmethod
    def has_resource(self, service: str, resource: str) -> bool: ...

    @abstractmethod
    def list_resources(self, service: str) -> list[str]: ...

    # ---- actions ----------------------------------------------------------

    @abstractmethod
    def add_action(self, service: str, resource: str, action: str,
                   description: str | None) -> None: ...

    @abstractmethod
    def remove_action(self, service: str, resource: str, action: str) -> None: ...

    @abstractmethod
    def has_action(self, service: str, resource: str, action: str) -> bool: ...

    @abstractmethod
    def list_actions(self, service: str, resource: str) -> list[str]: ...


class DefaultPermissionCatalog(PermissionCatalog):

    def __init__(self, database: Database, cache: PermissionCache) -> None:
        self._database = database
        self._cache = cache

    # ---- services ---------------------------------------------------------

    def add_service(self, service: str, description: str | None) -> None:
        _sql.write(self._database, "PermissionCatalog.add_service", lambda conn: _sql.execute(
            conn, "INSERT INTO gatedhouse.services (service, description) "
                "VALUES (%s, %s)",
                (service, description)))

    def remove_service(self, service: str) -> None:
        _sql.write(self._database, "PermissionCatalog.remove_service", lambda conn: _sql.execute(
            conn, "DELETE FROM gatedhouse.services WHERE service = %s",
                (service,)))
        # Cascade dropped resources, actions, and any role_permissions
        # referencing them. Affected identity set is wide.
        self._cache.invalidate_all()

    def has_service(self, service: str) -> bool:
        return _sql.read(self._database, "PermissionCatalog.has_service", lambda conn: _sql.exists(
            conn, "SELECT 1 FROM gatedhouse.services WHERE service = %s",
                (service,)))

    def list_services(self) -> list[str]:
        return _sql.read(self._database, "PermissionCatalog.list_services", lambda conn: _sql.strings(
            conn, "SELECT service FROM gatedhouse.services ORDER BY service"))

    # ---- resources --------------------------------------------------------

    def add_resource(self, service: str, resource: str,
                     description: str | None) -> None:
        _sql.write(self._database, "PermissionCatalog.add_resource", lambda conn: _sql.execute(
            conn, "INSERT INTO gatedhouse.resources "
                "(service, resource, description) VALUES (%s, %s, %s)",
                (service, resource, description)))

    def remove_resource(self, service: str, resource: str) -> None:
        _sql.write(self._database, "PermissionCatalog.remove_resource", lambda conn: _sql.execute(
            conn, "DELETE FROM gatedhouse.resources "
                "WHERE service = %s AND resource = %s",
                (service, resource)))
        self._cache.invalidate_all()

    def has_resource(self, service: str, resource: str) -> bool:
        return _sql.read(self._database, "PermissionCatalog.has_resource", lambda conn: _sql.exists(
            conn, "SELECT 1 FROM gatedhouse.resources "
                "WHERE service = %s AND resource = %s",
                (service, resource)))

    def list_resources(self, service: str) -> list[str]:
        return _sql.read(self._database, "PermissionCatalog.list_resources", lambda conn: _sql.strings(
            conn, "SELECT resource FROM gatedhouse.resources "
                "WHERE service = %s ORDER BY resource",
                (service,)))

    # ---- actions ----------------------------------------------------------

    def add_action(self, service: str, resource: str, action: str,
                   description: str | None) -> None:
        _sql.write(self._database, "PermissionCatalog.add_action", lambda conn: _sql.execute(
            conn, "INSERT INTO gatedhouse.actions "
                "(service, resource, action, description) "
                "VALUES (%s, %s, %s, %s)",
                (service, resource, action, description)))

    def remove_action(self, service: str, resource: str, action: str) -> None:
        _sql.write(self._database, "PermissionCatalog.remove_action", lambda conn: _sql.execute(
            conn, "DELETE FROM gatedhouse.actions "
                "WHERE service = %s AND resource = %s AND action = %s",
                (service, resource, action)))
        self._cache.invalidate_all()

    def has_action(self, service: str, resource: str, action: str) -> bool:
        return _sql.read(self._database, "PermissionCatalog.has_action", lambda conn: _sql.exists(
            conn, "SELECT 1 FROM gatedhouse.actions "
                "WHERE service = %s AND resource = %s AND action = %s",
                (service, resource, action)))

    def list_actions(self, service: str, resource: str) -> list[str]:
        return _sql.read(self._database, "PermissionCatalog.list_actions", lambda conn: _sql.strings(
            conn, "SELECT action FROM gatedhouse.actions "
                "WHERE service = %s AND resource = %s ORDER BY action",
                (service, resource)))
