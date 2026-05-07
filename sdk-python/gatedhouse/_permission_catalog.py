"""Permission catalog (services / resources / actions) — the application
vocabulary. Mirrors the Java ``PermissionCatalog`` interface and
``DefaultPermissionCatalog`` impl."""

from __future__ import annotations

from abc import ABC, abstractmethod

from psycopg import errors as pg_errors

from ._database import Database
from ._exceptions import GatedhouseDatabaseError
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
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatedhouse.services (service, description) "
                    "VALUES (%s, %s)",
                    (service, description),
                )
        except pg_errors.Error as e:
            raise _fail("add_service", e) from e

    def remove_service(self, service: str) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM gatedhouse.services WHERE service = %s",
                    (service,),
                )
        except pg_errors.Error as e:
            raise _fail("remove_service", e) from e
        # Cascade dropped resources, actions, and any role_permissions
        # referencing them. Affected identity set is wide.
        self._cache.invalidate_all()

    def has_service(self, service: str) -> bool:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM gatedhouse.services WHERE service = %s",
                    (service,),
                )
                return cur.fetchone() is not None
        except pg_errors.Error as e:
            raise _fail("has_service", e) from e

    def list_services(self) -> list[str]:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT service FROM gatedhouse.services ORDER BY service"
                )
                return [row[0] for row in cur.fetchall()]
        except pg_errors.Error as e:
            raise _fail("list_services", e) from e

    # ---- resources --------------------------------------------------------

    def add_resource(self, service: str, resource: str,
                     description: str | None) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatedhouse.resources "
                    "(service, resource, description) VALUES (%s, %s, %s)",
                    (service, resource, description),
                )
        except pg_errors.Error as e:
            raise _fail("add_resource", e) from e

    def remove_resource(self, service: str, resource: str) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM gatedhouse.resources "
                    "WHERE service = %s AND resource = %s",
                    (service, resource),
                )
        except pg_errors.Error as e:
            raise _fail("remove_resource", e) from e
        self._cache.invalidate_all()

    def has_resource(self, service: str, resource: str) -> bool:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM gatedhouse.resources "
                    "WHERE service = %s AND resource = %s",
                    (service, resource),
                )
                return cur.fetchone() is not None
        except pg_errors.Error as e:
            raise _fail("has_resource", e) from e

    def list_resources(self, service: str) -> list[str]:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT resource FROM gatedhouse.resources "
                    "WHERE service = %s ORDER BY resource",
                    (service,),
                )
                return [row[0] for row in cur.fetchall()]
        except pg_errors.Error as e:
            raise _fail("list_resources", e) from e

    # ---- actions ----------------------------------------------------------

    def add_action(self, service: str, resource: str, action: str,
                   description: str | None) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatedhouse.actions "
                    "(service, resource, action, description) "
                    "VALUES (%s, %s, %s, %s)",
                    (service, resource, action, description),
                )
        except pg_errors.Error as e:
            raise _fail("add_action", e) from e

    def remove_action(self, service: str, resource: str, action: str) -> None:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM gatedhouse.actions "
                    "WHERE service = %s AND resource = %s AND action = %s",
                    (service, resource, action),
                )
        except pg_errors.Error as e:
            raise _fail("remove_action", e) from e
        self._cache.invalidate_all()

    def has_action(self, service: str, resource: str, action: str) -> bool:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM gatedhouse.actions "
                    "WHERE service = %s AND resource = %s AND action = %s",
                    (service, resource, action),
                )
                return cur.fetchone() is not None
        except pg_errors.Error as e:
            raise _fail("has_action", e) from e

    def list_actions(self, service: str, resource: str) -> list[str]:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT action FROM gatedhouse.actions "
                    "WHERE service = %s AND resource = %s ORDER BY action",
                    (service, resource),
                )
                return [row[0] for row in cur.fetchall()]
        except pg_errors.Error as e:
            raise _fail("list_actions", e) from e


def _fail(op: str, cause: Exception) -> GatedhouseDatabaseError:
    return GatedhouseDatabaseError(f"PermissionCatalog.{op} failed: {cause}")
