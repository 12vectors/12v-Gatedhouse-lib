# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Top-level Gatedhouse interface and the default implementation that
wires everything together (managers, cache, JWT verifier).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from threading import Lock

from psycopg import errors as pg_errors

from ._config import GatedhouseConfig
from ._exceptions import GatedhouseDatabaseError
from ._group_manager import DefaultGroupManager, GroupManager
from ._jwt_verification import JwtVerification
from ._membership_manager import DefaultMembershipManager, MembershipManager
from ._permission_catalog import DefaultPermissionCatalog, PermissionCatalog
from ._role_manager import DefaultRoleManager, RoleManager
from ._types import AuthenticatedSubject, EffectivePermission


_LOAD_EFFECTIVE_PERMISSIONS_SQL = (
    "WITH RECURSIVE active_membership AS ( "
    "    SELECT 1 FROM gatedhouse.memberships "
    "    WHERE identity_id = %s AND org_id = %s AND status = 'active' "
    "), "
    "direct_roles AS ( "
    "    SELECT role_key FROM gatedhouse.role_assignments "
    "    WHERE identity_id = %s AND org_id = %s "
    "    UNION "
    "    SELECT gr.role_key "
    "    FROM gatedhouse.group_memberships gm "
    "    JOIN gatedhouse.group_roles gr "
    "      ON gr.group_id = gm.group_id AND gr.org_id = gm.org_id "
    "    WHERE gm.identity_id = %s AND gm.org_id = %s "
    "), "
    "all_roles AS ( "
    "    SELECT role_key FROM direct_roles "
    "    UNION "
    "    SELECT ri.parent_key "
    "    FROM gatedhouse.role_inherits ri "
    "    JOIN all_roles ar ON ar.role_key = ri.child_key "
    ") "
    "SELECT DISTINCT rp.service, rp.resource, rp.action "
    "FROM gatedhouse.role_permissions rp "
    "WHERE rp.role_key IN (SELECT role_key FROM all_roles) "
    "  AND EXISTS (SELECT 1 FROM active_membership)"
)


class Gatedhouse(ABC):
    """Top-level Gatedhouse handle. Implements the context manager
    protocol so it can be used with ``with`` for deterministic cleanup
    of the configured ``GroupSource``.
    """

    # ---- administrative sub-interfaces -----------------------------------

    @abstractmethod
    def permission_catalog(self) -> PermissionCatalog: ...

    @abstractmethod
    def role_manager(self) -> RoleManager: ...

    @abstractmethod
    def membership_manager(self) -> MembershipManager: ...

    @abstractmethod
    def group_manager(self) -> GroupManager: ...

    # ---- the core authorization check ------------------------------------

    @abstractmethod
    def has_permission(self, identity_id: str, org_id: str,
                       service: str, resource: str, action: str) -> bool: ...

    @abstractmethod
    def get_effective_permissions(self, identity_id: str,
                                  org_id: str) -> list[EffectivePermission]: ...

    @abstractmethod
    def get_roles(self, identity_id: str, org_id: str) -> list[str]: ...

    @abstractmethod
    def get_groups(self, identity_id: str, org_id: str) -> list[str]: ...

    # ---- JWT verification helper -----------------------------------------

    @abstractmethod
    def verify_token(self, jwt_token: str) -> AuthenticatedSubject: ...

    # ---- cache control ----------------------------------------------------

    @abstractmethod
    def invalidate_cache(self, identity_id: str, org_id: str) -> None: ...

    @abstractmethod
    def invalidate_all_cache(self) -> None: ...

    @abstractmethod
    def set_cache_bypass(self, bypass: bool) -> None: ...

    @abstractmethod
    def is_cache_bypassed(self) -> bool: ...

    # ---- lifecycle --------------------------------------------------------

    @abstractmethod
    def close(self) -> None: ...

    def __enter__(self) -> "Gatedhouse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class DefaultGatedhouse(Gatedhouse):

    def __init__(self, config: GatedhouseConfig) -> None:
        self._config = config
        self._cache = config.permission_cache
        self._permission_catalog = DefaultPermissionCatalog(
            config.database, self._cache)
        self._role_manager = DefaultRoleManager(config.database, self._cache)
        self._membership_manager = DefaultMembershipManager(
            config.database, self._cache)
        self._group_manager = DefaultGroupManager(config.database, self._cache)
        self._jwt = (
            JwtVerification(config.token_verifier)
            if config.token_verifier is not None
            else None
        )
        self._closed = False
        self._close_lock = Lock()
        self._cache_bypass = False
        self._bypass_lock = Lock()

    # ---- accessors --------------------------------------------------------

    def permission_catalog(self) -> PermissionCatalog:
        return self._permission_catalog

    def role_manager(self) -> RoleManager:
        return self._role_manager

    def membership_manager(self) -> MembershipManager:
        return self._membership_manager

    def group_manager(self) -> GroupManager:
        return self._group_manager

    # ---- core check + reads ----------------------------------------------

    def has_permission(self, identity_id: str, org_id: str,
                       service: str, resource: str, action: str) -> bool:
        for grant in self._effective_permissions_cached(identity_id, org_id):
            if (
                (grant.service is None or grant.service == service)
                and (grant.resource is None or grant.resource == resource)
                and (grant.action is None or grant.action == action)
            ):
                return True
        return False

    def get_effective_permissions(self, identity_id: str,
                                  org_id: str) -> list[EffectivePermission]:
        return list(self._effective_permissions_cached(identity_id, org_id))

    def get_roles(self, identity_id: str, org_id: str) -> list[str]:
        return self._role_manager.get_identity_roles(identity_id, org_id)

    def get_groups(self, identity_id: str, org_id: str) -> list[str]:
        return self._group_manager.get_identity_groups(identity_id, org_id)

    # ---- JWT verification ------------------------------------------------

    def verify_token(self, jwt_token: str) -> AuthenticatedSubject:
        if self._jwt is None:
            raise RuntimeError(
                "verify_token was called but no TokenVerifierConfig was "
                "supplied. Configure via "
                "GatedhouseConfig(token_verifier=TokenVerifierConfig(...))."
            )
        return self._jwt.verify(jwt_token)

    # ---- cache control ---------------------------------------------------

    def invalidate_cache(self, identity_id: str, org_id: str) -> None:
        self._cache.invalidate(identity_id, org_id)

    def invalidate_all_cache(self) -> None:
        self._cache.invalidate_all()

    def set_cache_bypass(self, bypass: bool) -> None:
        with self._bypass_lock:
            self._cache_bypass = bypass

    def is_cache_bypassed(self) -> bool:
        with self._bypass_lock:
            return self._cache_bypass

    # ---- lifecycle -------------------------------------------------------

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        self._config.group_source.close()

    # ---- internals -------------------------------------------------------

    def _effective_permissions_cached(self, identity_id: str,
                                      org_id: str) -> list[EffectivePermission]:
        if self.is_cache_bypassed():
            # Kill switch: skip the cache entirely on reads. We still
            # don't populate it — when bypass is cleared, the cache
            # starts cold.
            return self._load_effective_permissions(identity_id, org_id)
        hit = self._cache.get(identity_id, org_id)
        if hit is not None:
            return hit
        fresh = self._load_effective_permissions(identity_id, org_id)
        self._cache.put(identity_id, org_id, fresh)
        return fresh

    def _load_effective_permissions(self, identity_id: str,
                                    org_id: str) -> list[EffectivePermission]:
        try:
            with self._config.database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    _LOAD_EFFECTIVE_PERMISSIONS_SQL,
                    (
                        identity_id, org_id,  # active_membership
                        identity_id, org_id,  # direct_roles part 1
                        identity_id, org_id,  # direct_roles part 2 (groups)
                    ),
                )
                return [
                    EffectivePermission(row[0], row[1], row[2])
                    for row in cur.fetchall()
                ]
        except pg_errors.Error as e:
            raise GatedhouseDatabaseError(
                f"_load_effective_permissions failed: {e}"
            ) from e
