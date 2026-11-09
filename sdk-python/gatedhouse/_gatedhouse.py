# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Top-level Gatedhouse interface and the default implementation that
wires everything together (managers, cache, JWT verifier).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from threading import Lock

from . import _sql
from ._config import GatedhouseConfig
from ._group_manager import DefaultGroupManager, GroupManager
from ._jwt_verification import JwtVerification
from ._membership_manager import DefaultMembershipManager, MembershipManager
from ._permission_cache import PermissionCache
from ._permission_catalog import DefaultPermissionCatalog, PermissionCatalog
from ._role_manager import DefaultRoleManager, RoleManager
from ._enums import MembershipStatus
from ._types import (
    AuthenticatedSubject,
    EffectivePermission,
    ExplanationOutcome,
    GrantPath,
    GrantSource,
    PermissionExplanation,
)


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

# One statement, so the status and the paths come from one snapshot. The path
# search mirrors _LOAD_EFFECTIVE_PERMISSIONS_SQL (same sources, same
# inheritance climb, same column-wise wildcard rule as has_permission) but
# carries the role chain, and reports paths whatever the membership status is.
_EXPLAIN_PERMISSION_SQL = (
    "WITH RECURSIVE sources AS ( "
    "    SELECT 'DIRECT' AS source, NULL::TEXT AS group_id, role_key "
    "    FROM gatedhouse.role_assignments "
    "    WHERE identity_id = %(identity)s AND org_id = %(org)s "
    "    UNION ALL "
    "    SELECT 'GROUP', gm.group_id, gr.role_key "
    "    FROM gatedhouse.group_memberships gm "
    "    JOIN gatedhouse.group_roles gr "
    "      ON gr.group_id = gm.group_id AND gr.org_id = gm.org_id "
    "    WHERE gm.identity_id = %(identity)s AND gm.org_id = %(org)s "
    "), "
    "chains AS ( "
    "    SELECT source, group_id, role_key AS at_role, ARRAY[role_key] AS chain "
    "    FROM sources "
    "    UNION ALL "
    "    SELECT c.source, c.group_id, ri.parent_key, c.chain || ri.parent_key "
    "    FROM chains c "
    "    JOIN gatedhouse.role_inherits ri ON ri.child_key = c.at_role "
    "    WHERE NOT (ri.parent_key = ANY (c.chain)) "
    "), "
    "paths AS ( "
    "    SELECT c.source, c.group_id, c.chain, rp.service, rp.resource, rp.action "
    "    FROM chains c "
    "    JOIN gatedhouse.role_permissions rp ON rp.role_key = c.at_role "
    "    WHERE (rp.service  IS NULL OR rp.service  = %(service)s) "
    "      AND (rp.resource IS NULL OR rp.resource = %(resource)s) "
    "      AND (rp.action   IS NULL OR rp.action   = %(action)s) "
    ") "
    "SELECT (SELECT status::TEXT FROM gatedhouse.memberships "
    "        WHERE identity_id = %(identity)s AND org_id = %(org)s) AS status, "
    "       p.source, p.group_id, p.chain, p.service, p.resource, p.action "
    "FROM (SELECT 1) AS one "
    "LEFT JOIN paths p ON TRUE "
    "ORDER BY p.source, p.group_id NULLS FIRST, cardinality(p.chain), p.chain"
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
    def explain_permission(self, identity_id: str, org_id: str,
                           service: str, resource: str,
                           action: str) -> PermissionExplanation:
        """Explain the decision :meth:`has_permission` makes for the same
        inputs: the identity's membership status, and every path through
        which it holds the permission (direct or via a group, through role
        inheritance, to the matching grant). Paths are reported even when
        the decision is a denial.

        A diagnostic, not a hot-path check: it bypasses the permission cache
        and always reads the database.
        """

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
    def set_cache_enabled(self, enabled: bool) -> None: ...

    @abstractmethod
    def is_cache_enabled(self) -> bool: ...

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
        # The configured cache, or a no-op stand-in when caching is off.
        # The stand-in keeps the managers' write-path invalidation
        # unconditional; the read path never touches it (guarded by
        # _cache_enabled below).
        self._cache_configured = config.permission_cache is not None
        self._cache = (
            config.permission_cache
            if config.permission_cache is not None
            else _NoOpPermissionCache()
        )
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
        self._cache_enabled = self._cache_configured
        self._cache_enabled_lock = Lock()

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

    def explain_permission(self, identity_id: str, org_id: str,
                           service: str, resource: str,
                           action: str) -> PermissionExplanation:
        params = {"identity": identity_id, "org": org_id,
                  "service": service, "resource": resource, "action": action}
        def query(conn) -> list:
            with conn.cursor() as cur:
                cur.execute(_EXPLAIN_PERMISSION_SQL, params)
                return cur.fetchall()

        rows = _sql.read(self._config.database, "explain_permission", query)

        status_value = rows[0][0]  # the LEFT JOIN always yields a row
        status = None if status_value is None else MembershipStatus.from_db_value(status_value)
        paths = tuple(
            GrantPath(
                source=GrantSource(source),
                group_id=group_id,
                role_chain=tuple(chain),
                grant=EffectivePermission(svc, res, act),
            )
            for (_, source, group_id, chain, svc, res, act) in rows
            if source is not None  # skip the placeholder row: no paths
        )
        if status is None:
            outcome = ExplanationOutcome.NO_MEMBERSHIP
        elif status is not MembershipStatus.ACTIVE:
            outcome = ExplanationOutcome.MEMBERSHIP_NOT_ACTIVE
        elif not paths:
            outcome = ExplanationOutcome.NO_MATCHING_GRANT
        else:
            outcome = ExplanationOutcome.ALLOWED
        return PermissionExplanation(outcome, status, paths)

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

    def set_cache_enabled(self, enabled: bool) -> None:
        with self._cache_enabled_lock:
            self._cache_enabled = enabled and self._cache_configured

    def is_cache_enabled(self) -> bool:
        with self._cache_enabled_lock:
            return self._cache_enabled

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
        if not self.is_cache_enabled():
            # No cache configured, or caching switched off at runtime:
            # skip the cache entirely on reads. We don't populate it
            # either — when caching is re-enabled, the cache starts cold.
            return self._load_effective_permissions(identity_id, org_id)
        hit = self._cache.get(identity_id, org_id)
        if hit is not None:
            return hit
        fresh = self._load_effective_permissions(identity_id, org_id)
        self._cache.put(identity_id, org_id, fresh)
        return fresh

    def _load_effective_permissions(self, identity_id: str,
                                    org_id: str) -> list[EffectivePermission]:
        def query(conn) -> list[EffectivePermission]:
            with conn.cursor() as cur:
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

        return _sql.read(self._config.database, "_load_effective_permissions", query)


class _NoOpPermissionCache(PermissionCache):
    """Stand-in used when no cache is configured; every method is a no-op."""

    def get(self, identity_id: str, org_id: str) -> list[EffectivePermission] | None:
        return None

    def put(self, identity_id: str, org_id: str,
            permissions: list[EffectivePermission]) -> None:
        pass

    def invalidate(self, identity_id: str, org_id: str) -> None:
        pass

    def invalidate_all(self) -> None:
        pass
