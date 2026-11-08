# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Library-owned identity↔org memberships.

Memberships are never deleted. Every lifecycle transition runs in a single
transaction that first row-locks the membership, so a removal and the
revocation of its grants commit together, and concurrent transitions on the
same membership serialize. See docs/MODEL.md, "The membership lifecycle".
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

import psycopg
from psycopg import errors as pg_errors

from ._database import Database
from ._enums import EntityType, MembershipStatus
from ._exceptions import GatedhouseDatabaseError
from ._permission_cache import PermissionCache


class MembershipManager(ABC):
    """Manages an identity's membership of an org: the gate that lets its
    grants in that org count."""

    @abstractmethod
    def create_membership(self, identity_id: str, org_id: str,
                          entity_type: EntityType) -> None:
        """Create an ``ACTIVE`` membership.

        If the identity has a ``REMOVED`` membership in the org, it is
        revived instead: any grants left in that org are cleared, then the
        same row becomes ``ACTIVE`` with the given entity type. If a
        membership in any other status exists, the insert fails with a
        :class:`GatedhouseDatabaseError` whose ``__cause__`` is the unique
        violation.
        """

    @abstractmethod
    def remove_membership(self, identity_id: str, org_id: str) -> None:
        """Remove the identity from the org: in one transaction, set the
        status to ``REMOVED`` and revoke the identity's direct role
        assignments and group memberships in that org. The membership row
        is kept as history.

        If no membership exists, grants the identity holds in the org are
        still revoked, so afterwards it holds nothing there.
        """

    @abstractmethod
    def has_membership(self, identity_id: str, org_id: str) -> bool:
        """True if the identity is a member of the org in any status other
        than ``REMOVED``."""

    @abstractmethod
    def set_status(self, identity_id: str, org_id: str,
                   status: MembershipStatus) -> None:
        """Change the membership's status. Does nothing if no membership
        exists (except for ``REMOVED``, which behaves as
        :meth:`remove_membership`).

        - To ``REMOVED``: same as :meth:`remove_membership`.
        - From ``REMOVED`` to ``ACTIVE`` or ``PENDING``: revives the
          membership, clearing any grants left in the org first.
        - From ``REMOVED`` to ``SUSPENDED``: rejected with
          :class:`ValueError`; a removed identity has nothing to suspend.
        """

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
            # conn.transaction() opens a real transaction block even on an
            # autocommit (e.g. pooled) connection.
            with self._database.connection() as conn, conn.transaction(), \
                    conn.cursor() as cur:
                current = _lock_status(cur, identity_id, org_id)
                if current is MembershipStatus.REMOVED:
                    # Rejoin: same row, clean slate.
                    _clear_grants(cur, identity_id, org_id)
                    cur.execute(
                        "UPDATE gatedhouse.memberships "
                        "SET status = 'active'::gatedhouse.membership_status, "
                        "    entity_type = %s::gatedhouse.entity_type, "
                        "    updated_at = NOW() "
                        "WHERE identity_id = %s AND org_id = %s",
                        (entity_type.db_value, identity_id, org_id),
                    )
                else:
                    # No row, or a live one: a live row makes this insert
                    # fail with the unique violation, exactly as before.
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

    def remove_membership(self, identity_id: str, org_id: str) -> None:
        try:
            with self._database.connection() as conn, conn.transaction(), \
                    conn.cursor() as cur:
                current = _lock_status(cur, identity_id, org_id)
                if current is not None and current is not MembershipStatus.REMOVED:
                    _update_status(cur, identity_id, org_id, MembershipStatus.REMOVED)
                # Also when already REMOVED or absent: clears grants that
                # arrived after an earlier removal.
                _clear_grants(cur, identity_id, org_id)
        except pg_errors.Error as e:
            raise _fail("remove_membership", e) from e
        self._cache.invalidate(identity_id, org_id)

    def has_membership(self, identity_id: str, org_id: str) -> bool:
        try:
            with self._database.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM gatedhouse.memberships "
                    "WHERE identity_id = %s AND org_id = %s "
                    "  AND status <> 'removed'",
                    (identity_id, org_id),
                )
                return cur.fetchone() is not None
        except pg_errors.Error as e:
            raise _fail("has_membership", e) from e

    def set_status(self, identity_id: str, org_id: str,
                   status: MembershipStatus) -> None:
        if status is MembershipStatus.REMOVED:
            self.remove_membership(identity_id, org_id)
            return
        try:
            with self._database.connection() as conn, conn.transaction(), \
                    conn.cursor() as cur:
                current = _lock_status(cur, identity_id, org_id)
                if current is None:
                    return
                if current is MembershipStatus.REMOVED:
                    if status is MembershipStatus.SUSPENDED:
                        raise ValueError(
                            f"Cannot suspend removed membership ({identity_id}, "
                            f"{org_id}); revive it as ACTIVE or PENDING instead"
                        )
                    # Rejoin: clean slate.
                    _clear_grants(cur, identity_id, org_id)
                _update_status(cur, identity_id, org_id, status)
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


# ---- transaction helpers ---------------------------------------------------


def _lock_status(cur: psycopg.Cursor, identity_id: str,
                 org_id: str) -> MembershipStatus | None:
    cur.execute(
        "SELECT status::TEXT FROM gatedhouse.memberships "
        "WHERE identity_id = %s AND org_id = %s FOR UPDATE",
        (identity_id, org_id),
    )
    row = cur.fetchone()
    return None if row is None else MembershipStatus.from_db_value(row[0])


def _update_status(cur: psycopg.Cursor, identity_id: str, org_id: str,
                   status: MembershipStatus) -> None:
    cur.execute(
        "UPDATE gatedhouse.memberships "
        "SET status = %s::gatedhouse.membership_status, updated_at = NOW() "
        "WHERE identity_id = %s AND org_id = %s",
        (status.db_value, identity_id, org_id),
    )


def _clear_grants(cur: psycopg.Cursor, identity_id: str, org_id: str) -> None:
    """Revoke the identity's direct roles and group memberships in the org."""
    for sql in (
        "DELETE FROM gatedhouse.role_assignments WHERE identity_id = %s AND org_id = %s",
        "DELETE FROM gatedhouse.group_memberships WHERE identity_id = %s AND org_id = %s",
    ):
        cur.execute(sql, (identity_id, org_id))


def _fail(op: str, cause: Exception) -> GatedhouseDatabaseError:
    return GatedhouseDatabaseError(f"MembershipManager.{op} failed: {cause}")
