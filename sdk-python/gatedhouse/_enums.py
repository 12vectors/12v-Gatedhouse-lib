# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Enumerated value types shared with the Postgres schema."""

from __future__ import annotations

from enum import Enum


class EntityType(Enum):
    """Mirrors the ``gatedhouse.entity_type`` Postgres enum."""

    USER = "user"
    AGENT = "agent"

    @property
    def db_value(self) -> str:
        return self.value

    @classmethod
    def from_db_value(cls, value: str) -> EntityType:
        for t in cls:
            if t.value == value:
                return t
        raise ValueError(f"Unknown entity_type value: {value!r}")


class MembershipStatus(Enum):
    """Mirrors the ``gatedhouse.membership_status`` Postgres enum.

    Only ``ACTIVE`` lets the identity's grants in the org count. See
    docs/MODEL.md, "The membership lifecycle".
    """

    #: A member in good standing: grants apply.
    ACTIVE = "active"
    #: Temporarily barred: grants are kept but ignored until reactivated.
    SUSPENDED = "suspended"
    #: Invited or being provisioned: grants may be prepared but are ignored.
    PENDING = "pending"
    #: Has left the org: grants were revoked; the row remains as history.
    REMOVED = "removed"

    @property
    def db_value(self) -> str:
        return self.value

    @classmethod
    def from_db_value(cls, value: str) -> MembershipStatus:
        for s in cls:
            if s.value == value:
                return s
        raise ValueError(f"Unknown membership_status value: {value!r}")
