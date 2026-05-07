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
    """Mirrors the ``gatedhouse.membership_status`` Postgres enum."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING = "pending"

    @property
    def db_value(self) -> str:
        return self.value

    @classmethod
    def from_db_value(cls, value: str) -> MembershipStatus:
        for s in cls:
            if s.value == value:
                return s
        raise ValueError(f"Unknown membership_status value: {value!r}")
