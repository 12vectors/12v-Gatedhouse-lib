"""Core type definitions for the Gatedhouse authorization library."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Literal


# ─── Identity Types ────────────────────────────────────────────────

IdentityType = Literal["human", "agent", "machine"]

AuthMethod = Literal[
    "password",
    "sso",
    "passkey",
    "client_credentials",
    "api_key",
    "workload",
    "token_exchange",
]


@dataclass(frozen=True)
class Identity:
    id: str
    type: IdentityType
    auth_method: AuthMethod
    email: str | None = None
    name: str | None = None
    mfa_verified: bool | None = None


# ─── Organization ──────────────────────────────────────────────────


@dataclass(frozen=True)
class OrgContext:
    id: str


# ─── Membership ────────────────────────────────────────────────────

EntityType = Literal["person", "agent", "service_account"]


@dataclass(frozen=True)
class MembershipContext:
    id: str
    entity_type: EntityType
    is_owner: bool
    status: str
    groups: tuple[str, ...] = ()


# ─── Delegation ────────────────────────────────────────────────────


@dataclass(frozen=True)
class DelegationContext:
    id: str
    delegator_id: str
    delegator_membership_id: str
    scopes: tuple[str, ...]
    constraints: dict[str, Any]
    expires_at: str
    uses_remaining: int | None = None


# ─── GatedContext ──────────────────────────────────────────────────


@dataclass(frozen=True)
class GatedContext:
    identity: Identity
    org: OrgContext
    membership: MembershipContext
    roles: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    scopes: tuple[str, ...] | None = None
    delegation: DelegationContext | None = None


# ─── Role Definition ───────────────────────────────────────────────


@dataclass
class RoleDefinition:
    key: str
    name: str
    description: str | None = None
    permissions: list[str] = field(default_factory=list)
    inherits: list[str] = field(default_factory=list)
    is_system: bool = False


@dataclass
class StoredRole:
    id: str
    org_id: str
    name: str
    description: str | None
    permissions: list[str]
    inherits: list[str]
    is_system: bool
    created_at: datetime
    updated_at: datetime


# ─── Permission Check Result ───────────────────────────────────────


@dataclass(frozen=True)
class PermissionCheckResult:
    allowed: bool
    source: str | None = None


# ─── Events ────────────────────────────────────────────────────────


@dataclass
class GatehouseEvent:
    type: str
    timestamp: str
    data: dict[str, Any]


# ─── Cached Types ──────────────────────────────────────────────────


@dataclass
class CachedMembership:
    membership_id: str
    org_id: str
    entity_type: EntityType
    entity_id: str
    is_owner: bool
    status: str
    groups: list[str]
    synced_at: datetime | None = None


@dataclass
class CachedDelegation:
    delegation_id: str
    agent_id: str
    delegator_id: str
    delegator_membership_id: str
    org_id: str
    scopes: list[str]
    constraints: dict[str, Any]
    max_uses: int | None
    use_count: int
    status: str
    expires_at: datetime
    synced_at: datetime | None = None


@dataclass(frozen=True)
class ResolvedPermission:
    membership_id: str
    permission: str
    source: str


# ─── Audit ─────────────────────────────────────────────────────────


@dataclass
class AuditEntry:
    action: str
    result: Literal["allowed", "denied"]
    ctx: GatedContext
    resource_type: str | None = None
    resource_id: str | None = None
    reason: str | None = None
