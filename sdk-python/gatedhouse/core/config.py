"""Gatedhouse configuration types and validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from gatedhouse.core.types import RoleDefinition


@dataclass
class DatabaseConfig:
    connection_string: str
    migrations_table: str = "gatedhouse_migrations"
    table_prefix: str = "gatedhouse_"
    pool_min: int = 2
    pool_max: int = 10


@dataclass
class EventBusConfig:
    adapter: Literal["kafka", "rabbitmq", "in_memory", "noop"] = "noop"
    topics: list[str] | None = None
    brokers: list[str] | None = None
    group_id: str | None = None
    url: str | None = None
    exchange: str | None = None


@dataclass
class AuditConfig:
    enabled: bool = True
    log_denied: bool = True
    log_allowed: bool = False


@dataclass
class DelegationConfig:
    enabled: bool = True
    cache_ttl: int = 60
    validate_live: bool = False
    allowed_identity_types: list[str] = field(
        default_factory=lambda: ["human", "agent", "machine"]
    )


DEFAULT_BASE_ROLES: list[RoleDefinition] = [
    RoleDefinition(
        key="owner",
        name="Owner",
        description="Organization owner with full access",
        permissions=["*:*:*"],
        is_system=True,
    ),
    RoleDefinition(
        key="admin",
        name="Administrator",
        description="Organization administrator with full access except ownership transfer",
        permissions=["*:*:*"],
        is_system=True,
    ),
    RoleDefinition(
        key="member",
        name="Member",
        description="Regular organization member with standard access",
        permissions=[],
        is_system=True,
    ),
    RoleDefinition(
        key="viewer",
        name="Viewer",
        description="Read-only access",
        permissions=[],
        is_system=True,
    ),
]


@dataclass
class GatehouseConfig:
    jwks_url: str
    database: DatabaseConfig
    service: str
    jwks_cache_ttl: int = 3600
    event_bus: EventBusConfig | None = None
    org_header: str = "X-Org-Id"
    org_required: bool = True
    cache_miss_strategy: Literal["fetch", "deny"] = "fetch"
    cache_miss_ttl: int = 60
    resolved_permissions_cache_ttl: int = 300
    audit: AuditConfig | None = None
    base_roles: list[RoleDefinition] | None = None
    default_role: str = "member"
    citadel_base_url: str | None = None
    delegation: DelegationConfig | None = None


@dataclass
class ResolvedConfig:
    jwks_url: str
    jwks_cache_ttl: int
    database: DatabaseConfig
    event_bus: EventBusConfig
    service: str
    org_header: str
    org_required: bool
    cache_miss_strategy: Literal["fetch", "deny"]
    cache_miss_ttl: int
    resolved_permissions_cache_ttl: int
    audit: AuditConfig
    base_roles: list[RoleDefinition]
    default_role: str
    citadel_base_url: str | None
    delegation: DelegationConfig


def resolve_config(config: GatehouseConfig) -> ResolvedConfig:
    """Validate and resolve configuration with defaults."""
    if not config.jwks_url:
        raise ValueError("Gatedhouse: jwks_url is required")
    if not config.database or not config.database.connection_string:
        raise ValueError("Gatedhouse: database.connection_string is required")
    if not config.service:
        raise ValueError("Gatedhouse: service name is required")

    return ResolvedConfig(
        jwks_url=config.jwks_url,
        jwks_cache_ttl=config.jwks_cache_ttl,
        database=config.database,
        event_bus=config.event_bus or EventBusConfig(),
        service=config.service,
        org_header=config.org_header,
        org_required=config.org_required,
        cache_miss_strategy=config.cache_miss_strategy,
        cache_miss_ttl=config.cache_miss_ttl,
        resolved_permissions_cache_ttl=config.resolved_permissions_cache_ttl,
        audit=config.audit or AuditConfig(),
        base_roles=config.base_roles if config.base_roles is not None else DEFAULT_BASE_ROLES,
        default_role=config.default_role,
        citadel_base_url=config.citadel_base_url,
        delegation=config.delegation or DelegationConfig(),
    )
