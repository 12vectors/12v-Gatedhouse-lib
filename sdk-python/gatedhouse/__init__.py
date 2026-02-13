"""Gatedhouse authorization library for the SuperAgent Platform."""

from gatedhouse.core.types import (
    AuthMethod,
    DelegationContext,
    EntityType,
    GatedContext,
    Identity,
    IdentityType,
    MembershipContext,
    OrgContext,
    PermissionCheckResult,
    RoleDefinition,
)
from gatedhouse.core.config import GatehouseConfig, resolve_config
from gatedhouse.core.permissions.matcher import (
    has_all_permissions,
    has_any_permission,
    has_permission,
    intersect_permissions,
    match_permission,
)
from gatedhouse.core.permissions.checker import PermissionChecker

__all__ = [
    "AuthMethod",
    "DelegationContext",
    "EntityType",
    "GatedContext",
    "GatehouseConfig",
    "Identity",
    "IdentityType",
    "MembershipContext",
    "OrgContext",
    "PermissionCheckResult",
    "PermissionChecker",
    "RoleDefinition",
    "has_all_permissions",
    "has_any_permission",
    "has_permission",
    "intersect_permissions",
    "match_permission",
    "resolve_config",
]

__version__ = "0.1.0"
