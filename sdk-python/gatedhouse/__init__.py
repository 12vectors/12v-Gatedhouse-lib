"""Gatedhouse — embedded authorization library, Python SDK.

Public API: import from ``gatedhouse`` directly. Modules with leading
underscores are implementation detail; do not import from them.
"""

from __future__ import annotations

from ._config import GatedhouseConfig
from ._database import Database
from ._enums import EntityType, MembershipStatus
from ._exceptions import (
    GatedhouseDatabaseError,
    GatedhouseError,
    GatedhouseInitializationError,
    SchemaNotInitializedError,
    SchemaOutOfDateError,
    TokenVerificationException,
)
from ._factory import GatedhouseFactory
from ._gatedhouse import Gatedhouse
from ._group_manager import GroupManager
from ._group_source import GroupSource, LocalGroupSource
from ._membership_manager import MembershipManager
from ._permission_cache import InMemoryPermissionCache, PermissionCache
from ._permission_catalog import PermissionCatalog
from ._role_manager import RoleManager
from ._token_verifier_config import TokenVerifierConfig
from ._types import AuthenticatedSubject, EffectivePermission, PermissionCacheKey

__all__ = [
    # Config / lifecycle
    "Database",
    "Gatedhouse",
    "GatedhouseConfig",
    "GatedhouseFactory",
    "TokenVerifierConfig",
    # Sub-managers
    "GroupManager",
    "GroupSource",
    "LocalGroupSource",
    "MembershipManager",
    "PermissionCatalog",
    "RoleManager",
    # Cache
    "InMemoryPermissionCache",
    "PermissionCache",
    # Value types
    "AuthenticatedSubject",
    "EffectivePermission",
    "EntityType",
    "MembershipStatus",
    "PermissionCacheKey",
    # Exceptions
    "GatedhouseDatabaseError",
    "GatedhouseError",
    "GatedhouseInitializationError",
    "SchemaNotInitializedError",
    "SchemaOutOfDateError",
    "TokenVerificationException",
]
