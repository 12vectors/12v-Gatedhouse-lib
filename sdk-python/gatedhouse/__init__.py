# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Gatedhouse — embedded authorization library, Python SDK.

Public API: import from ``gatedhouse`` directly. Modules with leading
underscores are implementation detail; do not import from them.

Web integration: the top-level ``GatedhouseApiFilter`` /
``GatedhouseWebFilter`` are WSGI middleware; ASGI hosts (FastAPI,
Starlette, Litestar, Quart) use the same-named classes from
``gatedhouse.asgi``.
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
from ._gated_context import GatedContext
from ._gatedhouse import Gatedhouse
from ._group_manager import GroupManager
from ._group_source import GroupSource, LocalGroupSource
from ._membership_manager import MembershipManager
from ._permission_cache import InMemoryPermissionCache, PermissionCache
from ._permission_catalog import PermissionCatalog
from ._role_manager import RoleManager
from ._sphinx_client import SphinxClient, TokenResponse
from ._token_verifier_config import TokenVerifierConfig
from ._types import AuthenticatedSubject, EffectivePermission, PermissionCacheKey
from ._web import (
    ForbiddenException,
    GatedhouseApiFilter,
    GatedhouseWebFilter,
    UnauthorizedException,
)

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
    # Web & Sphinx SSO integration
    "GatedContext",
    "GatedhouseApiFilter",
    "GatedhouseWebFilter",
    "SphinxClient",
    "TokenResponse",
    # Value types
    "AuthenticatedSubject",
    "EffectivePermission",
    "EntityType",
    "MembershipStatus",
    "PermissionCacheKey",
    # Exceptions
    "ForbiddenException",
    "GatedhouseDatabaseError",
    "GatedhouseError",
    "GatedhouseInitializationError",
    "SchemaNotInitializedError",
    "SchemaOutOfDateError",
    "TokenVerificationException",
    "UnauthorizedException",
]
