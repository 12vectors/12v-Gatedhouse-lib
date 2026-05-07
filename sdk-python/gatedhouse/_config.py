"""Top-level configuration object."""

from __future__ import annotations

from dataclasses import dataclass, field

from ._database import Database
from ._group_source import GroupSource, LocalGroupSource
from ._permission_cache import InMemoryPermissionCache, PermissionCache
from ._token_verifier_config import TokenVerifierConfig


@dataclass(frozen=True, slots=True)
class GatedhouseConfig:
    """Mirrors the Java ``GatedhouseConfig``.

    Only ``database`` is required. All other components have sensible
    defaults: a process-local ``InMemoryPermissionCache`` (60s TTL),
    a no-op ``LocalGroupSource``, and JWT verification disabled.
    """

    database: Database
    group_source: GroupSource = field(default_factory=LocalGroupSource)
    permission_cache: PermissionCache = field(default_factory=InMemoryPermissionCache)
    token_verifier: TokenVerifierConfig | None = None
