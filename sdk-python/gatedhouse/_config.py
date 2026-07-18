# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Top-level configuration object."""

from __future__ import annotations

from dataclasses import dataclass, field

from ._database import Database
from ._group_source import GroupSource, LocalGroupSource
from ._permission_cache import PermissionCache
from ._token_verifier_config import TokenVerifierConfig


@dataclass(frozen=True, slots=True)
class GatedhouseConfig:
    """Mirrors the Java ``GatedhouseConfig``.

    Only ``database`` is required. All other components have sensible
    defaults: a no-op ``LocalGroupSource``, JWT verification disabled,
    and **no permission cache** — caching is opt-in; when
    ``permission_cache`` is left unset, every permission read goes
    straight to the database with zero cache overhead. Pass
    ``InMemoryPermissionCache()`` (60s TTL) or a custom
    ``PermissionCache`` to enable caching.
    """

    database: Database
    group_source: GroupSource = field(default_factory=LocalGroupSource)
    permission_cache: PermissionCache | None = None
    token_verifier: TokenVerifierConfig | None = None
