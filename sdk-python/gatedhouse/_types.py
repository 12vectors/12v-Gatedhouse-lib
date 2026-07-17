# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Immutable value types used across the public API."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class EffectivePermission:
    """A single permission tuple as it appears on a role grant.

    Any of the three components may be ``None``, denoting a wildcard at
    that level.
    """

    service: str | None
    resource: str | None
    action: str | None


@dataclass(frozen=True, slots=True)
class PermissionCacheKey:
    """Composite key used by ``PermissionCache`` implementations."""

    identity_id: str
    org_id: str


@dataclass(frozen=True, slots=True)
class AuthenticatedSubject:
    """Trusted output of a successful ``Gatedhouse.verify_token`` call.

    The ``id`` is the JWT ``sub`` claim — pass it to
    ``Gatedhouse.has_permission`` as the authenticated identity.
    """

    id: str
    issuer: str
    audience: str
    issued_at: datetime | None
    expires_at: datetime
    token_type: str | None
    claims: Mapping[str, Any] = field(default_factory=dict)
