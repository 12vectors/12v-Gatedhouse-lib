# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Immutable value types used across the public API."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping

from ._enums import MembershipStatus


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


# ---- permission explanations (docs/MODEL.md, "Explaining a decision") ----


class GrantSource(Enum):
    """Where the first role in a :class:`GrantPath` comes from."""

    #: Assigned directly to the identity.
    DIRECT = "DIRECT"
    #: Assigned to a group the identity belongs to.
    GROUP = "GROUP"


class ExplanationOutcome(Enum):
    """The decision a :class:`PermissionExplanation` reports, and for a
    denial, why."""

    #: An active membership and at least one granting path.
    ALLOWED = "ALLOWED"
    #: No membership in the org. Any paths are grants with no effect.
    NO_MEMBERSHIP = "NO_MEMBERSHIP"
    #: The membership is not ACTIVE. The paths show what would apply if it were.
    MEMBERSHIP_NOT_ACTIVE = "MEMBERSHIP_NOT_ACTIVE"
    #: An active membership, but nothing grants the permission.
    NO_MATCHING_GRANT = "NO_MATCHING_GRANT"


@dataclass(frozen=True, slots=True)
class GrantPath:
    """One path through which an identity holds a permission, as reported
    by :meth:`Gatedhouse.explain_permission`.

    ``role_chain`` runs from the assigned role, through each inherited
    parent, to the role holding ``grant``; it is never empty. ``group_id``
    is ``None`` for :attr:`GrantSource.DIRECT`. ``grant`` components may be
    ``None`` (wildcards).
    """

    source: GrantSource
    group_id: str | None
    role_chain: tuple[str, ...]
    grant: EffectivePermission

    def __post_init__(self) -> None:
        object.__setattr__(self, "role_chain", tuple(self.role_chain))
        if not self.role_chain:
            raise ValueError("role_chain must not be empty")

    @property
    def assigned_role(self) -> str:
        """The role assigned to the identity, or to its group."""
        return self.role_chain[0]

    @property
    def granting_role(self) -> str:
        """The role that holds the matching grant."""
        return self.role_chain[-1]


@dataclass(frozen=True, slots=True)
class PermissionExplanation:
    """Why a permission is granted or denied, as reported by
    :meth:`Gatedhouse.explain_permission`.

    ``membership_status`` is ``None`` if the identity has no membership in
    the org. ``paths`` lists every path that would grant the permission,
    even when the decision is a denial.
    """

    outcome: ExplanationOutcome
    membership_status: MembershipStatus | None
    paths: tuple[GrantPath, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "paths", tuple(self.paths))

    @property
    def allowed(self) -> bool:
        """True iff the permission is granted; agrees with
        :meth:`Gatedhouse.has_permission`."""
        return self.outcome is ExplanationOutcome.ALLOWED
