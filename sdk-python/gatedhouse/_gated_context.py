"""Type-safe view over a verified Sphinx token's claims."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from ._types import AuthenticatedSubject


@dataclass(frozen=True, slots=True)
class GatedContext:
    """Representation of a verified Sphinx token's request context.

    A type-safe wrapper around the generic authenticated subject and its
    claims. Mirrors the Java ``GatedContext`` record.
    """

    person_id: str
    email: str | None
    role: str | None
    identity_type: str | None
    auth_method: str | None
    mfa_verified: bool
    email_verified: bool
    client_id: str | None
    scope: str | None
    delegation_id: str | None
    actor_claims: Mapping[str, Any] | None
    raw_claims: Mapping[str, Any] = field(default_factory=dict)

    def is_admin(self) -> bool:
        """True if the role is ``"admin"``."""
        return self.role == "admin"

    def is_human(self) -> bool:
        """True if the identity type is ``"human"``."""
        return self.identity_type == "human"

    def is_delegated(self) -> bool:
        """True if a delegation ID is present."""
        return self.delegation_id is not None

    def has_scope(self, required_scope: str) -> bool:
        """True if the token's space-separated scope list contains
        ``required_scope``."""
        if self.scope is None:
            return False
        return required_scope in self.scope.split()

    @staticmethod
    def from_subject(subject: AuthenticatedSubject) -> "GatedContext":
        """Construct a GatedContext from an ``AuthenticatedSubject``."""
        claims = subject.claims
        return GatedContext(
            person_id=subject.id,
            email=claims.get("email"),
            role=claims.get("role"),
            identity_type=claims.get("person_type", "human"),
            auth_method=claims.get("auth_method"),
            mfa_verified=claims.get("mfa_verified") is True,
            email_verified=claims.get("email_verified") is True,
            client_id=claims.get("client_id"),
            scope=claims.get("scope"),
            delegation_id=claims.get("delegation_id"),
            actor_claims=claims.get("act"),
            raw_claims=claims,
        )
