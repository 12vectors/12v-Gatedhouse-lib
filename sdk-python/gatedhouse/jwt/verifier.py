"""JWT verifier — extracts Identity from JWT claims."""

from __future__ import annotations

import logging
from typing import Any

import jwt as pyjwt
from jwt import PyJWKClient

from gatedhouse.core.types import Identity

logger = logging.getLogger("gatedhouse.jwt.verifier")


class JwtVerifier:
    """Verifies JWTs and extracts Identity from claims."""

    def __init__(self, jwks_url: str, cache_ttl: int = 3600) -> None:
        self._jwks_client = PyJWKClient(jwks_url, cache_keys=True, lifespan=cache_ttl)
        self._jwks_url = jwks_url

    def verify(self, token: str) -> Identity | None:
        """Verify a JWT and extract the Identity."""
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = pyjwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                options={"verify_aud": False},
            )
            return self._extract_identity(claims)
        except Exception:
            logger.exception("JWT verification failed")
            return None

    @staticmethod
    def _extract_identity(claims: dict[str, Any]) -> Identity:
        sub = claims.get("sub", "")
        identity_type = claims.get("identity_type", "human")
        auth_method = claims.get("auth_method", "password")

        return Identity(
            id=sub,
            type=identity_type,
            auth_method=auth_method,
            email=claims.get("email"),
            name=claims.get("name"),
            mfa_verified=claims.get("mfa_verified"),
        )
