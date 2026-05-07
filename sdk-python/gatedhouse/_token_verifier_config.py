"""Configuration for the optional JWT verification helper."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TokenVerifierConfig:
    """Settings for ``Gatedhouse.verify_token``.

    For a Sphinx deployment, ``jwks_uri`` is typically
    ``https://<sphinx-host>/api/sphinx/v1/.well-known/jwks.json``,
    ``issuer`` matches Sphinx's ``JWT_ISSUER``, and ``audience`` matches
    its ``JWT_AUDIENCE``.
    """

    jwks_uri: str
    issuer: str
    audience: str
