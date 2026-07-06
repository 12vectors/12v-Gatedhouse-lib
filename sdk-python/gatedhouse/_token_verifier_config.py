"""Configuration for the optional JWT verification helper."""

from __future__ import annotations

from dataclasses import dataclass

from ._secure_urls import require_https_or_loopback


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

    def __post_init__(self) -> None:
        # All signature trust roots in the keys fetched from jwks_uri — a
        # cleartext fetch would let a network attacker substitute keys and forge
        # tokens. Require TLS (loopback exempt for dev/test). (review M4)
        require_https_or_loopback(self.jwks_uri, "jwks_uri")
