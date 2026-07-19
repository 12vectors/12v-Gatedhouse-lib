"""Configuration for the optional JWT verification helper."""

from __future__ import annotations

from dataclasses import dataclass

from ._secure_urls import require_https_or_loopback


@dataclass(frozen=True, slots=True)
class TokenVerifierConfig:
    """Settings for ``Gatedhouse.verify_token``.

    For a Sphinx deployment, ``jwks_uri`` is
    ``https://<sphinx-host>/api/sphinx/v1/auth/jwks`` (as advertised by Sphinx's
    OIDC discovery ``jwks_uri``). ``issuer`` is the literal ``"sphinx"`` -- the
    ``iss`` on Sphinx's OAuth access tokens, a fixed value that does *not* vary with
    the deployment URL (it is not the OIDC issuer URL, which appears only on
    id_tokens). ``audience`` is your app's registered ``client_id`` -- the ``aud``
    Sphinx sets on the access token issued to that client.
    """

    jwks_uri: str
    issuer: str
    audience: str

    def __post_init__(self) -> None:
        # All signature trust roots in the keys fetched from jwks_uri — a
        # cleartext fetch would let a network attacker substitute keys and forge
        # tokens. Require TLS (loopback exempt for dev/test). (review M4)
        require_https_or_loopback(self.jwks_uri, "jwks_uri")
