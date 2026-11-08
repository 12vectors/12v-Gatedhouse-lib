# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

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
    #: The longest any single network wait may take while fetching the JWKS,
    #: in seconds. A fetch that fails or times out raises
    #: ``TokenVerificationException`` with reason ``JWKS_UNAVAILABLE``.
    jwks_timeout: float = 5.0

    #: The JWKS fetch timeout used when none is given, in seconds.
    DEFAULT_JWKS_TIMEOUT = 5.0

    def __post_init__(self) -> None:
        t = self.jwks_timeout
        if isinstance(t, bool) or not isinstance(t, (int, float)) or not t > 0:
            raise ValueError(f"jwks_timeout must be a positive number of seconds, got {t!r}")
