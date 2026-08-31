# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Configuration for the optional JWT verification helper."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TokenVerifierConfig:
    """Settings for ``Gatedhouse.verify_token``.

    For a Sphinx deployment, ``jwks_uri`` is
    ``https://<sphinx-host>/api/sphinx/v1/auth/jwks``, ``issuer`` is the
    literal ``"sphinx"`` (Sphinx access tokens carry ``iss="sphinx"``;
    its ``OIDC_ISSUER`` URL applies only to OIDC id_tokens), and
    ``audience`` is your app's ``client_id`` as registered in Sphinx
    (access tokens set ``aud`` to the client id).
    """

    jwks_uri: str
    issuer: str
    audience: str
