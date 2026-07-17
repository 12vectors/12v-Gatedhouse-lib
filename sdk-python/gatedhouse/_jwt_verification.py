# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Internal PyJWT-backed verifier used by ``Gatedhouse.verify_token``.

Not part of the public API. Mirrors the Java ``JwtVerification``
package-private helper.

Thread-safe: PyJWT's ``PyJWKClient`` is documented thread-safe (it
caches signing keys with an internal lock); we hold it as an instance
attribute and never mutate verifier state on a verify call.
"""

from __future__ import annotations

from datetime import datetime, timezone

import jwt
from jwt import PyJWKClient
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    PyJWKClientError,
)

from ._exceptions import TokenVerificationException
from ._token_verifier_config import TokenVerifierConfig
from ._types import AuthenticatedSubject

_STANDARD_CLAIMS = frozenset({"sub", "iss", "aud", "iat", "exp", "nbf", "type"})

_R = TokenVerificationException.Reason


class JwtVerification:

    def __init__(self, config: TokenVerifierConfig) -> None:
        self._issuer = config.issuer
        self._audience = config.audience
        # PyJWKClient handles JWKS fetching, caching, and key rotation.
        self._jwks_client = PyJWKClient(config.jwks_uri)

    def verify(self, token: str) -> AuthenticatedSubject:
        if token is None:
            raise TypeError("token must not be None")

        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token).key
            claims: dict = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
            )
        except ExpiredSignatureError as e:
            raise TokenVerificationException(_R.EXPIRED, str(e)) from e
        except ImmatureSignatureError as e:
            raise TokenVerificationException(_R.NOT_YET_VALID, str(e)) from e
        except InvalidIssuerError as e:
            raise TokenVerificationException(_R.INVALID_ISSUER, str(e)) from e
        except InvalidAudienceError as e:
            raise TokenVerificationException(_R.INVALID_AUDIENCE, str(e)) from e
        except InvalidSignatureError as e:
            raise TokenVerificationException(_R.INVALID_SIGNATURE, str(e)) from e
        except PyJWKClientError as e:
            # Could be JWKS endpoint unreachable or kid not found. The
            # message text distinguishes; fall back to UNKNOWN_KEY for
            # the lookup-failure case and JWKS_UNAVAILABLE otherwise.
            msg = str(e).lower()
            if "could not find" in msg or "no matching" in msg:
                raise TokenVerificationException(_R.UNKNOWN_KEY, str(e)) from e
            raise TokenVerificationException(_R.JWKS_UNAVAILABLE, str(e)) from e
        except DecodeError as e:
            raise TokenVerificationException(_R.MALFORMED, str(e)) from e
        except InvalidTokenError as e:
            raise TokenVerificationException(_R.OTHER, str(e)) from e

        # PyJWT validates iss/aud/exp/nbf when those kwargs are passed,
        # so reaching here means the token's standard claims are good.

        exp_ts = claims.get("exp")
        if not isinstance(exp_ts, (int, float)):
            raise TokenVerificationException(
                _R.MALFORMED, "exp claim missing or not numeric"
            )
        iat_ts = claims.get("iat")
        issued_at = (
            datetime.fromtimestamp(iat_ts, tz=timezone.utc)
            if isinstance(iat_ts, (int, float))
            else None
        )

        aud_claim = claims.get("aud", self._audience)
        audience = aud_claim if isinstance(aud_claim, str) else aud_claim[0]
        token_type = claims.get("type")
        token_type = token_type if isinstance(token_type, str) else None

        custom = {k: v for k, v in claims.items() if k not in _STANDARD_CLAIMS}

        return AuthenticatedSubject(
            id=claims["sub"],
            issuer=claims["iss"],
            audience=audience,
            issued_at=issued_at,
            expires_at=datetime.fromtimestamp(exp_ts, tz=timezone.utc),
            token_type=token_type,
            claims=custom,
        )
