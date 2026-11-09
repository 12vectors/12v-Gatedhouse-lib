# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Internal PyJWT-backed verifier used by ``Gatedhouse.verify_token``.

Not part of the public API. Mirrors the Java ``JwtVerification``
package-private helper.

Thread-safe. Signing keys come from :class:`_JwksCache`, which owns the
caching policy (identical to the Java SDK's Nimbus defaults): keys live
for :data:`JWKS_CACHE_TTL` seconds; a refetch (for an unknown ``kid`` or
after a failed fetch) happens at most once per
:data:`JWKS_MIN_REFRESH_INTERVAL` seconds, by one thread at a time, so
forged tokens with random ``kid`` values cannot turn into a flood of
requests to the identity provider. PyJWT does the fetching and parsing.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

import jwt
from jwt import PyJWK, PyJWKClient
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    PyJWKClientError,
    PyJWKSetError,
)

from ._exceptions import TokenVerificationException
from ._token_verifier_config import TokenVerifierConfig
from ._types import AuthenticatedSubject

_STANDARD_CLAIMS = frozenset({"sub", "iss", "aud", "iat", "exp", "nbf", "type"})

_R = TokenVerificationException.Reason

#: Seconds fetched signing keys are trusted before they are refetched, so a
#: key the identity provider has removed stops validating.
JWKS_CACHE_TTL = 300.0
#: Least seconds between two fetches of the JWKS.
JWKS_MIN_REFRESH_INTERVAL = 30.0


class _JwksCache:
    """Signing keys by ``kid``. The fast path takes no lock; fetching is
    serialized, and other threads reuse its outcome."""

    def __init__(self, uri: str, timeout: float) -> None:
        # PyJWT fetches and parses; this class decides when.
        self._client = PyJWKClient(uri, cache_jwk_set=False, timeout=timeout)
        self._fetch_lock = threading.Lock()
        self._keys: dict[str, PyJWK] = {}
        self._fetched_at: float | None = None      # last successful fetch
        self._attempted_at: float | None = None    # last fetch, either outcome
        self._last_error: str | None = None        # set while the last fetch failed

    def key_for(self, kid: str) -> PyJWK:
        key = self._fresh(kid, time.monotonic())
        if key is not None:
            return key
        with self._fetch_lock:
            now = time.monotonic()
            key = self._fresh(kid, now)    # another thread may have just fetched
            if key is not None:
                return key
            recently = (self._attempted_at is not None
                        and now - self._attempted_at < JWKS_MIN_REFRESH_INTERVAL)
            if not recently:
                self._fetch(now)
            if self._last_error is not None:
                raise TokenVerificationException(
                    _R.JWKS_UNAVAILABLE, f"JWKS could not be fetched: {self._last_error}")
            key = self._keys.get(kid)
            if key is None:
                raise TokenVerificationException(_R.UNKNOWN_KEY, f"kid {kid!r} not present in JWKS")
            return key

    def _fresh(self, kid: str, now: float) -> PyJWK | None:
        fetched_at = self._fetched_at
        if fetched_at is None or now - fetched_at >= JWKS_CACHE_TTL:
            return None
        return self._keys.get(kid)

    def _fetch(self, now: float) -> None:
        self._attempted_at = now
        try:
            jwk_set = self._client.get_jwk_set(refresh=True)
        except (PyJWKClientError, PyJWKSetError) as e:
            self._last_error = str(e)
            return
        self._keys = {k.key_id: k for k in jwk_set.keys
                      if k.key_id is not None and k.public_key_use in (None, "sig")}
        self._fetched_at = now
        self._last_error = None


class JwtVerification:

    def __init__(self, config: TokenVerifierConfig) -> None:
        self._issuer = config.issuer
        self._audience = config.audience
        self._jwks = _JwksCache(config.jwks_uri, config.jwks_timeout)

    def verify(self, token: str) -> AuthenticatedSubject:
        if token is None:
            raise TypeError("token must not be None")

        try:
            kid = jwt.get_unverified_header(token).get("kid")
            if not isinstance(kid, str):
                raise TokenVerificationException(_R.MALFORMED, "JWT header has no kid")
            signing_key = self._jwks.key_for(kid).key
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
