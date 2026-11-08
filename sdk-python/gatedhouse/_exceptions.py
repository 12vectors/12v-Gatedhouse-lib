# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Exception hierarchy for Gatedhouse runtime failures."""

from __future__ import annotations

from enum import Enum


class GatedhouseError(Exception):
    """Base for every Gatedhouse-raised exception."""


class GatedhouseInitializationError(GatedhouseError):
    """Raised when constructing a Gatedhouse instance fails (schema check,
    GroupSource startup, etc.)."""


class GatedhouseDatabaseError(GatedhouseError):
    """Wraps a psycopg/DB-API failure raised during a Gatedhouse method."""


class SchemaNotInitializedError(GatedhouseInitializationError):
    """The target database has no ``gatedhouse`` schema. Run the migration."""

    def __init__(self) -> None:
        super().__init__(
            "Gatedhouse schema is not initialized in the target database.\n"
            "\n"
            "Run the migration tool against the same database, e.g.:\n"
            "    python -m gatedhouse.cli.migrate <conninfo>\n"
            "\n"
            "Or, from your application's bootstrap:\n"
            "    GatedhouseFactory.migrate(config)\n"
        )


class SchemaOutOfDateError(GatedhouseInitializationError):
    """The schema is at a version older than this library expects."""

    def __init__(self, current_version: int, expected_version: int) -> None:
        super().__init__(
            f"Gatedhouse schema is at version {current_version} but this "
            f"library requires version {expected_version}.\n"
            "\n"
            "Run the migration tool to upgrade:\n"
            "    python -m gatedhouse.cli.migrate <conninfo>\n"
            "\n"
            "Or, from your application's bootstrap:\n"
            "    GatedhouseFactory.migrate(config)\n"
        )
        self.current_version = current_version
        self.expected_version = expected_version


class TokenVerificationException(GatedhouseError):
    """Raised by ``Gatedhouse.verify_token`` for any verification failure.

    Inspect ``reason`` to decide whether to refresh, redirect to SSO, retry,
    or hard-reject.
    """

    class Reason(Enum):
        EXPIRED = "expired"
        NOT_YET_VALID = "not_yet_valid"
        INVALID_SIGNATURE = "invalid_signature"
        INVALID_ISSUER = "invalid_issuer"
        INVALID_AUDIENCE = "invalid_audience"
        MALFORMED = "malformed"
        UNKNOWN_KEY = "unknown_key"
        JWKS_UNAVAILABLE = "jwks_unavailable"
        OTHER = "other"

    def __init__(self, reason: "TokenVerificationException.Reason", message: str) -> None:
        super().__init__(message)
        self.reason = reason


class SphinxError(GatedhouseError, RuntimeError):
    """A ``SphinxClient`` call failed. ``kind`` says how, so a host can tell
    "the IdP is unavailable, try again" (``TIMEOUT``, ``TRANSPORT``) apart
    from "the request was refused" (``HTTP_STATUS``, e.g. an invalid or
    already-used authorization code).

    The library never retries. In particular, do not blindly retry
    ``exchange_code`` after a timeout: authorization codes are single-use,
    and the IdP may already have consumed the code.

    Also a ``RuntimeError``, which these calls raised before, so existing
    handlers keep working. The underlying error is chained as
    ``__cause__``.
    """

    class Kind(Enum):
        #: A network wait (connecting, or waiting for data) exceeded the timeout.
        TIMEOUT = "timeout"
        #: The endpoint could not be reached, or the connection failed,
        #: other than by timing out.
        TRANSPORT = "transport"
        #: The endpoint answered with an unsuccessful HTTP status; see
        #: ``status_code``.
        HTTP_STATUS = "http_status"
        #: The endpoint answered, but the body was not the expected JSON object.
        INVALID_RESPONSE = "invalid_response"

    def __init__(self, kind: "SphinxError.Kind", message: str,
                 status_code: int | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        #: The HTTP status for ``HTTP_STATUS``; ``None`` for every other kind.
        self.status_code = status_code
