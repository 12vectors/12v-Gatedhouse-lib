# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Schema-version check executed by ``GatedhouseFactory.create``."""

from __future__ import annotations

from . import _sql
from ._database import Database
from ._exceptions import SchemaNotInitializedError, SchemaOutOfDateError

EXPECTED_VERSION = 2


def verify(database: Database) -> None:
    """:raises SchemaNotInitializedError: the schema was never migrated.
    :raises SchemaOutOfDateError: it is older than this library expects.
    :raises GatedhouseDatabaseError: the database could not be queried (for
        example it is unreachable); this is not reported as a missing schema.
    """
    def current_version(conn) -> int | None:
        if not _sql.exists(
                conn,
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = 'gatedhouse' AND table_name = 'schema_versions'"):
            return None
        with conn.cursor() as cur:
            cur.execute("SELECT COALESCE(MAX(version), 0) FROM gatedhouse.schema_versions")
            return cur.fetchone()[0]

    current = _sql.read(database, "SchemaCheck.verify", current_version)
    if current is None:
        raise SchemaNotInitializedError()
    if current < EXPECTED_VERSION:
        raise SchemaOutOfDateError(current, EXPECTED_VERSION)
