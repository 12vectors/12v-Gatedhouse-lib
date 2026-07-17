# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Schema-version check executed by ``GatedhouseFactory.create``."""

from __future__ import annotations

from psycopg import errors as pg_errors

from ._database import Database
from ._exceptions import SchemaNotInitializedError, SchemaOutOfDateError

EXPECTED_VERSION = 1


def verify(database: Database) -> None:
    try:
        with database.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = 'gatedhouse' "
                "  AND table_name = 'schema_versions'"
            )
            if cur.fetchone() is None:
                raise SchemaNotInitializedError()
            cur.execute(
                "SELECT COALESCE(MAX(version), 0) "
                "FROM gatedhouse.schema_versions"
            )
            row = cur.fetchone()
            current = row[0] if row else 0
            if current < EXPECTED_VERSION:
                raise SchemaOutOfDateError(current, EXPECTED_VERSION)
    except pg_errors.Error as e:
        raise SchemaNotInitializedError() from e
