# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Tiny migration runner. Mirrors the Java ``Migrator`` package-private
class. Reads V###__name.sql files from the migrations resource directory,
tracks applied versions in ``gatedhouse.schema_versions``, applies
pending migrations under a Postgres advisory lock so concurrent
instances don't race.
"""

from __future__ import annotations

import hashlib
import re
from importlib.resources import files

from psycopg import errors as pg_errors

from ._database import Database
from ._exceptions import GatedhouseInitializationError

# Stable but arbitrary; matches the Java side so the lock is shared.
_ADVISORY_LOCK_KEY = 0x6761746564686F75  # 'gatedhou'

_FILENAME_PATTERN = re.compile(r"^V(\d+)__([A-Za-z0-9_]+)\.sql$")
_MIGRATIONS_PACKAGE = "gatedhouse.migrations"


def migrate(database: Database) -> None:
    available = _load_available_migrations()

    try:
        with database.connection() as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                _acquire_lock(cur)
            try:
                with conn.cursor() as cur:
                    _ensure_bookkeeping(cur)
                    applied = _applied_versions(cur)
                for migration in available:
                    if migration.version in applied:
                        continue
                    _apply(conn, migration)
            finally:
                with conn.cursor() as cur:
                    _release_lock(cur)
    except pg_errors.Error as e:
        raise GatedhouseInitializationError(
            f"Gatedhouse migration failed: {e}"
        ) from e


# ---- migration discovery -------------------------------------------------


class _Migration:

    __slots__ = ("version", "name", "sql", "checksum")

    def __init__(self, version: int, name: str, sql: str, checksum: str) -> None:
        self.version = version
        self.name = name
        self.sql = sql
        self.checksum = checksum


def _load_available_migrations() -> list[_Migration]:
    migrations_dir = files(_MIGRATIONS_PACKAGE)
    index_text = (migrations_dir / "migrations.txt").read_text(encoding="utf-8")

    out: list[_Migration] = []
    for raw in index_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _FILENAME_PATTERN.match(line)
        if not match:
            raise GatedhouseInitializationError(
                f"Migration filename does not match V###__name.sql: {line!r}"
            )
        version = int(match.group(1))
        name = match.group(2)
        sql = (migrations_dir / line).read_text(encoding="utf-8")
        checksum = hashlib.sha256(sql.encode("utf-8")).hexdigest()
        out.append(_Migration(version, name, sql, checksum))
    out.sort(key=lambda m: m.version)
    return out


# ---- bookkeeping ---------------------------------------------------------


def _acquire_lock(cur) -> None:
    cur.execute("SELECT pg_advisory_lock(%s)", (_ADVISORY_LOCK_KEY,))
    cur.fetchone()


def _release_lock(cur) -> None:
    cur.execute("SELECT pg_advisory_unlock(%s)", (_ADVISORY_LOCK_KEY,))
    cur.fetchone()


def _ensure_bookkeeping(cur) -> None:
    cur.execute("CREATE SCHEMA IF NOT EXISTS gatedhouse")
    cur.execute(
        "CREATE TABLE IF NOT EXISTS gatedhouse.schema_versions ("
        "    version    INTEGER PRIMARY KEY,"
        "    name       TEXT NOT NULL,"
        "    checksum   TEXT NOT NULL,"
        "    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
        ")"
    )


def _applied_versions(cur) -> set[int]:
    cur.execute("SELECT version FROM gatedhouse.schema_versions")
    return {row[0] for row in cur.fetchall()}


def _apply(conn, migration: _Migration) -> None:
    prev_autocommit = conn.autocommit
    conn.autocommit = False
    try:
        with conn.cursor() as cur:
            cur.execute(migration.sql)
            cur.execute(
                "INSERT INTO gatedhouse.schema_versions "
                "(version, name, checksum) VALUES (%s, %s, %s)",
                (migration.version, migration.name, migration.checksum),
            )
        conn.commit()
    except pg_errors.Error:
        conn.rollback()
        raise
    finally:
        conn.autocommit = prev_autocommit
