"""Database migration runner."""

from __future__ import annotations

import logging
from pathlib import Path

from gatedhouse.database.connection import DatabaseConnection

logger = logging.getLogger("gatedhouse.migrations")

# Locate shared SQL migrations
_SPEC_DIR = Path(__file__).resolve().parent.parent.parent.parent / "spec" / "sql" / "migrations"


class MigrationRunner:
    """Applies shared SQL migrations from spec/sql/migrations/."""

    def __init__(self, db: DatabaseConnection, table: str = "gatedhouse_migrations") -> None:
        self._db = db
        self._table = table

    async def ensure_table(self) -> None:
        await self._db.execute(f"""
            CREATE TABLE IF NOT EXISTS {self._table} (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                applied_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)

    async def applied(self) -> set[str]:
        rows = await self._db.query(f"SELECT name FROM {self._table}")
        return {r["name"] for r in rows}

    async def up(self) -> list[str]:
        """Apply all pending up migrations. Returns list of applied migration names."""
        await self.ensure_table()
        already = await self.applied()
        applied: list[str] = []

        up_files = sorted(_SPEC_DIR.glob("*_up.sql")) + sorted(
            f for f in _SPEC_DIR.glob("*.sql") if not f.name.endswith("_down.sql") and "_up.sql" not in f.name
        )
        # Deduplicate
        seen: set[str] = set()
        for f in sorted(_SPEC_DIR.glob("*.sql")):
            if f.name.endswith("_down.sql"):
                continue
            if f.name in seen:
                continue
            seen.add(f.name)
            if f.name in already:
                continue
            sql = f.read_text()
            logger.info("Applying migration: %s", f.name)
            await self._db.execute(sql)
            await self._db.execute(
                f"INSERT INTO {self._table} (name) VALUES ($1)", f.name
            )
            applied.append(f.name)

        return applied

    async def down(self) -> list[str]:
        """Rollback the last applied migration. Returns list of rolled-back names."""
        await self.ensure_table()
        rows = await self._db.query(
            f"SELECT name FROM {self._table} ORDER BY id DESC LIMIT 1"
        )
        if not rows:
            return []

        name = rows[0]["name"]
        down_name = name.replace(".sql", "_down.sql")
        down_file = _SPEC_DIR / down_name
        if not down_file.exists():
            logger.warning("No down migration for %s", name)
            return []

        sql = down_file.read_text()
        logger.info("Rolling back migration: %s", name)
        await self._db.execute(sql)
        await self._db.execute(f"DELETE FROM {self._table} WHERE name = $1", name)
        return [name]
