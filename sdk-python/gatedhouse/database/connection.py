"""Database connection management using asyncpg."""

from __future__ import annotations

import logging
from typing import Any

import asyncpg

from gatedhouse.core.config import ResolvedConfig

logger = logging.getLogger("gatedhouse.database")


class DatabaseConnection:
    """Async PostgreSQL connection pool wrapper."""

    def __init__(self, config: ResolvedConfig) -> None:
        self._config = config
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        """Initialize the connection pool."""
        self._pool = await asyncpg.create_pool(
            dsn=self._config.database.connection_string,
            min_size=self._config.database.pool_min,
            max_size=self._config.database.pool_max,
            command_timeout=5,
        )
        logger.info("Database connection pool initialized")

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._pool

    async def query(self, text: str, *args: Any) -> list[asyncpg.Record]:
        """Execute a query and return all rows."""
        return await self.pool.fetch(text, *args)

    async def query_one(self, text: str, *args: Any) -> asyncpg.Record | None:
        """Execute a query and return the first row or None."""
        return await self.pool.fetchrow(text, *args)

    async def execute(self, text: str, *args: Any) -> str:
        """Execute a statement and return the status."""
        return await self.pool.execute(text, *args)

    async def health_check(self) -> bool:
        """Check database connectivity."""
        try:
            await self.pool.fetchval("SELECT 1")
            return True
        except Exception:
            return False

    async def close(self) -> None:
        """Close the connection pool."""
        if self._pool:
            await self._pool.close()
            logger.info("Database connection pool closed")
