"""JWKS client with TTL caching and fetch coalescing."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger("gatedhouse.jwt.jwks")


class JwksClient:
    """Fetches and caches JWKS keys from the Sphinx auth service."""

    def __init__(self, url: str, cache_ttl: int = 3600) -> None:
        self._url = url
        self._cache_ttl = cache_ttl
        self._cache: dict[str, Any] | None = None
        self._cache_time: float = 0
        self._lock = asyncio.Lock()
        self._fetching: asyncio.Task[dict[str, Any]] | None = None

    async def get_keys(self) -> dict[str, Any]:
        """Get JWKS keys, using cache if available."""
        if self._cache and (time.monotonic() - self._cache_time) < self._cache_ttl:
            return self._cache

        async with self._lock:
            # Double check after acquiring lock
            if self._cache and (time.monotonic() - self._cache_time) < self._cache_ttl:
                return self._cache

            return await self._fetch()

    async def get_key(self, kid: str) -> dict[str, Any] | None:
        """Get a specific key by ID."""
        keys = await self.get_keys()
        for key in keys.get("keys", []):
            if key.get("kid") == kid:
                return key
        return None

    async def _fetch(self) -> dict[str, Any]:
        """Fetch JWKS from the endpoint."""
        async with httpx.AsyncClient() as client:
            response = await client.get(self._url, timeout=10)
            response.raise_for_status()
            data = response.json()

        self._cache = data
        self._cache_time = time.monotonic()
        logger.debug("JWKS cache refreshed from %s", self._url)
        return data
