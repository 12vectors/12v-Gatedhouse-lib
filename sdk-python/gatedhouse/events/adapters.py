"""Event bus adapters."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Awaitable

from gatedhouse.core.types import GatehouseEvent

logger = logging.getLogger("gatedhouse.events.adapters")

EventHandler = Callable[[GatehouseEvent], Awaitable[None]]


class EventBusAdapter:
    """Base class for event bus adapters."""

    async def subscribe(self, topics: list[str], handler: EventHandler) -> None:
        raise NotImplementedError

    async def publish(self, topic: str, event: GatehouseEvent) -> None:
        raise NotImplementedError

    async def disconnect(self) -> None:
        raise NotImplementedError


class InMemoryEventBus(EventBusAdapter):
    """In-memory event bus for testing and development."""

    def __init__(self) -> None:
        self._handlers: list[EventHandler] = []

    async def subscribe(self, topics: list[str], handler: EventHandler) -> None:
        self._handlers.append(handler)

    async def publish(self, topic: str, event: GatehouseEvent) -> None:
        for handler in self._handlers:
            await handler(event)

    async def disconnect(self) -> None:
        self._handlers.clear()


class NoopEventBus(EventBusAdapter):
    """No-op event bus that silently discards events."""

    async def subscribe(self, topics: list[str], handler: EventHandler) -> None:
        pass

    async def publish(self, topic: str, event: GatehouseEvent) -> None:
        pass

    async def disconnect(self) -> None:
        pass
