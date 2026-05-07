"""Pluggable extension point for where group data originates.

Mirrors the Java ``GroupSource`` interface. Both built-in and custom
implementations write to the same local
``gatedhouse.groups`` / ``gatedhouse.group_memberships`` tables — the
difference is *who* triggers those writes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._gatedhouse import Gatedhouse


class GroupSource(ABC):
    """Configured at factory time via ``GatedhouseConfig(group_source=...)``.

    * :class:`LocalGroupSource`: the host calls ``gh.group_manager()``
      methods directly. ``start`` is a no-op.
    * Custom (e.g., a Citadel bridge): on ``start``, register a listener
      with the host's transport that translates incoming events into
      ``gh.group_manager()`` write calls. Release the listener on
      ``close``.

    Implementations must be safe for concurrent invocation.
    """

    @abstractmethod
    def start(self, gatedhouse: "Gatedhouse") -> None:
        """Called once by ``GatedhouseFactory.create`` after the schema
        check passes and the ``Gatedhouse`` instance is fully constructed."""

    @abstractmethod
    def close(self) -> None:
        """Called when the ``Gatedhouse`` instance is closed.
        Implementations should release listeners and any resources they
        hold. Must be idempotent."""


class LocalGroupSource(GroupSource):
    """Default :class:`GroupSource`. The host owns group lifecycle and
    calls ``gh.group_manager()`` write methods directly. Holds no
    listeners and no resources."""

    def start(self, gatedhouse: "Gatedhouse") -> None:
        pass  # no-op

    def close(self) -> None:
        pass  # no-op
