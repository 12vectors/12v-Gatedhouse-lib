"""Static factory mirroring Java's ``GatedhouseFactory``."""

from __future__ import annotations

from . import _migrator, _schema_check
from ._config import GatedhouseConfig
from ._exceptions import GatedhouseInitializationError
from ._gatedhouse import DefaultGatedhouse, Gatedhouse


class GatedhouseFactory:

    def __init__(self) -> None:
        raise TypeError("GatedhouseFactory is not instantiable")

    @staticmethod
    def create(config: GatedhouseConfig) -> Gatedhouse:
        if config is None:
            raise TypeError("config must not be None")
        _schema_check.verify(config.database)

        gatedhouse = DefaultGatedhouse(config)
        try:
            config.group_source.start(gatedhouse)
        except Exception as e:
            # Best-effort cleanup before propagating.
            try:
                config.group_source.close()
            except Exception:
                pass
            raise GatedhouseInitializationError(
                f"GroupSource.start failed during Gatedhouse initialization: {e}"
            ) from e
        return gatedhouse

    @staticmethod
    def migrate(config: GatedhouseConfig) -> None:
        if config is None:
            raise TypeError("config must not be None")
        _migrator.migrate(config.database)
