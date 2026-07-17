# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Static factory mirroring Java's ``GatedhouseFactory``."""

from __future__ import annotations

from . import _migrator, _schema_check
from ._config import GatedhouseConfig
from ._exceptions import GatedhouseInitializationError
from ._gatedhouse import DefaultGatedhouse, Gatedhouse
from ._token_verifier_config import TokenVerifierConfig
from ._token_verifier_gatedhouse import JustTokenVerifierGatedhouse


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
    def create_just_token_verifier(config: TokenVerifierConfig) -> Gatedhouse:
        """Creates a lightweight Gatedhouse instance that only supports
        token verification and requires no database backend."""
        if config is None:
            raise TypeError("config must not be None")
        return JustTokenVerifierGatedhouse(config)

    @staticmethod
    def migrate(config: GatedhouseConfig) -> None:
        if config is None:
            raise TypeError("config must not be None")
        _migrator.migrate(config.database)
