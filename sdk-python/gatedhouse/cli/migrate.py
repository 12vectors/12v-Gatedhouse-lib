"""CLI migration runner."""

from __future__ import annotations

import argparse
import asyncio
import sys

from gatedhouse.core.config import DatabaseConfig, GatehouseConfig
from gatedhouse.database.connection import DatabaseConnection
from gatedhouse.database.migrations import MigrationRunner


async def run_migrate(connection_string: str, direction: str) -> None:
    from gatedhouse.core.config import resolve_config

    config = resolve_config(GatehouseConfig(
        jwks_url="https://placeholder",
        database=DatabaseConfig(connection_string=connection_string),
        service="migrate-cli",
    ))
    db = DatabaseConnection(config)
    await db.connect()

    runner = MigrationRunner(db)

    try:
        if direction == "up":
            applied = await runner.up()
            for name in applied:
                print(f"Applied: {name}")
            if not applied:
                print("No pending migrations")
        elif direction == "down":
            rolled_back = await runner.down()
            for name in rolled_back:
                print(f"Rolled back: {name}")
            if not rolled_back:
                print("Nothing to roll back")
    finally:
        await db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Gatedhouse migration runner")
    parser.add_argument("direction", choices=["up", "down"], help="Migration direction")
    parser.add_argument(
        "--database-url", required=True,
        help="PostgreSQL connection string",
    )
    args = parser.parse_args()
    asyncio.run(run_migrate(args.database_url, args.direction))


if __name__ == "__main__":
    main()
