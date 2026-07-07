"""Standalone migration runner.

Usage::

    DATABASE_URL='postgresql://user:pwd@host:5432/db' python -m gatedhouse.cli.migrate

The libpq connection string is read from the ``DATABASE_URL`` environment
variable so the password never appears on the command line / process list.
"""

from __future__ import annotations

import os
import sys

from gatedhouse import Database, GatedhouseConfig, GatedhouseFactory


USAGE = (
    "Set DATABASE_URL to the Postgres conninfo, e.g. "
    "DATABASE_URL='postgresql://user:pwd@host:5432/db'\n"
)


def main(argv: list[str] | None = None) -> int:
    conninfo = os.environ.get("DATABASE_URL")
    if not conninfo:
        sys.stderr.write(USAGE)
        return 2

    config = GatedhouseConfig(database=Database.from_uri(conninfo))

    try:
        GatedhouseFactory.migrate(config)
    except Exception as e:
        sys.stderr.write(f"Gatedhouse migration failed: {e}\n")
        cause = e.__cause__
        if cause is not None:
            sys.stderr.write(f"Caused by: {cause}\n")
        return 1

    print("Gatedhouse migration completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
