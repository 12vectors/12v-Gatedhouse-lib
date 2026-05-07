"""Standalone migration runner.

Usage::

    python -m gatedhouse.cli.migrate <conninfo>

where ``<conninfo>`` is a libpq connection string, e.g.
``postgresql://user:pass@host:5432/dbname``.
"""

from __future__ import annotations

import sys

from gatedhouse import Database, GatedhouseConfig, GatedhouseFactory


USAGE = (
    "Usage: python -m gatedhouse.cli.migrate <conninfo>\n"
    "\n"
    "Example:\n"
    "  python -m gatedhouse.cli.migrate "
    "'postgresql://user:pass@localhost:5432/mydb'\n"
)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        sys.stderr.write(USAGE)
        return 2

    conninfo = args[0]
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
