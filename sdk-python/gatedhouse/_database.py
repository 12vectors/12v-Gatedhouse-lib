"""Database access abstraction.

Mirrors the Java ``Database`` functional interface: a single method that
returns a fresh connection. The library does not bundle a connection pool;
hosts wire their own (psycopg's ``ConnectionPool``, pgbouncer, etc.) by
implementing this ABC and returning a connection from the pool.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import psycopg


class Database(ABC):
    """Connection factory used by every Gatedhouse manager."""

    @abstractmethod
    def connection(self) -> psycopg.Connection:
        """Return a connection ready to use. The library closes it via
        context manager when done with the unit of work."""

    @staticmethod
    def from_uri(conninfo: str) -> "Database":
        """Convenience constructor: each call to ``connection()`` opens a
        fresh psycopg connection using the supplied conninfo string.
        Suitable for scripts and tests; production hosts should plug in
        a pool.
        """
        return _ConninfoDatabase(conninfo)


class _ConninfoDatabase(Database):

    def __init__(self, conninfo: str) -> None:
        self._conninfo = conninfo

    def connection(self) -> psycopg.Connection:
        return psycopg.connect(self._conninfo)
