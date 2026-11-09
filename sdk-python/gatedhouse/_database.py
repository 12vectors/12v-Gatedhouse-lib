# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Where Gatedhouse gets its database connections.

Mirrors the Java ``Database``. Gatedhouse borrows one connection per
operation, never holds two at once, and gives it back when the operation
ends.

Ways to provide one, in order of preference for production:

1. :meth:`Database.from_pool`: your application's existing
   ``psycopg_pool.ConnectionPool``. Gatedhouse then opens no connections of
   its own.
2. A :class:`Database` subclass, for any other source (for example a
   SQLAlchemy engine's pool; see the README for a tested recipe).
3. :meth:`Database.from_uri`: Gatedhouse runs its own pool. Recommended for
   development and staging; needs the optional extra
   ``pip install 'gatedhouse[pool]'``.

Whatever the source, Gatedhouse commits or rolls back its own work, never
changes the connection's autocommit setting, and refuses a connection that is
already inside a transaction rather than commit the caller's work.
"""

from __future__ import annotations

import inspect
import threading
import time
import weakref
from abc import ABC, abstractmethod
from typing import Any, ContextManager

import psycopg


class Database(ABC):
    """Connection source used by every Gatedhouse manager.

    Implementations must be safe to call from many threads at once.
    """

    @abstractmethod
    def connection(self) -> ContextManager[psycopg.Connection]:
        """Return a context manager that yields a connection for one unit of
        work and gives it back when the ``with`` block ends. Must not yield
        the same connection to two callers at the same time.

        ``pool.connection()`` of a ``psycopg_pool.ConnectionPool`` is such a
        context manager. So is a plain ``psycopg.Connection``, which commits
        and closes on exit. Never return ``pool.getconn()``: nothing would
        give the connection back, and the pool would run dry.
        """

    @staticmethod
    def from_pool(pool: Any) -> "Database":
        """Borrows connections from the host application's
        ``psycopg_pool.ConnectionPool``. Gatedhouse opens no connections of
        its own and never closes the pool.

        Open the pool after the server forks its workers (gunicorn, uWSGI),
        not before: connections do not survive a fork.

        :raises TypeError: if ``pool`` is not a synchronous psycopg pool.
            Gatedhouse is synchronous; async frameworks call it from a thread
            (as the bundled ASGI middleware does) with a synchronous pool.
        """
        connection = getattr(pool, "connection", None)
        if not callable(connection):
            raise TypeError(
                f"Database.from_pool expects a psycopg_pool.ConnectionPool, got "
                f"{type(pool).__name__}")
        if inspect.iscoroutinefunction(getattr(pool, "getconn", None)):
            raise TypeError(
                "Database.from_pool needs a synchronous psycopg_pool.ConnectionPool; "
                f"{type(pool).__name__} is asynchronous. Gatedhouse is synchronous: "
                "call it from a worker thread with a synchronous pool.")
        return _PoolDatabase(pool)

    @staticmethod
    def from_uri(conninfo: str, *, max_size: int = 10, timeout: float = 10.0,
                 max_lifetime: float = 1800.0,
                 statement_timeout: float = 30.0) -> "PooledDatabase":
        """Runs a pool owned by Gatedhouse. Recommended for development and
        staging; in production, pass your application's pool with
        :meth:`from_pool`.

        Needs ``psycopg_pool``: ``pip install 'gatedhouse[pool]'``. Close the
        returned pool when done with it (or use it as a context manager);
        closing a Gatedhouse instance does not.

        :param max_size: most connections the pool opens.
        :param timeout: longest, in seconds, an operation waits for a free
            connection before failing with ``Kind.UNAVAILABLE``.
        :param max_lifetime: seconds after which a connection is retired.
        :param statement_timeout: longest, in seconds, any statement may run
            before PostgreSQL cancels it (then ``Kind.UNAVAILABLE``); ``0``
            means no limit. Set on the pool's own sessions only.
        :raises ImportError: if ``psycopg_pool`` is not installed.
        """
        return PooledDatabase(conninfo, max_size=max_size, timeout=timeout,
                              max_lifetime=max_lifetime,
                              statement_timeout=statement_timeout)


class _PoolDatabase(Database):

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    def connection(self) -> ContextManager[psycopg.Connection]:
        return self._pool.connection()


class PooledDatabase(Database):
    """A connection pool owned by Gatedhouse, created by
    :meth:`Database.from_uri`. Backed by ``psycopg_pool`` (the optional
    ``pool`` extra).

    Whoever creates it closes it. Closing a Gatedhouse instance does not,
    because one Database is commonly shared by ``migrate`` and several
    Gatedhouse instances.
    """

    DEFAULT_MAX_SIZE = 10
    DEFAULT_TIMEOUT = 10.0
    DEFAULT_MAX_LIFETIME = 1800.0
    DEFAULT_STATEMENT_TIMEOUT = 30.0
    #: A connection returned within this many seconds is handed out without
    #: a liveness check (HikariCP's default), saving a round trip per
    #: operation under load; an idle one is checked first.
    ALIVE_BYPASS_WINDOW = 0.5

    def __init__(self, conninfo: str, *, max_size: int = DEFAULT_MAX_SIZE,
                 timeout: float = DEFAULT_TIMEOUT,
                 max_lifetime: float = DEFAULT_MAX_LIFETIME,
                 statement_timeout: float = DEFAULT_STATEMENT_TIMEOUT) -> None:
        _require_number("max_size", max_size, minimum=1, integer=True)
        _require_number("timeout", timeout, minimum=0.25)
        _require_number("max_lifetime", max_lifetime, minimum=30)
        _require_number("statement_timeout", statement_timeout, minimum=0)
        try:
            from psycopg_pool import ConnectionPool
        except ImportError as e:
            raise ImportError(
                "Database.from_uri runs a connection pool and needs psycopg_pool, an "
                "optional dependency of gatedhouse. Install it with "
                "pip install 'gatedhouse[pool]', or pass your application's pool "
                "with Database.from_pool(...).") from e
        timeout_ms = int(statement_timeout * 1000)
        returned_at: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
        lock = threading.Lock()

        def configure(conn: psycopg.Connection) -> None:
            # The pool is Gatedhouse's own, so its sessions may carry settings.
            conn.execute(f"SET statement_timeout = {timeout_ms}")
            if not conn.autocommit:
                conn.commit()

        def reset(conn: psycopg.Connection) -> None:
            with lock:
                returned_at[conn] = time.monotonic()

        def check(conn: psycopg.Connection) -> None:
            with lock:
                last = returned_at.get(conn)
            if last is None or time.monotonic() - last >= self.ALIVE_BYPASS_WINDOW:
                ConnectionPool.check_connection(conn)

        self._pool = ConnectionPool(
            conninfo,
            min_size=1,
            max_size=max_size,
            timeout=timeout,
            max_lifetime=max_lifetime,
            configure=configure,
            reset=reset,
            # Hand out only connections that still work; recently used ones
            # are known to.
            check=check,
            name="gatedhouse",
            # Opening must not fail just because the database is briefly
            # unreachable; the first operation reports it.
            open=False,
        )
        self._pool.open(wait=False)

    def connection(self) -> ContextManager[psycopg.Connection]:
        return self._pool.connection()

    def close(self) -> None:
        """Closes every pooled connection. Idempotent."""
        self._pool.close()

    def __enter__(self) -> "PooledDatabase":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _require_number(name: str, value: object, *, minimum: float,
                    integer: bool = False) -> None:
    allowed = (int,) if integer else (int, float)
    if isinstance(value, bool) or not isinstance(value, allowed) or value < minimum:
        kind = "an integer" if integer else "a number"
        raise ValueError(f"{name} must be {kind} >= {minimum:g}, got {value!r}")
