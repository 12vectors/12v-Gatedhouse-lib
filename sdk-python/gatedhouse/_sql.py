# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""The only way library code touches the database.

Mirrors the Java ``Sql`` helper. Every operation borrows exactly one
connection through here, so the connection contract holds in one place:

* **Borrow and return.** The connection is borrowed from the host's
  :class:`Database` and handed back on every path.
* **We own our commits.** Work commits or rolls back here, whatever
  autocommit setting the pool hands out.
* **Returned clean.** The connection's autocommit setting is never changed
  and no transaction is left open.
* **Never someone else's transaction.** A connection already inside a
  transaction is refused, so the caller's work is never committed or
  rolled back by us.
* **Typed failures.** No connection available is
  :attr:`GatedhouseDatabaseError.Kind.UNAVAILABLE`.

Library code never holds two connections at once, so a pool of size 1
cannot deadlock.
"""

from __future__ import annotations

from typing import Any, Callable, Sequence, TypeVar

import psycopg
from psycopg import errors as pg_errors
from psycopg.pq import TransactionStatus

from ._database import Database
from ._exceptions import GatedhouseDatabaseError

T = TypeVar("T")

_Kind = GatedhouseDatabaseError.Kind

#: Server shut down / not accepting connections; class 08 is checked by prefix.
_UNAVAILABLE_STATES = frozenset({"57P01", "57P02", "57P03"})


def read(database: Database, op: str, work: Callable[[psycopg.Connection], T]) -> T:
    """Runs read-only work. On an autocommit connection this adds no round
    trips; otherwise the reads run in a transaction that is ended before the
    connection goes back."""
    return _run(database, op, work, write=False)


def write(database: Database, op: str, work: Callable[[psycopg.Connection], T]) -> T:
    """Runs work in one explicit READ COMMITTED transaction that commits only
    if the work completes. Locking in library code is reasoned about under
    READ COMMITTED, so the level is set rather than inherited from the pool."""
    return _run(database, op, work, write=True)


def _run(database: Database, op: str, work: Callable[[psycopg.Connection], T],
         write: bool) -> T:
    try:
        borrowed = database.connection()
        conn = borrowed.__enter__()
    except pg_errors.Error as e:
        raise GatedhouseDatabaseError(
            f"{op} failed: could not obtain a database connection: {e}",
            kind=_Kind.UNAVAILABLE) from e
    if conn is None:
        borrowed.__exit__(None, None, None)
        raise RuntimeError(f"Database.connection() yielded no connection (in {op})")

    try:
        require_no_open_transaction(conn, op)
        if write or not conn.autocommit:
            # transaction() issues BEGIN/COMMIT itself in either autocommit
            # mode, so the connection's setting is never touched.
            with conn.transaction():
                if write:
                    conn.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                result = work(conn)
        else:
            result = work(conn)
    except BaseException as e:
        try:
            borrowed.__exit__(type(e), e, e.__traceback__)
        except pg_errors.Error:
            pass  # the original failure is the one to report
        if isinstance(e, pg_errors.Error):
            raise classify(f"{op} failed: {e}", e) from e
        raise
    try:
        borrowed.__exit__(None, None, None)
    except pg_errors.Error as e:
        raise classify(f"{op} failed returning the connection: {e}", e) from e
    return result


def classify(message: str, cause: pg_errors.Error) -> GatedhouseDatabaseError:
    """SQLSTATE class 08 and 57P01-57P03 mean the database went away, as does
    a client-side operational failure with no SQLSTATE (connection lost, pool
    timeout); anything else is the statement failing."""
    state = getattr(cause, "sqlstate", None)
    unavailable = (
        (state is not None and (state.startswith("08") or state in _UNAVAILABLE_STATES))
        or (state is None and isinstance(cause, pg_errors.OperationalError))
    )
    return GatedhouseDatabaseError(
        message, kind=_Kind.UNAVAILABLE if unavailable else _Kind.QUERY)


def require_no_open_transaction(conn: psycopg.Connection, op: str) -> None:
    """Refuses a connection the host is using for a transaction of its own."""
    status = conn.info.transaction_status
    if status != TransactionStatus.IDLE:
        raise RuntimeError(
            f"{op}: the connection from Database.connection() is already inside a "
            f"transaction ({status.name}). Gatedhouse commits its own work, so it will "
            "not run on a connection bound to the caller's transaction. Pass a pool "
            "(Database.from_pool) or a Database that yields idle connections.")


# ---- statement helpers -------------------------------------------------------

def execute(conn: psycopg.Connection, sql: str, params: Sequence[Any] = ()) -> int:
    """Executes an INSERT/UPDATE/DELETE; returns the affected row count."""
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.rowcount


def exists(conn: psycopg.Connection, sql: str, params: Sequence[Any] = ()) -> bool:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone() is not None


def strings(conn: psycopg.Connection, sql: str, params: Sequence[Any] = ()) -> list[str]:
    """The first column of every row."""
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return [row[0] for row in cur.fetchall()]
