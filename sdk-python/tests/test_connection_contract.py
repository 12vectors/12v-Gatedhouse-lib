# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""The connection contract every Gatedhouse SDK honours with a host's pool.
Mirrors the Java ConnectionContractTest.

Needs PostgreSQL: set GATEDHOUSE_TEST_DATABASE_URL to a conninfo URL, e.g.
``postgresql://gh:gh@127.0.0.1:5432/gatedhouse_test``, and install
``requirements-test.txt``.

* C1 every borrowed connection is returned, on every path
* C2 one connection per operation, never two at once
* C3 our writes commit whatever the host's context manager does on exit
* C4 connections come back with autocommit unchanged and no transaction open
* C5 a connection inside the caller's transaction is refused, untouched
* C6 no connection available is ``Kind.UNAVAILABLE``
* C7 one Gatedhouse instance is safe to share across threads
"""

from __future__ import annotations

import contextlib
import os
import sys
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Iterator

import psycopg
from psycopg.pq import TransactionStatus

from gatedhouse import (
    Database,
    EntityType,
    Gatedhouse,
    GatedhouseConfig,
    GatedhouseDatabaseError,
    GatedhouseFactory,
    GatedhouseInitializationError,
    MembershipStatus,
    PooledDatabase,
)
from gatedhouse._sql import classify

URL = os.environ.get("GATEDHOUSE_TEST_DATABASE_URL", "")
Kind = GatedhouseDatabaseError.Kind


class _Connect(Database):
    """A fresh connection per call; ``psycopg.Connection`` commits and closes on exit."""

    def __init__(self, url: str = URL, **kwargs) -> None:
        self._url, self._kwargs = url, kwargs

    def connection(self):
        return psycopg.connect(self._url, **self._kwargs)


class _CloseWithoutCommit(Database):
    """A host whose context manager hands the connection back without
    committing, as SQLAlchemy's pool does (it rolls back on return)."""

    def connection(self):
        return contextlib.closing(psycopg.connect(URL))


class SQLAlchemyDatabase(Database):
    """The README recipe, verbatim: borrow from a SQLAlchemy engine's pool."""

    def __init__(self, engine) -> None:
        self._engine = engine

    @contextlib.contextmanager
    def connection(self) -> Iterator[psycopg.Connection]:
        raw = self._engine.raw_connection()   # checked out of the engine's pool
        try:
            yield raw.driver_connection       # the underlying psycopg connection
        finally:
            raw.close()                       # back to the engine's pool


class _Tracking(Database):
    """Records every borrow and return, and how each connection came back."""

    def __init__(self, inner: Database) -> None:
        self._inner = inner
        self._lock = threading.Lock()
        self._held = threading.local()
        self.borrowed = self.returned = self.max_held_by_one_thread = 0
        self.problems: list[str] = []

    @contextlib.contextmanager
    def connection(self) -> Iterator[psycopg.Connection]:
        held = getattr(self._held, "n", 0) + 1
        self._held.n = held
        with self._lock:
            self.borrowed += 1
            self.max_held_by_one_thread = max(self.max_held_by_one_thread, held)
        try:
            with self._inner.connection() as conn:
                autocommit = conn.autocommit
                try:
                    yield conn
                finally:
                    with self._lock:
                        if conn.autocommit != autocommit:
                            self.problems.append(
                                f"returned with autocommit {conn.autocommit}, "
                                f"borrowed with {autocommit}")
                        if conn.info.transaction_status != TransactionStatus.IDLE:
                            self.problems.append(
                                f"returned with transaction {conn.info.transaction_status.name}")
        finally:
            self._held.n -= 1
            with self._lock:
                self.returned += 1

    def assert_all_returned_clean(self, test: unittest.TestCase) -> None:
        test.assertGreater(self.borrowed, 0, "nothing was borrowed")
        test.assertEqual(self.borrowed, self.returned, "borrowed vs returned")
        test.assertEqual([], self.problems)


def _create(db: Database) -> Gatedhouse:
    return GatedhouseFactory.create(GatedhouseConfig(database=db))


def _prefix() -> str:
    return f"cc_{uuid.uuid4().hex[:8]}_"


def _row_exists(sql: str, param: str) -> bool:
    with psycopg.connect(URL) as conn:
        return conn.execute(sql, (param,)).fetchone() is not None


def _check(condition: bool, what: str) -> None:
    if not condition:
        raise AssertionError(f"expected: {what}")


def exercise_every_operation(test: unittest.TestCase, gh: Gatedhouse, p: str) -> None:
    """Calls every operation that touches the database, including failing ones."""
    cat, roles = gh.permission_catalog(), gh.role_manager()
    groups, mem = gh.group_manager(), gh.membership_manager()
    svc, org, alice, team = p + "svc", p + "org", p + "alice", p + "team"

    cat.add_service(svc, "d")
    _check(cat.has_service(svc) and svc in cat.list_services(), "service")
    cat.add_resource(svc, "doc", "d")
    _check(cat.has_resource(svc, "doc") and cat.list_resources(svc) == ["doc"], "resource")
    cat.add_action(svc, "doc", "read", "d")
    _check(cat.has_action(svc, "doc", "read") and cat.list_actions(svc, "doc") == ["read"], "action")

    roles.create_role(p + "base", "Base", None)
    roles.create_role(p + "viewer", "Viewer", "d")
    roles.grant_permission(p + "base", svc, "doc", "read")
    roles.add_parent_role(p + "viewer", p + "base")
    _check(roles.has_role(p + "viewer") and p + "viewer" in roles.list_roles(), "role")
    _check(roles.get_parent_roles(p + "viewer") == [p + "base"], "parents")

    mem.create_membership(alice, org, EntityType.USER)
    _check(mem.has_membership(alice, org), "membership")
    _check(mem.get_status(alice, org) is MembershipStatus.ACTIVE, "status")
    _check(mem.get_entity_type(alice, org) is EntityType.USER, "entity type")

    roles.assign_to_identity(alice, org, p + "viewer")
    _check(roles.get_identity_roles(alice, org) == [p + "viewer"], "identity roles")
    groups.create_group(team, org, "Team", None)
    _check(groups.has_group(team, org) and groups.list_groups(org) == [team], "group")
    groups.add_identity_to_group(team, org, alice)
    _check(groups.get_group_members(team, org) == [alice], "members")
    _check(groups.get_identity_groups(alice, org) == [team], "identity groups")
    roles.assign_to_group(team, org, p + "base")
    _check(roles.get_group_roles(team, org) == [p + "base"], "group roles")

    _check(gh.has_permission(alice, org, svc, "doc", "read"), "allowed")
    _check(len(gh.get_effective_permissions(alice, org)) > 0, "effective")
    _check(gh.explain_permission(alice, org, svc, "doc", "read").outcome.name == "ALLOWED", "explain")
    _check(p + "viewer" in gh.get_roles(alice, org), "get_roles")
    _check(team in gh.get_groups(alice, org), "get_groups")
    mem.set_status(alice, org, MembershipStatus.SUSPENDED)
    _check(not gh.has_permission(alice, org, svc, "doc", "read"), "suspended")
    mem.set_status(alice, org, MembershipStatus.ACTIVE)

    # Failing operations return their connection too.
    with test.assertRaises(GatedhouseDatabaseError):
        roles.create_role(p + "viewer", "dup", None)
    with test.assertRaises(ValueError):
        roles.add_parent_role(p + "base", p + "viewer")
    mem.remove_membership(alice, org)
    with test.assertRaises(ValueError):
        mem.set_status(alice, org, MembershipStatus.SUSPENDED)

    roles.revoke_from_group(team, org, p + "base")
    groups.remove_identity_from_group(team, org, alice)
    roles.revoke_from_identity(alice, org, p + "viewer")
    groups.delete_group(team, org)
    roles.remove_parent_role(p + "viewer", p + "base")
    roles.revoke_permission(p + "base", svc, "doc", "read")
    roles.delete_role(p + "viewer")
    roles.delete_role(p + "base")
    cat.remove_action(svc, "doc", "read")
    cat.remove_resource(svc, "doc")
    cat.remove_service(svc)


@unittest.skipUnless(URL, "set GATEDHOUSE_TEST_DATABASE_URL to run the connection contract tests")
class ConnectionContractTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        GatedhouseFactory.migrate(GatedhouseConfig(database=_Connect()))

    # ---- C3: writes are never lost -----------------------------------------

    def test_writes_commit_even_when_the_host_hands_back_without_committing(self) -> None:
        p = _prefix()
        gh = _create(_CloseWithoutCommit())
        gh.role_manager().create_role(p + "r", "R", None)
        gh.permission_catalog().add_service(p + "svc", None)
        gh.membership_manager().create_membership(p + "id", p + "org", EntityType.USER)
        self.assertTrue(_row_exists("SELECT 1 FROM gatedhouse.roles WHERE key = %s", p + "r"))
        self.assertTrue(_row_exists("SELECT 1 FROM gatedhouse.services WHERE service = %s", p + "svc"))
        self.assertTrue(_row_exists(
            "SELECT 1 FROM gatedhouse.memberships WHERE identity_id = %s", p + "id"))

    # ---- C1, C2, C4: every operation, both autocommit modes ----------------

    def test_every_operation_returns_its_connection_clean_and_never_holds_two(self) -> None:
        for base in (_Connect(autocommit=True), _Connect(), _CloseWithoutCommit()):
            with self.subTest(base=type(base).__name__):
                db = _Tracking(base)
                exercise_every_operation(self, _create(db), _prefix())
                db.assert_all_returned_clean(self)
                self.assertEqual(1, db.max_held_by_one_thread,
                                 "an operation held two connections at once")

    def test_migrator_returns_its_connection_as_it_found_it(self) -> None:
        for autocommit in (False, True):
            db = _Tracking(_Connect(autocommit=autocommit))
            GatedhouseFactory.migrate(GatedhouseConfig(database=db))
            db.assert_all_returned_clean(self)

    # ---- C2 under a real pool: size 1 must not deadlock --------------------

    def test_a_pool_of_one_connection_runs_every_operation(self) -> None:
        with Database.from_uri(URL, max_size=1, timeout=2) as pool:
            done = threading.Event()

            def run() -> None:
                exercise_every_operation(self, _create(pool), _prefix())
                done.set()

            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            worker.join(60)
            self.assertTrue(done.is_set(), "deadlocked or failed with a pool of one")

    # ---- the production path: the host's own pool --------------------------

    def test_host_pool_is_borrowed_from_and_returned_to(self) -> None:
        from psycopg_pool import ConnectionPool
        for autocommit in (True, False):
            with ConnectionPool(URL, min_size=1, max_size=4, open=True,
                                kwargs={"autocommit": autocommit}) as host:
                db = _Tracking(Database.from_pool(host))
                exercise_every_operation(self, _create(db), _prefix())
                db.assert_all_returned_clean(self)
                stats = host.get_stats()
                self.assertEqual(stats["pool_size"], stats["pool_available"],
                                 "connections still checked out of the host pool")

    def test_sqlalchemy_engine_recipe(self) -> None:
        import sqlalchemy
        engine = sqlalchemy.create_engine(
            URL.replace("postgresql://", "postgresql+psycopg://", 1), pool_size=2, max_overflow=0)
        try:
            db = _Tracking(SQLAlchemyDatabase(engine))
            exercise_every_operation(self, _create(db), _prefix())
            db.assert_all_returned_clean(self)
            self.assertEqual(0, engine.pool.checkedout(), "connections still checked out")
        finally:
            engine.dispose()

    def test_from_pool_rejects_what_it_cannot_use(self) -> None:
        from psycopg_pool import AsyncConnectionPool
        with self.assertRaisesRegex(TypeError, "asynchronous"):
            Database.from_pool(AsyncConnectionPool(URL, open=False))
        with self.assertRaisesRegex(TypeError, "ConnectionPool"):
            Database.from_pool(object())

    # ---- C5: never someone else's transaction ------------------------------

    def test_connection_inside_the_callers_transaction_is_refused_and_left_untouched(self) -> None:
        p = _prefix()
        gh = _create(_Connect())
        with psycopg.connect(URL) as callers:
            # The caller's own unit of work, in progress.
            callers.execute("INSERT INTO gatedhouse.services (service) VALUES (%s)", (p + "callers",))

            class Bound(Database):  # hands back that same connection, never closing it
                def connection(self):
                    return contextlib.nullcontext(callers)

            from gatedhouse._gatedhouse import DefaultGatedhouse
            bound_gh = DefaultGatedhouse(GatedhouseConfig(database=Bound()))

            with self.assertRaisesRegex(RuntimeError, "already inside a transaction"):
                bound_gh.role_manager().create_role(p + "r", "R", None)
            with self.assertRaises(RuntimeError):
                bound_gh.role_manager().has_role(p + "r")

            # Nothing of ours ran, nothing of theirs was committed or rolled back.
            self.assertFalse(_row_exists("SELECT 1 FROM gatedhouse.roles WHERE key = %s", p + "r"))
            self.assertFalse(_row_exists(
                "SELECT 1 FROM gatedhouse.services WHERE service = %s", p + "callers"))
            self.assertEqual(TransactionStatus.INTRANS, callers.info.transaction_status)
            callers.commit()
        self.assertTrue(_row_exists("SELECT 1 FROM gatedhouse.services WHERE service = %s", p + "callers"))
        self.assertFalse(gh.role_manager().has_role(p + "r"))

    # ---- C6: unavailable is typed, and fast ---------------------------------

    def test_exhausted_pool_fails_as_unavailable_within_its_timeout(self) -> None:
        with Database.from_uri(URL, max_size=1, timeout=0.3) as pool:
            gh = _create(pool)
            with pool.connection():  # the only connection
                start = time.monotonic()
                with self.assertRaises(GatedhouseDatabaseError) as ctx:
                    gh.has_permission("a", "b", "s", "r", "x")
                elapsed = time.monotonic() - start
            self.assertIs(Kind.UNAVAILABLE, ctx.exception.kind)
            self.assertLess(elapsed, 3, f"gave up after {elapsed:.2f} s")
            self.assertFalse(gh.role_manager().has_role("no-such-role"), "pool recovered")

    def test_unreachable_database_fails_startup_as_unavailable(self) -> None:
        with Database.from_uri("postgresql://u:p@127.0.0.1:1/none", timeout=0.3) as nowhere:
            with self.assertRaises(GatedhouseInitializationError) as ctx:
                _create(nowhere)
        cause = ctx.exception.__cause__
        self.assertIsInstance(cause, GatedhouseDatabaseError)
        self.assertIs(Kind.UNAVAILABLE, cause.kind)

    # ---- C7: shared across threads -----------------------------------------

    def test_one_instance_shared_by_many_threads_on_a_smaller_pool(self) -> None:
        from psycopg_pool import ConnectionPool
        p, threads, rounds = _prefix(), 16, 15
        with ConnectionPool(URL, min_size=1, max_size=4, timeout=30, open=True) as host:
            db = _Tracking(Database.from_pool(host))
            gh = _create(db)
            gh.permission_catalog().add_service(p + "svc", None)
            gh.permission_catalog().add_resource(p + "svc", "doc", None)
            gh.permission_catalog().add_action(p + "svc", "doc", "read", None)
            gh.role_manager().create_role(p + "reader", "Reader", None)
            gh.role_manager().grant_permission(p + "reader", p + "svc", "doc", "read")

            def worker(t: int) -> None:
                identity = f"{p}user{t}"
                for i in range(rounds):
                    org = f"org{i}"
                    gh.membership_manager().create_membership(identity, org, EntityType.USER)
                    gh.role_manager().assign_to_identity(identity, org, p + "reader")
                    _check(gh.has_permission(identity, org, p + "svc", "doc", "read"), "granted")
                    _check(gh.explain_permission(identity, org, p + "svc", "doc", "read")
                           .outcome.name == "ALLOWED", "explained")
                    gh.membership_manager().remove_membership(identity, org)
                    _check(not gh.has_permission(identity, org, p + "svc", "doc", "read"), "revoked")

            with ThreadPoolExecutor(threads) as executor:
                for future in [executor.submit(worker, t) for t in range(threads)]:
                    future.result(timeout=120)  # re-raises any worker failure
            db.assert_all_returned_clean(self)

    # ---- role inheritance stays acyclic ------------------------------------

    def test_inheritance_cycles_are_rejected(self) -> None:
        p = _prefix()
        roles = _create(_Connect()).role_manager()
        for r in ("a", "b", "c"):
            roles.create_role(p + r, r, None)
        roles.add_parent_role(p + "a", p + "b")
        roles.add_parent_role(p + "b", p + "c")
        with self.assertRaisesRegex(ValueError, "cycle"):
            roles.add_parent_role(p + "b", p + "a")
        with self.assertRaises(ValueError):
            roles.add_parent_role(p + "c", p + "a")
        with self.assertRaises(GatedhouseDatabaseError):
            roles.add_parent_role(p + "a", p + "a")
        roles.add_parent_role(p + "a", p + "c")  # a shortcut is not a cycle
        self.assertEqual([p + "b", p + "c"], roles.get_parent_roles(p + "a"))

    def test_concurrent_opposite_edges_cannot_both_succeed(self) -> None:
        # Also when sessions default to SERIALIZABLE: the check must not
        # depend on the host's isolation level.
        for options in ("", "-c default_transaction_isolation=serializable"):
            with self.subTest(options=options or "default"):
                p = _prefix()
                roles = _create(_Connect(options=options) if options else _Connect()).role_manager()
                with ThreadPoolExecutor(2) as pair:
                    for i in range(25):
                        a, b = f"{p}a{i}", f"{p}b{i}"
                        roles.create_role(a, a, None)
                        roles.create_role(b, b, None)
                        go = threading.Event()

                        def edge(child: str, parent: str) -> bool:
                            go.wait()
                            try:
                                roles.add_parent_role(child, parent)
                                return True
                            except ValueError:
                                return False

                        ab, ba = pair.submit(edge, a, b), pair.submit(edge, b, a)
                        go.set()
                        succeeded = ab.result(30) + ba.result(30)
                        self.assertEqual(1, succeeded, f"both or neither of {a}<->{b} succeeded")

    # ---- URL mode is opt-in --------------------------------------------------

    def test_from_uri_without_psycopg_pool_explains_what_to_add(self) -> None:
        saved = sys.modules.get("psycopg_pool")
        sys.modules["psycopg_pool"] = None  # makes `import psycopg_pool` fail
        try:
            with self.assertRaisesRegex(ImportError, r"gatedhouse\[pool\]"):
                Database.from_uri(URL)
        finally:
            if saved is None:
                del sys.modules["psycopg_pool"]
            else:
                sys.modules["psycopg_pool"] = saved


class NoDatabaseTest(unittest.TestCase):
    """Needs no database."""

    def test_pooled_database_settings_are_validated_before_anything_opens(self) -> None:
        for kwargs in ({"max_size": 0}, {"max_size": 2.5}, {"timeout": 0.2},
                       {"max_lifetime": 29}, {"timeout": True}):
            with self.subTest(**kwargs), self.assertRaises(ValueError):
                PooledDatabase("postgresql://unused", **kwargs)
        self.assertEqual((10, 10.0, 1800.0), (PooledDatabase.DEFAULT_MAX_SIZE,
                                             PooledDatabase.DEFAULT_TIMEOUT,
                                             PooledDatabase.DEFAULT_MAX_LIFETIME))

    def test_connection_loss_is_unavailable_and_everything_else_is_query(self) -> None:
        from psycopg import errors as e
        self.assertIs(Kind.UNAVAILABLE, classify("x", e.OperationalError("lost")).kind)
        self.assertIs(Kind.UNAVAILABLE, classify("x", e.AdminShutdown("bye")).kind)
        self.assertIs(Kind.QUERY, classify("x", e.UniqueViolation("dup")).kind)
        self.assertIs(Kind.QUERY, classify("x", e.SerializationFailure("retry")).kind)
        self.assertIs(Kind.QUERY, GatedhouseDatabaseError("legacy").kind)


if __name__ == "__main__":
    unittest.main()
