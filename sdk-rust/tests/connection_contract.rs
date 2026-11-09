// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! The connection contract every Gatedhouse SDK honours with a host's pool.
//! Mirrors the Java ConnectionContractTest.
//!
//! Needs PostgreSQL and the `r2d2` feature:
//!
//! ```text
//! GATEDHOUSE_TEST_DATABASE_URL='host=127.0.0.1 user=gh password=gh dbname=gatedhouse_test' \
//!     cargo test --features r2d2 --test connection_contract
//! ```
//!
//! Without the variable each test returns early, except under CI (`CI` set),
//! where a missing database is a failure rather than a silent pass.
//!
//! * C1 every borrowed connection is returned, on every path
//! * C2 one connection per operation, never two at once
//! * C3 our writes commit
//! * C4 connections come back with no transaction open
//! * C5 (Java/Python) a connection inside the caller's transaction is
//!   refused: not testable here, `postgres` cannot lend one out
//! * C6 no connection available is `DatabaseErrorKind::Unavailable`
//! * C7 one Gatedhouse instance is safe to share across threads
#![cfg(feature = "r2d2")]

use std::cell::Cell;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use gatedhouse::{
    from_fn, ConnectionError, Database, DatabaseErrorKind, EntityType, ExplanationOutcome,
    Gatedhouse, GatedhouseConfig, GatedhouseError, GatedhouseFactory, MembershipStatus,
    OwnedClient, PoolSettings, PooledClient, PooledDatabase,
};
use postgres::{Client, NoTls};
use r2d2_postgres::PostgresConnectionManager;

fn url() -> Option<String> {
    match std::env::var("GATEDHOUSE_TEST_DATABASE_URL") {
        Ok(url) if !url.is_empty() => Some(url),
        _ if std::env::var_os("CI").is_some() => {
            panic!("GATEDHOUSE_TEST_DATABASE_URL must be set in CI")
        }
        _ => {
            eprintln!("skipped: set GATEDHOUSE_TEST_DATABASE_URL to run the connection contract tests");
            None
        }
    }
}

macro_rules! database_url {
    () => {
        match url() {
            Some(url) => {
                migrate(&url);
                url
            }
            None => return,
        }
    };
}

/// A fresh connection per borrow, from a parsed `postgres::Config` (so any
/// conninfo format works), optionally with extra session options.
fn plain(url: &str, options: Option<&str>) -> Arc<dyn Database> {
    let mut config: postgres::Config = url.parse().expect("conninfo");
    if let Some(options) = options {
        config.options(options);
    }
    Arc::new(from_fn(move || {
        Ok(Box::new(OwnedClient(config.connect(NoTls)?)) as PooledClient)
    }))
}

fn host_pool(url: &str, size: u32) -> r2d2::Pool<PostgresConnectionManager<NoTls>> {
    let manager = PostgresConnectionManager::new(url.parse().expect("conninfo"), NoTls);
    r2d2::Pool::builder().max_size(size).build(manager).expect("host pool")
}

fn migrate(url: &str) {
    GatedhouseFactory::migrate(&GatedhouseConfig::builder(plain(url, None)).build())
        .expect("migrate");
}

fn create(db: Arc<dyn Database>) -> Arc<dyn Gatedhouse> {
    GatedhouseFactory::create(GatedhouseConfig::builder(db).build()).expect("create")
}

fn prefix() -> String {
    format!("cc_{}_", &uuid::Uuid::new_v4().simple().to_string()[..8])
}

fn row_exists(url: &str, sql: &str, param: &str) -> bool {
    let mut c = Client::connect(url, NoTls).expect("connect");
    c.query_opt(sql, &[&param]).expect("query").is_some()
}

fn kind_of<T>(result: Result<T, GatedhouseError>) -> Option<DatabaseErrorKind> {
    result.err().and_then(|e| e.database_kind())
}

// ---- tracking -----------------------------------------------------------

thread_local! {
    static HELD: Cell<usize> = const { Cell::new(0) };
}

#[derive(Default)]
struct Stats {
    borrowed: AtomicUsize,
    returned: AtomicUsize,
    max_held_by_one_thread: AtomicUsize,
    problems: Mutex<Vec<String>>,
}

/// Wraps a Database, recording every borrow and every return, and whether
/// each connection came back with a transaction still open.
struct Tracking {
    inner: Arc<dyn Database>,
    stats: Arc<Stats>,
}

impl Tracking {
    fn wrap(inner: Arc<dyn Database>) -> (Arc<dyn Database>, Arc<Stats>) {
        let stats = Arc::new(Stats::default());
        (Arc::new(Tracking { inner, stats: stats.clone() }), stats)
    }
}

impl Database for Tracking {
    fn connection(&self) -> Result<PooledClient, ConnectionError> {
        let client = self.inner.connection()?;
        self.stats.borrowed.fetch_add(1, Ordering::SeqCst);
        let held = HELD.with(|h| {
            h.set(h.get() + 1);
            h.get()
        });
        self.stats.max_held_by_one_thread.fetch_max(held, Ordering::SeqCst);
        Ok(Box::new(Tracked { client: Some(client), stats: self.stats.clone() }))
    }
}

struct Tracked {
    client: Option<PooledClient>,
    stats: Arc<Stats>,
}

impl Deref for Tracked {
    type Target = Client;
    fn deref(&self) -> &Client {
        self.client.as_ref().expect("live")
    }
}

impl DerefMut for Tracked {
    fn deref_mut(&mut self) -> &mut Client {
        self.client.as_mut().expect("live")
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        if let Some(mut client) = self.client.take() {
            if in_transaction(&mut client) {
                self.stats.problems.lock().unwrap().push("returned with a transaction open".into());
            }
            drop(client);
            HELD.with(|h| h.set(h.get() - 1));
            self.stats.returned.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Outside an explicit transaction, a simple-protocol statement runs in its
/// own implicit transaction, which starts with it; inside one, now() is the
/// earlier start of that transaction.
fn in_transaction(client: &mut Client) -> bool {
    let messages = client
        .simple_query("SELECT now() = statement_timestamp()")
        .unwrap_or_default();
    messages.iter().any(|m| match m {
        postgres::SimpleQueryMessage::Row(row) => row.get(0) == Some("f"),
        _ => false,
    })
}

#[test]
fn the_open_transaction_probe_itself_works() {
    let url = database_url!();
    let mut client = Client::connect(&url, NoTls).unwrap();
    assert!(!in_transaction(&mut client), "idle connection reported in a transaction");
    client.batch_execute("BEGIN; SELECT 1").unwrap();
    thread::sleep(Duration::from_millis(5));
    assert!(in_transaction(&mut client), "open transaction not detected");
    client.batch_execute("ROLLBACK").unwrap();
    assert!(!in_transaction(&mut client));
}

fn assert_all_returned_clean(stats: &Stats) {
    let borrowed = stats.borrowed.load(Ordering::SeqCst);
    assert!(borrowed > 0, "nothing was borrowed");
    assert_eq!(borrowed, stats.returned.load(Ordering::SeqCst), "borrowed vs returned");
    assert_eq!(Vec::<String>::new(), *stats.problems.lock().unwrap());
}

// ---- every operation ----------------------------------------------------

/// Calls every operation that touches the database, including failing ones.
fn exercise_every_operation(gh: &Arc<dyn Gatedhouse>, p: &str) {
    let (cat, roles, groups, mem) =
        (gh.permission_catalog(), gh.role_manager(), gh.group_manager(), gh.membership_manager());
    let svc = format!("{p}svc");
    let org = format!("{p}org");
    let alice = format!("{p}alice");
    let team = format!("{p}team");
    let base = format!("{p}base");
    let viewer = format!("{p}viewer");

    cat.add_service(&svc, Some("d")).unwrap();
    assert!(cat.has_service(&svc).unwrap() && cat.list_services().unwrap().contains(&svc));
    cat.add_resource(&svc, "doc", Some("d")).unwrap();
    assert!(cat.has_resource(&svc, "doc").unwrap());
    assert_eq!(vec!["doc"], cat.list_resources(&svc).unwrap());
    cat.add_action(&svc, "doc", "read", Some("d")).unwrap();
    assert!(cat.has_action(&svc, "doc", "read").unwrap());
    assert_eq!(vec!["read"], cat.list_actions(&svc, "doc").unwrap());

    roles.create_role(&base, "Base", None).unwrap();
    roles.create_role(&viewer, "Viewer", Some("d")).unwrap();
    roles.grant_permission(&base, Some(&svc), Some("doc"), Some("read")).unwrap();
    roles.add_parent_role(&viewer, &base).unwrap();
    assert!(roles.has_role(&viewer).unwrap() && roles.list_roles().unwrap().contains(&viewer));
    assert_eq!(vec![base.clone()], roles.get_parent_roles(&viewer).unwrap());

    mem.create_membership(&alice, &org, EntityType::User).unwrap();
    assert!(mem.has_membership(&alice, &org).unwrap());
    assert_eq!(Some(MembershipStatus::Active), mem.get_status(&alice, &org).unwrap());
    assert_eq!(Some(EntityType::User), mem.get_entity_type(&alice, &org).unwrap());

    roles.assign_to_identity(&alice, &org, &viewer).unwrap();
    assert_eq!(vec![viewer.clone()], roles.get_identity_roles(&alice, &org).unwrap());
    groups.create_group(&team, &org, Some("Team"), None).unwrap();
    assert!(groups.has_group(&team, &org).unwrap());
    assert_eq!(vec![team.clone()], groups.list_groups(&org).unwrap());
    groups.add_identity_to_group(&team, &org, &alice).unwrap();
    assert_eq!(vec![alice.clone()], groups.get_group_members(&team, &org).unwrap());
    assert_eq!(vec![team.clone()], groups.get_identity_groups(&alice, &org).unwrap());
    roles.assign_to_group(&team, &org, &base).unwrap();
    assert_eq!(vec![base.clone()], roles.get_group_roles(&team, &org).unwrap());

    assert!(gh.has_permission(&alice, &org, &svc, "doc", "read").unwrap());
    assert!(!gh.get_effective_permissions(&alice, &org).unwrap().is_empty());
    assert_eq!(
        ExplanationOutcome::Allowed,
        gh.explain_permission(&alice, &org, &svc, "doc", "read").unwrap().outcome
    );
    assert!(gh.get_roles(&alice, &org).unwrap().contains(&viewer));
    assert!(gh.get_groups(&alice, &org).unwrap().contains(&team));
    mem.set_status(&alice, &org, MembershipStatus::Suspended).unwrap();
    assert!(!gh.has_permission(&alice, &org, &svc, "doc", "read").unwrap());
    mem.set_status(&alice, &org, MembershipStatus::Active).unwrap();

    // Failing operations return their connection too.
    assert!(matches!(roles.create_role(&viewer, "dup", None), Err(GatedhouseError::Database { .. })));
    assert!(matches!(roles.add_parent_role(&base, &viewer), Err(GatedhouseError::InvalidArgument(_))));
    mem.remove_membership(&alice, &org).unwrap();
    assert!(matches!(
        mem.set_status(&alice, &org, MembershipStatus::Suspended),
        Err(GatedhouseError::InvalidTransition(_))
    ));

    roles.revoke_from_group(&team, &org, &base).unwrap();
    groups.remove_identity_from_group(&team, &org, &alice).unwrap();
    roles.revoke_from_identity(&alice, &org, &viewer).unwrap();
    groups.delete_group(&team, &org).unwrap();
    roles.remove_parent_role(&viewer, &base).unwrap();
    roles.revoke_permission(&base, Some(&svc), Some("doc"), Some("read")).unwrap();
    roles.delete_role(&viewer).unwrap();
    roles.delete_role(&base).unwrap();
    cat.remove_action(&svc, "doc", "read").unwrap();
    cat.remove_resource(&svc, "doc").unwrap();
    cat.remove_service(&svc).unwrap();
}

// ---- C3 -------------------------------------------------------------------

#[test]
fn writes_commit() {
    let url = database_url!();
    let p = prefix();
    let gh = create(plain(&url, None));
    gh.role_manager().create_role(&format!("{p}r"), "R", None).unwrap();
    gh.membership_manager().create_membership(&format!("{p}id"), "o", EntityType::User).unwrap();
    assert!(row_exists(&url, "SELECT 1 FROM gatedhouse.roles WHERE key = $1", &format!("{p}r")));
    assert!(row_exists(
        &url,
        "SELECT 1 FROM gatedhouse.memberships WHERE identity_id = $1",
        &format!("{p}id")
    ));
}

// ---- C1, C2, C4 -----------------------------------------------------------

#[test]
fn every_operation_returns_its_connection_clean_and_never_holds_two() {
    let url = database_url!();
    let (db, stats) = Tracking::wrap(plain(&url, None));
    exercise_every_operation(&create(db), &prefix());
    assert_all_returned_clean(&stats);
    assert_eq!(1, stats.max_held_by_one_thread.load(Ordering::SeqCst), "held two at once");
}

#[test]
fn migrator_returns_its_connection_clean() {
    let url = database_url!();
    let (db, stats) = Tracking::wrap(plain(&url, None));
    GatedhouseFactory::migrate(&GatedhouseConfig::builder(db).build()).unwrap();
    assert_all_returned_clean(&stats);
}

// ---- C2 under a real pool: size 1 must not deadlock ------------------------

#[test]
fn a_pool_of_one_connection_runs_every_operation() {
    let url = database_url!();
    let settings = PoolSettings::default()
        .with_max_size(1)
        .with_connection_timeout(Duration::from_secs(2));
    let pool: Arc<dyn Database> = Arc::new(PooledDatabase::from_url_with(&url, settings).unwrap());
    let (done, finished) = mpsc::channel();
    thread::spawn(move || {
        exercise_every_operation(&create(pool), &prefix());
        done.send(()).unwrap();
    });
    finished
        .recv_timeout(Duration::from_secs(60))
        .expect("deadlocked or failed with a pool of one");
}

// ---- the production path: the host's own pool ------------------------------

#[test]
fn host_r2d2_pool_is_borrowed_from_and_returned_to() {
    let url = database_url!();
    let host = host_pool(&url, 4);
    let (db, stats) = Tracking::wrap(Arc::new(host.clone()));
    exercise_every_operation(&create(db), &prefix());
    assert_all_returned_clean(&stats);
    let state = host.state();
    assert_eq!(state.connections, state.idle_connections, "connections still checked out");
}

#[test]
fn any_pool_through_from_fn() {
    let url = database_url!();
    let host = host_pool(&url, 2);
    let db: Arc<dyn Database> =
        Arc::new(from_fn(move || Ok(Box::new(host.get()?) as PooledClient)));
    exercise_every_operation(&create(db), &prefix());
}

// ---- C6 -------------------------------------------------------------------

#[test]
fn exhausted_pool_fails_as_unavailable_within_its_timeout() {
    let url = database_url!();
    let settings = PoolSettings::default()
        .with_max_size(1)
        .with_connection_timeout(Duration::from_millis(300));
    let pool = Arc::new(PooledDatabase::from_url_with(&url, settings).unwrap());
    let gh = create(pool.clone());
    {
        let _held = pool.connection().unwrap(); // the only connection
        let start = Instant::now();
        let result = gh.has_permission("a", "b", "s", "r", "x");
        let elapsed = start.elapsed();
        assert_eq!(Some(DatabaseErrorKind::Unavailable), kind_of(result));
        assert!(elapsed < Duration::from_secs(3), "gave up after {elapsed:?}");
    }
    assert!(!gh.role_manager().has_role("no-such-role").unwrap(), "pool recovered");
}

#[test]
fn unreachable_database_fails_startup_as_unavailable() {
    let _ = database_url!();
    let settings = PoolSettings::default().with_connection_timeout(Duration::from_millis(300));
    let nowhere = PooledDatabase::from_url_with("host=127.0.0.1 port=1 user=u dbname=none", settings)
        .unwrap();
    let result = GatedhouseFactory::create(GatedhouseConfig::builder(Arc::new(nowhere)).build());
    assert_eq!(Some(DatabaseErrorKind::Unavailable), kind_of(result));
}

#[test]
fn a_connection_terminated_by_the_server_is_unavailable_and_a_refused_statement_is_query() {
    let url = database_url!();
    let admin_url = url.clone();
    let gh = create(plain(&url, None));
    // A refused statement: duplicate key.
    let key = format!("{}r", prefix());
    gh.role_manager().create_role(&key, "R", None).unwrap();
    assert_eq!(
        Some(DatabaseErrorKind::Query),
        kind_of(gh.role_manager().create_role(&key, "R", None))
    );
    // The server terminates the connection we are about to use (57P01).
    let doomed: Arc<dyn Database> = Arc::new(from_fn(move || {
        let mut client = Client::connect(&admin_url, NoTls)?;
        let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[])?.get(0);
        Client::connect(&admin_url, NoTls)?.execute("SELECT pg_terminate_backend($1)", &[&pid])?;
        Ok(Box::new(OwnedClient(client)) as PooledClient)
    }));
    let doomed_gh = gatedhouse_without_schema_check(doomed);
    assert_eq!(
        Some(DatabaseErrorKind::Unavailable),
        kind_of(doomed_gh.role_manager().has_role("x"))
    );
}

/// Builds a Gatedhouse whose schema check runs on a healthy connection, then
/// switches every later borrow to `then`.
fn gatedhouse_without_schema_check(then: Arc<dyn Database>) -> Arc<dyn Gatedhouse> {
    let url = url().unwrap();
    let healthy = plain(&url, None);
    let checked = Arc::new(AtomicUsize::new(0));
    let db: Arc<dyn Database> = Arc::new(from_fn(move || {
        if checked.fetch_add(1, Ordering::SeqCst) == 0 {
            healthy.connection()
        } else {
            then.connection()
        }
    }));
    create(db)
}

// ---- C7 -------------------------------------------------------------------

#[test]
fn one_instance_shared_by_many_threads_on_a_smaller_pool() {
    let url = database_url!();
    let p = prefix();
    let host = host_pool(&url, 4);
    let (db, stats) = Tracking::wrap(Arc::new(host.clone()));
    let gh = create(db);
    let svc = format!("{p}svc");
    let reader = format!("{p}reader");
    gh.permission_catalog().add_service(&svc, None).unwrap();
    gh.permission_catalog().add_resource(&svc, "doc", None).unwrap();
    gh.permission_catalog().add_action(&svc, "doc", "read", None).unwrap();
    gh.role_manager().create_role(&reader, "Reader", None).unwrap();
    gh.role_manager().grant_permission(&reader, Some(&svc), Some("doc"), Some("read")).unwrap();

    let workers: Vec<_> = (0..16)
        .map(|t| {
            let (gh, svc, reader) = (gh.clone(), svc.clone(), reader.clone());
            let id = format!("{p}user{t}");
            thread::spawn(move || {
                for i in 0..15 {
                    let org = format!("org{i}");
                    gh.membership_manager().create_membership(&id, &org, EntityType::User).unwrap();
                    gh.role_manager().assign_to_identity(&id, &org, &reader).unwrap();
                    assert!(gh.has_permission(&id, &org, &svc, "doc", "read").unwrap());
                    assert_eq!(
                        ExplanationOutcome::Allowed,
                        gh.explain_permission(&id, &org, &svc, "doc", "read").unwrap().outcome
                    );
                    gh.membership_manager().remove_membership(&id, &org).unwrap();
                    assert!(!gh.has_permission(&id, &org, &svc, "doc", "read").unwrap());
                }
            })
        })
        .collect();
    for w in workers {
        w.join().expect("worker failed");
    }
    assert_all_returned_clean(&stats);
    let state = host.state();
    assert_eq!(state.connections, state.idle_connections);
}

// ---- role inheritance stays acyclic --------------------------------------

#[test]
fn inheritance_cycles_are_rejected() {
    let url = database_url!();
    let p = prefix();
    let gh = create(plain(&url, None));
    let roles = gh.role_manager();
    let [a, b, c] = ["a", "b", "c"].map(|r| format!("{p}{r}"));
    for r in [&a, &b, &c] {
        roles.create_role(r, r, None).unwrap();
    }
    roles.add_parent_role(&a, &b).unwrap();
    roles.add_parent_role(&b, &c).unwrap();
    match roles.add_parent_role(&b, &a) {
        Err(GatedhouseError::InvalidArgument(msg)) => assert!(msg.contains("cycle"), "{msg}"),
        other => panic!("expected a cycle error, got {other:?}"),
    }
    assert!(matches!(roles.add_parent_role(&c, &a), Err(GatedhouseError::InvalidArgument(_))));
    assert!(matches!(roles.add_parent_role(&a, &a), Err(GatedhouseError::Database { .. })));
    roles.add_parent_role(&a, &c).unwrap(); // a shortcut is not a cycle
    assert_eq!(vec![b.clone(), c.clone()], roles.get_parent_roles(&a).unwrap());
}

#[test]
fn concurrent_opposite_edges_cannot_both_succeed() {
    let url = database_url!();
    // Also when sessions default to SERIALIZABLE: the check must not depend
    // on the host's isolation level.
    for options in [None, Some("-c default_transaction_isolation=serializable")] {
        let p = prefix();
        let gh = create(plain(&url, options));
        for i in 0..25 {
            let (a, b) = (format!("{p}a{i}"), format!("{p}b{i}"));
            gh.role_manager().create_role(&a, &a, None).unwrap();
            gh.role_manager().create_role(&b, &b, None).unwrap();
            let go = Arc::new(Barrier::new(2));
            let edge = |child: String, parent: String| {
                let (gh, go) = (gh.clone(), go.clone());
                thread::spawn(move || {
                    go.wait();
                    match gh.role_manager().add_parent_role(&child, &parent) {
                        Ok(()) => true,
                        Err(GatedhouseError::InvalidArgument(_)) => false,
                        Err(e) => panic!("unexpected failure ({options:?}): {e}"),
                    }
                })
            };
            let ab = edge(a.clone(), b.clone());
            let ba = edge(b.clone(), a.clone());
            let succeeded = ab.join().unwrap() as u8 + ba.join().unwrap() as u8;
            assert_eq!(1, succeeded, "both or neither of {a}<->{b} succeeded ({options:?})");
        }
    }
}

// ---- settings (no database) ----------------------------------------------

#[test]
fn pool_settings_defaults() {
    let s = PoolSettings::default();
    assert_eq!(10, s.max_size());
    assert_eq!(Duration::from_secs(10), s.connection_timeout());
    assert_eq!(Duration::from_secs(1800), s.max_lifetime());
}

#[test]
#[should_panic(expected = "max_size must be at least 1")]
fn pool_settings_reject_an_empty_pool() {
    let _ = PoolSettings::default().with_max_size(0);
}

#[test]
#[should_panic(expected = "connection_timeout must be at least 250 ms")]
fn pool_settings_reject_a_tiny_timeout() {
    let _ = PoolSettings::default().with_connection_timeout(Duration::from_millis(249));
}

#[test]
#[should_panic(expected = "max_lifetime must be at least 30 seconds")]
fn pool_settings_reject_a_tiny_lifetime() {
    let _ = PoolSettings::default().with_max_lifetime(Duration::from_secs(29));
}

#[test]
fn an_invalid_connection_string_is_an_initialization_error() {
    assert!(matches!(
        PooledDatabase::from_url("not a valid = = conninfo '"),
        Err(GatedhouseError::Initialization(_))
    ));
}
