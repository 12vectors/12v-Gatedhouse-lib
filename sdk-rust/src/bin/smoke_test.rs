// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! End-to-end smoke test, ported from the Java `SmokeTest`. Idempotent
//! and self-cleaning — runs against a real Postgres pointed at by the
//! supplied conninfo string.
//!
//! Usage:
//!     cargo run --bin gatedhouse-smoke-test -- <conninfo>

use std::process::ExitCode;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use gatedhouse::{
    ConninfoDatabase, Database, EntityType, Gatedhouse, GatedhouseConfig, GatedhouseFactory,
    InMemoryPermissionCache, MembershipStatus,
};

// ---- fixtures ------------------------------------------------------------

const SVC: &str = "smoketestsvc";
const RES_PROJ: &str = "projects";
const RES_DOC: &str = "documents";
const ACT_READ: &str = "read";
const ACT_WRITE: &str = "write";
const ACT_DELETE: &str = "delete";
const ACT_DEPLOY: &str = "deploy";

const ROLE_VIEWER: &str = "smoketestviewer";
const ROLE_EDITOR: &str = "smoketesteditor";
const ROLE_READER: &str = "smoketestreader";
const ROLE_DEPLOYER: &str = "smoketestdeployer";
const OWNER_ROLE: &str = "gatedhouse:owner";

const ORG: &str = "smoketestorg";
const IDENTITY_ALICE: &str = "smoketestalice";
const IDENTITY_BOB: &str = "smoketestbob";
const GROUP_ENG: &str = "smoketestgroup";

static PASSED: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn section(title: &str) {
    println!();
    println!("=== {title} ===");
}

fn check(description: &str, condition: bool) {
    if condition {
        PASSED.fetch_add(1, Ordering::Relaxed);
        println!("  [PASS] {description}");
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        println!("  [FAIL] {description}");
    }
}

// ---- main ----------------------------------------------------------------

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        eprintln!(
            "Usage: gatedhouse-smoke-test <conninfo>\n\n\
             Example:\n\
             \x20   gatedhouse-smoke-test 'host=localhost user=postgres password=secret dbname=mydb'"
        );
        return ExitCode::from(2);
    }

    let database: Arc<dyn Database> = Arc::new(ConninfoDatabase::new(&args[0]));
    let cache = Arc::new(InMemoryPermissionCache::new());
    let config = GatedhouseConfig::builder(database.clone())
        .permission_cache(cache.clone())
        .build();

    let gh = match GatedhouseFactory::create(config) {
        Ok(gh) => gh,
        Err(e) => {
            eprintln!("Gatedhouse initialization failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cleanup(database.as_ref()).expect("initial cleanup");
        setup_catalog(gh.as_ref());
        setup_roles_and_memberships(gh.as_ref());
        run_scenarios(gh.as_ref());
        run_cache_scenarios(gh.as_ref(), &cache);
        run_ttl_scenario(database.clone());
    }));

    if let Err(e) = cleanup(database.as_ref()) {
        eprintln!("Cleanup failed: {e}");
    }

    if result.is_err() {
        eprintln!("Smoke test panicked.");
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    println!("\n{p} passed, {f} failed");
    if f == 0 && result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// ---- setup ---------------------------------------------------------------

fn setup_catalog(gh: &dyn Gatedhouse) {
    section("Setup: catalog");
    let cat = gh.permission_catalog();
    cat.add_service(SVC, Some("Smoke test service")).unwrap();
    cat.add_resource(SVC, RES_PROJ, Some("Projects")).unwrap();
    cat.add_resource(SVC, RES_DOC, Some("Documents")).unwrap();
    cat.add_action(SVC, RES_PROJ, ACT_READ, Some("Read projects")).unwrap();
    cat.add_action(SVC, RES_PROJ, ACT_WRITE, Some("Write projects")).unwrap();
    cat.add_action(SVC, RES_PROJ, ACT_DELETE, Some("Delete projects")).unwrap();
    cat.add_action(SVC, RES_PROJ, ACT_DEPLOY, Some("Deploy projects")).unwrap();
    cat.add_action(SVC, RES_DOC, ACT_READ, Some("Read documents")).unwrap();
    check("catalog.has_service", cat.has_service(SVC).unwrap());
    check("catalog.has_resource", cat.has_resource(SVC, RES_PROJ).unwrap());
    check("catalog.has_action", cat.has_action(SVC, RES_PROJ, ACT_READ).unwrap());
    check(
        "catalog.list_actions(projects) returns 4",
        cat.list_actions(SVC, RES_PROJ).unwrap().len() == 4,
    );
}

fn setup_roles_and_memberships(gh: &dyn Gatedhouse) {
    section("Setup: roles + memberships");
    let rm = gh.role_manager();

    rm.create_role(ROLE_VIEWER, "Viewer", Some("Read-only")).unwrap();
    rm.grant_permission(ROLE_VIEWER, Some(SVC), Some(RES_PROJ), Some(ACT_READ)).unwrap();

    rm.create_role(ROLE_EDITOR, "Editor", Some("Read+write")).unwrap();
    rm.add_parent_role(ROLE_EDITOR, ROLE_VIEWER).unwrap();
    rm.grant_permission(ROLE_EDITOR, Some(SVC), Some(RES_PROJ), Some(ACT_WRITE)).unwrap();

    rm.create_role(ROLE_READER, "Reader", Some("Read across all resources")).unwrap();
    rm.grant_permission(ROLE_READER, Some(SVC), None, Some(ACT_READ)).unwrap();

    rm.create_role(ROLE_DEPLOYER, "Deployer", Some("Can deploy")).unwrap();
    rm.grant_permission(ROLE_DEPLOYER, Some(SVC), Some(RES_PROJ), Some(ACT_DEPLOY)).unwrap();

    gh.membership_manager()
        .create_membership(IDENTITY_ALICE, ORG, EntityType::User)
        .unwrap();
    gh.membership_manager()
        .create_membership(IDENTITY_BOB, ORG, EntityType::Agent)
        .unwrap();

    check("role_manager.has_role(viewer)", rm.has_role(ROLE_VIEWER).unwrap());
    check(
        "role_manager.get_parent_roles(editor) contains viewer",
        rm.get_parent_roles(ROLE_EDITOR)
            .unwrap()
            .iter()
            .any(|s| s == ROLE_VIEWER),
    );
    check(
        "membership_manager.has_membership(alice)",
        gh.membership_manager().has_membership(IDENTITY_ALICE, ORG).unwrap(),
    );
    check(
        "membership_manager.get_status(alice) == Active",
        gh.membership_manager().get_status(IDENTITY_ALICE, ORG).unwrap()
            == Some(MembershipStatus::Active),
    );
    check(
        "membership_manager.get_entity_type(bob) == Agent",
        gh.membership_manager().get_entity_type(IDENTITY_BOB, ORG).unwrap()
            == Some(EntityType::Agent),
    );
}

// ---- behavioral scenarios ------------------------------------------------

fn run_scenarios(gh: &dyn Gatedhouse) {
    section("Scenario: no roles → no perms");
    check(
        "alice has no perms before assignment",
        !gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap(),
    );

    section("Scenario: direct role assignment + inheritance");
    gh.role_manager().assign_to_identity(IDENTITY_ALICE, ORG, ROLE_EDITOR).unwrap();
    check(
        "alice can write (direct grant on editor)",
        gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE).unwrap(),
    );
    check(
        "alice can read (inherited from viewer)",
        gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap(),
    );
    check(
        "alice cannot delete (not granted anywhere)",
        !gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_DELETE).unwrap(),
    );
    check(
        "alice cannot read documents (editor only grants read on projects)",
        !gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_DOC, ACT_READ).unwrap(),
    );

    section("Scenario: suspension short-circuits to deny");
    gh.membership_manager()
        .set_status(IDENTITY_ALICE, ORG, MembershipStatus::Suspended)
        .unwrap();
    check(
        "suspended alice cannot read",
        !gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap(),
    );
    gh.membership_manager()
        .set_status(IDENTITY_ALICE, ORG, MembershipStatus::Active)
        .unwrap();
    check(
        "reactivated alice can read again",
        gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap(),
    );

    section("Scenario: pending = deny (per spec)");
    gh.membership_manager()
        .set_status(IDENTITY_ALICE, ORG, MembershipStatus::Pending)
        .unwrap();
    check(
        "pending alice cannot read",
        !gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap(),
    );
    gh.membership_manager()
        .set_status(IDENTITY_ALICE, ORG, MembershipStatus::Active)
        .unwrap();

    section("Scenario: wildcard grant (svc, *, read) covers any resource");
    gh.role_manager().assign_to_identity(IDENTITY_BOB, ORG, ROLE_READER).unwrap();
    check(
        "bob can read projects via wildcard",
        gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_READ).unwrap(),
    );
    check(
        "bob can read documents via wildcard",
        gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_DOC, ACT_READ).unwrap(),
    );
    check(
        "bob still cannot write projects (only read is wildcarded)",
        !gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_WRITE).unwrap(),
    );

    section("Scenario: permission via group membership");
    gh.group_manager()
        .create_group(GROUP_ENG, ORG, Some("Engineering"), Some("Smoke test group"))
        .unwrap();
    gh.group_manager().add_identity_to_group(GROUP_ENG, ORG, IDENTITY_BOB).unwrap();
    gh.role_manager().assign_to_group(GROUP_ENG, ORG, ROLE_DEPLOYER).unwrap();
    check(
        "bob can deploy (via engineering group → deployer role)",
        gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_DEPLOY).unwrap(),
    );
    check(
        "alice cannot deploy (not in group)",
        !gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_DEPLOY).unwrap(),
    );

    section("Scenario: built-in owner role grants everything");
    gh.role_manager().assign_to_identity(IDENTITY_ALICE, ORG, OWNER_ROLE).unwrap();
    check(
        "owner alice can delete (full wildcard)",
        gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_DELETE).unwrap(),
    );
    check(
        "owner alice can read documents",
        gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_DOC, ACT_READ).unwrap(),
    );
    check(
        "owner alice can do anything on a fictional resource",
        gh.has_permission(IDENTITY_ALICE, ORG, "anyservice", "anyresource", "anyaction").unwrap(),
    );

    section("Scenario: get_effective_permissions");
    let bob_perms = gh.get_effective_permissions(IDENTITY_BOB, ORG).unwrap();
    check(
        "bob has at least 2 effective permissions (wildcard read + deploy)",
        bob_perms.len() >= 2,
    );
    check(
        "bob's effective perms contain (svc, None, read) — the wildcard grant",
        bob_perms.iter().any(|p| {
            p.service.as_deref() == Some(SVC)
                && p.resource.is_none()
                && p.action.as_deref() == Some(ACT_READ)
        }),
    );
    check(
        "bob's effective perms contain (svc, projects, deploy) — via group",
        bob_perms.iter().any(|p| {
            p.service.as_deref() == Some(SVC)
                && p.resource.as_deref() == Some(RES_PROJ)
                && p.action.as_deref() == Some(ACT_DEPLOY)
        }),
    );

    section("Scenario: delete identity from group revokes group-derived perms");
    gh.group_manager().remove_identity_from_group(GROUP_ENG, ORG, IDENTITY_BOB).unwrap();
    check(
        "bob can no longer deploy (removed from group)",
        !gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_DEPLOY).unwrap(),
    );

    section("Scenario: revoke role from identity");
    gh.role_manager().revoke_from_identity(IDENTITY_ALICE, ORG, OWNER_ROLE).unwrap();
    check(
        "after revoking owner, alice can no longer delete",
        !gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_DELETE).unwrap(),
    );
    check(
        "but alice can still read (editor → viewer chain still in place)",
        gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap(),
    );

    section("Scenario: missing membership = deny");
    check(
        "unknown identity has no perms",
        !gh.has_permission("noSuchIdentity", ORG, SVC, RES_PROJ, ACT_READ).unwrap(),
    );
    check(
        "unknown identity has empty effective perms",
        gh.get_effective_permissions("noSuchIdentity", ORG).unwrap().is_empty(),
    );
}

// ---- cache scenarios -----------------------------------------------------

fn run_cache_scenarios(gh: &dyn Gatedhouse, cache: &Arc<InMemoryPermissionCache>) {
    section("Cache: cold read populates");
    gh.invalidate_all_cache();
    cache.reset_stats();
    check(
        "starting empty",
        cache.size() == 0 && cache.hit_count() == 0 && cache.miss_count() == 0,
    );
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    check("after cold read: 1 miss", cache.miss_count() == 1);
    check("after cold read: 0 hits", cache.hit_count() == 0);
    check("after cold read: 1 put", cache.put_count() == 1);
    check("after cold read: size 1", cache.size() == 1);

    section("Cache: warm read serves from cache (no DB)");
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE).unwrap();
    check("warm read: still 1 miss", cache.miss_count() == 1);
    check("warm read: 1 hit", cache.hit_count() == 1);
    check("warm read: still size 1", cache.size() == 1);

    section("Cache: has_permission and get_effective_permissions share cache");
    gh.invalidate_all_cache();
    cache.reset_stats();
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    gh.get_effective_permissions(IDENTITY_ALICE, ORG).unwrap();
    check("shared cache: 1 miss", cache.miss_count() == 1);
    check("shared cache: 1 hit", cache.hit_count() == 1);

    section("Cache: targeted invalidation on assign_to_identity");
    gh.invalidate_all_cache();
    cache.reset_stats();
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    check("both cached: size 2", cache.size() == 2);
    cache.reset_stats();
    gh.role_manager().assign_to_identity(IDENTITY_ALICE, ORG, ROLE_DEPLOYER).unwrap();
    check(
        "targeted invalidate fired",
        cache.targeted_invalidation_count() == 1,
    );
    check(
        "no wholesale invalidation",
        cache.wholesale_invalidation_count() == 0,
    );
    check("only alice evicted: size 1", cache.size() == 1);
    cache.reset_stats();
    gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    check(
        "bob still cached: hit, no miss",
        cache.hit_count() == 1 && cache.miss_count() == 0,
    );
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    check("alice re-fetched: 1 miss", cache.miss_count() == 1);
    gh.role_manager().revoke_from_identity(IDENTITY_ALICE, ORG, ROLE_DEPLOYER).unwrap();

    section("Cache: wholesale invalidation on grant_permission");
    // The granted service must exist in the catalog (FK on role_permissions).
    gh.permission_catalog()
        .add_service("smoketestneversvc", Some("Never-used service"))
        .unwrap();
    gh.invalidate_all_cache();
    cache.reset_stats();
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    check("both cached: size 2", cache.size() == 2);
    cache.reset_stats();
    gh.role_manager().grant_permission(ROLE_VIEWER, Some("smoketestneversvc"), None, None).unwrap();
    check(
        "wholesale invalidation fired",
        cache.wholesale_invalidation_count() == 1,
    );
    check("everything evicted: size 0", cache.size() == 0);
    gh.role_manager().revoke_permission(ROLE_VIEWER, Some("smoketestneversvc"), None, None).unwrap();
    gh.permission_catalog().remove_service("smoketestneversvc").unwrap();

    section("Cache: set_status invalidates and new status reflected");
    gh.invalidate_all_cache();
    cache.reset_stats();
    let active_before = gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    check("alice active can read", active_before);
    cache.reset_stats();
    gh.membership_manager()
        .set_status(IDENTITY_ALICE, ORG, MembershipStatus::Suspended)
        .unwrap();
    check(
        "set_status targeted invalidate",
        cache.targeted_invalidation_count() == 1,
    );
    let read_suspended = gh
        .has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
        .unwrap();
    check(
        "suspended alice cannot read after invalidation",
        !read_suspended,
    );
    gh.membership_manager()
        .set_status(IDENTITY_ALICE, ORG, MembershipStatus::Active)
        .unwrap();
    let read_reactivated = gh
        .has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
        .unwrap();
    check("reactivated alice can read again", read_reactivated);

    section("Cache: empty effective set is cached, not re-fetched");
    gh.invalidate_all_cache();
    cache.reset_stats();
    let unknown_id = "smoketestnobody";
    let a = gh
        .has_permission(unknown_id, ORG, SVC, RES_PROJ, ACT_READ)
        .unwrap();
    let b = gh
        .has_permission(unknown_id, ORG, SVC, RES_DOC, ACT_READ)
        .unwrap();
    check("unknown identity always denied", !a && !b);
    check(
        "unknown identity: 1 miss + 1 hit",
        cache.miss_count() == 1 && cache.hit_count() == 1,
    );
    check(
        "unknown identity: empty list is cached (size 1)",
        cache.size() == 1,
    );

    section("Cache: manual invalidate_cache on Gatedhouse");
    gh.invalidate_all_cache();
    cache.reset_stats();
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    check("cached: size 1", cache.size() == 1);
    cache.reset_stats();
    gh.invalidate_cache(IDENTITY_ALICE, ORG);
    check("after invalidate_cache: size 0", cache.size() == 0);
    check(
        "after invalidate_cache: targeted=1",
        cache.targeted_invalidation_count() == 1,
    );

    section("Cache: manual invalidate_all_cache on Gatedhouse");
    gh.invalidate_all_cache();
    cache.reset_stats();
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    check("two cached: size 2", cache.size() == 2);
    cache.reset_stats();
    gh.invalidate_all_cache();
    check("after invalidate_all_cache: size 0", cache.size() == 0);
    check(
        "after invalidate_all_cache: wholesale=1",
        cache.wholesale_invalidation_count() == 1,
    );

    section("Cache: kill switch — disable at runtime");
    gh.invalidate_all_cache();
    cache.reset_stats();
    check("configured cache starts enabled", gh.is_cache_enabled());
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    check(
        "warm-up: 1 miss + 1 put + size 1",
        cache.miss_count() == 1 && cache.put_count() == 1 && cache.size() == 1,
    );
    gh.set_cache_enabled(false);
    check("cache is disabled", !gh.is_cache_enabled());
    cache.reset_stats();
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE).unwrap();
    gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    check(
        "disabled: zero hits and zero misses",
        cache.hit_count() == 0 && cache.miss_count() == 0,
    );
    check("disabled: zero puts", cache.put_count() == 0);
    check("disabled: cache size unchanged from warm-up", cache.size() == 1);
    gh.role_manager().assign_to_identity(IDENTITY_ALICE, ORG, ROLE_DEPLOYER).unwrap();
    check(
        "disabled: writes still invalidate cache",
        cache.targeted_invalidation_count() == 1,
    );
    gh.role_manager().revoke_from_identity(IDENTITY_ALICE, ORG, ROLE_DEPLOYER).unwrap();
    gh.set_cache_enabled(true);
    check("cache is enabled again", gh.is_cache_enabled());
    cache.reset_stats();
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    check(
        "resumed: cold read = 1 miss",
        cache.miss_count() == 1 && cache.put_count() == 1,
    );
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE).unwrap();
    check("resumed: warm read = 1 hit", cache.hit_count() == 1);

    section("Cache: result consistency (cached vs fresh)");
    gh.invalidate_all_cache();
    let fresh = gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    let cached = gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    check("cached result matches fresh result", fresh == cached);
    let p1 = gh.get_effective_permissions(IDENTITY_ALICE, ORG).unwrap();
    gh.invalidate_cache(IDENTITY_ALICE, ORG);
    let p2 = gh.get_effective_permissions(IDENTITY_ALICE, ORG).unwrap();
    let s1: std::collections::HashSet<_> = p1.into_iter().collect();
    let s2: std::collections::HashSet<_> = p2.into_iter().collect();
    check(
        "get_effective_permissions is consistent across cache hits & misses",
        s1 == s2,
    );
}

fn run_ttl_scenario(database: Arc<dyn Database>) {
    section("Cache: TTL expiry");
    let short_ttl = Arc::new(InMemoryPermissionCache::with_ttl(Duration::from_millis(100)));
    let cfg = GatedhouseConfig::builder(database)
        .permission_cache(short_ttl.clone())
        .build();
    let gh2 = GatedhouseFactory::create(cfg).expect("ttl gatedhouse create");

    gh2.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    check(
        "ttl: cold read = 1 miss",
        short_ttl.miss_count() == 1 && short_ttl.hit_count() == 0,
    );

    gh2.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE).unwrap();
    check(
        "ttl: warm read = 1 hit",
        short_ttl.miss_count() == 1 && short_ttl.hit_count() == 1,
    );

    sleep(Duration::from_millis(150)); // > TTL of 100ms

    gh2.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ).unwrap();
    check(
        "ttl: read after expiry = 2 misses (entry re-fetched)",
        short_ttl.miss_count() == 2,
    );
}

// ---- cleanup -------------------------------------------------------------

fn cleanup(database: &dyn Database) -> Result<(), postgres::Error> {
    let mut conn = database.connection()?;
    let statements: &[&str] = &[
        "DELETE FROM gatedhouse.role_assignments WHERE org_id = 'smoketestorg'",
        // cascades to group_memberships, group_roles
        "DELETE FROM gatedhouse.groups WHERE org_id = 'smoketestorg'",
        "DELETE FROM gatedhouse.memberships WHERE org_id = 'smoketestorg'",
        // cascades to role_permissions, role_inherits
        "DELETE FROM gatedhouse.roles WHERE key IN \
         ('smoketestviewer','smoketesteditor','smoketestreader','smoketestdeployer')",
        // cascades to resources, actions
        "DELETE FROM gatedhouse.services WHERE service IN ('smoketestsvc', 'smoketestneversvc')",
    ];
    for sql in statements {
        conn.execute(*sql, &[])?;
    }
    Ok(())
}
