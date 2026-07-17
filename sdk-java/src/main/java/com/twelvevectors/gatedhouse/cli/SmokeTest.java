// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse.cli;

import com.twelvevectors.gatedhouse.Database;
import com.twelvevectors.gatedhouse.EffectivePermission;
import com.twelvevectors.gatedhouse.EntityType;
import com.twelvevectors.gatedhouse.Gatedhouse;
import com.twelvevectors.gatedhouse.GatedhouseConfig;
import com.twelvevectors.gatedhouse.GatedhouseFactory;
import com.twelvevectors.gatedhouse.InMemoryPermissionCache;
import com.twelvevectors.gatedhouse.MembershipStatus;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.List;

public final class SmokeTest {

    // Stable, prefix-namespaced fixtures (no underscores so cleanup is exact).
    private static final String SVC      = "smoketestsvc";
    private static final String RES_PROJ = "projects";
    private static final String RES_DOC  = "documents";
    private static final String ACT_READ   = "read";
    private static final String ACT_WRITE  = "write";
    private static final String ACT_DELETE = "delete";
    private static final String ACT_DEPLOY = "deploy";

    private static final String ROLE_VIEWER   = "smoketestviewer";
    private static final String ROLE_EDITOR   = "smoketesteditor";
    private static final String ROLE_READER   = "smoketestreader";
    private static final String ROLE_DEPLOYER = "smoketestdeployer";
    private static final String OWNER_ROLE    = "gatedhouse:owner"; // seeded by V001

    private static final String ORG          = "smoketestorg";
    private static final String IDENTITY_ALICE = "smoketestalice";
    private static final String IDENTITY_BOB   = "smoketestbob";
    private static final String GROUP_ENG    = "smoketestgroup";

    private static int passed = 0;
    private static int failed = 0;

    private SmokeTest() {
    }

    public static void main(String[] args) {
        if (args.length < 2 || args.length > 3) {
            System.err.println(
                "Usage: java -cp gatedhouse-<v>.jar:postgresql-<v>.jar \\\n"
                + "         com.twelvevectors.gatedhouse.cli.SmokeTest \\\n"
                + "         <jdbc-url> <user> [password]");
            System.exit(2);
        }

        String url = args[0];
        String user = args[1];
        String password = args.length == 3 ? args[2] : "";

        Database database = Database.fromUrl(url, user, password);
        // Hold a reference so the cache scenarios can inspect hits/misses
        // and verify invalidation behavior, not just outcomes.
        InMemoryPermissionCache cache = new InMemoryPermissionCache();
        GatedhouseConfig config = GatedhouseConfig.builder()
            .database(database)
            .permissionCache(cache)
            .build();

        try (Gatedhouse gh = GatedhouseFactory.create(config)) {
            try {
                cleanup(database);
                setupCatalog(gh);
                setupRolesAndMemberships(gh);
                runScenarios(gh);
                runCacheScenarios(gh, cache);
                // TTL test uses a second Gatedhouse with a tiny-TTL cache,
                // sharing the same DB and fixtures.
                runTtlScenario(database);
            } finally {
                try {
                    cleanup(database);
                } catch (RuntimeException e) {
                    System.err.println("Cleanup failed: " + e.getMessage());
                }
            }
        }

        System.out.printf("%n%d passed, %d failed%n", passed, failed);
        System.exit(failed == 0 ? 0 : 1);
    }

    // ---- setup -------------------------------------------------------------

    private static void setupCatalog(Gatedhouse gh) {
        section("Setup: catalog");
        gh.permissionCatalog().addService(SVC, "Smoke test service");
        gh.permissionCatalog().addResource(SVC, RES_PROJ, "Projects");
        gh.permissionCatalog().addResource(SVC, RES_DOC,  "Documents");
        gh.permissionCatalog().addAction(SVC, RES_PROJ, ACT_READ,   "Read projects");
        gh.permissionCatalog().addAction(SVC, RES_PROJ, ACT_WRITE,  "Write projects");
        gh.permissionCatalog().addAction(SVC, RES_PROJ, ACT_DELETE, "Delete projects");
        gh.permissionCatalog().addAction(SVC, RES_PROJ, ACT_DEPLOY, "Deploy projects");
        gh.permissionCatalog().addAction(SVC, RES_DOC,  ACT_READ,   "Read documents");
        check("catalog.hasService",
            gh.permissionCatalog().hasService(SVC));
        check("catalog.hasResource",
            gh.permissionCatalog().hasResource(SVC, RES_PROJ));
        check("catalog.hasAction",
            gh.permissionCatalog().hasAction(SVC, RES_PROJ, ACT_READ));
        check("catalog.listActions(projects) returns 4",
            gh.permissionCatalog().listActions(SVC, RES_PROJ).size() == 4);
    }

    private static void setupRolesAndMemberships(Gatedhouse gh) {
        section("Setup: roles + memberships");

        // viewer: read projects only
        gh.roleManager().createRole(ROLE_VIEWER, "Viewer", "Read-only");
        gh.roleManager().grantPermission(ROLE_VIEWER, SVC, RES_PROJ, ACT_READ);

        // editor: inherits viewer + can write projects
        gh.roleManager().createRole(ROLE_EDITOR, "Editor", "Read+write");
        gh.roleManager().addParentRole(ROLE_EDITOR, ROLE_VIEWER);
        gh.roleManager().grantPermission(ROLE_EDITOR, SVC, RES_PROJ, ACT_WRITE);

        // reader: wildcard read across all resources of svc (workspace:*:read style)
        gh.roleManager().createRole(ROLE_READER, "Reader", "Read across all resources");
        gh.roleManager().grantPermission(ROLE_READER, SVC, null, ACT_READ);

        // deployer: deploy projects (assigned to a group, not directly)
        gh.roleManager().createRole(ROLE_DEPLOYER, "Deployer", "Can deploy");
        gh.roleManager().grantPermission(ROLE_DEPLOYER, SVC, RES_PROJ, ACT_DEPLOY);

        // memberships
        gh.membershipManager().createMembership(IDENTITY_ALICE, ORG, EntityType.USER);
        gh.membershipManager().createMembership(IDENTITY_BOB,   ORG, EntityType.AGENT);

        check("roleManager.hasRole(viewer)", gh.roleManager().hasRole(ROLE_VIEWER));
        check("roleManager.getParentRoles(editor) contains viewer",
            gh.roleManager().getParentRoles(ROLE_EDITOR).contains(ROLE_VIEWER));
        check("membershipManager.hasMembership(alice)",
            gh.membershipManager().hasMembership(IDENTITY_ALICE, ORG));
        check("membershipManager.getStatus(alice) = ACTIVE",
            gh.membershipManager().getStatus(IDENTITY_ALICE, ORG)
                .orElseThrow() == MembershipStatus.ACTIVE);
        check("membershipManager.getEntityType(bob) = AGENT",
            gh.membershipManager().getEntityType(IDENTITY_BOB, ORG)
                .orElseThrow() == EntityType.AGENT);
    }

    // ---- scenarios ---------------------------------------------------------

    private static void runScenarios(Gatedhouse gh) {
        section("Scenario: no roles → no perms");
        check("alice has no perms before assignment",
            !gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ));

        section("Scenario: direct role assignment + inheritance");
        gh.roleManager().assignToIdentity(IDENTITY_ALICE, ORG, ROLE_EDITOR);
        check("alice can write (direct grant on editor)",
            gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE));
        check("alice can read (inherited from viewer)",
            gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ));
        check("alice cannot delete (not granted anywhere)",
            !gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_DELETE));
        check("alice cannot read documents (editor only grants read on projects)",
            !gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_DOC, ACT_READ));

        section("Scenario: suspension short-circuits to deny");
        gh.membershipManager().setStatus(IDENTITY_ALICE, ORG, MembershipStatus.SUSPENDED);
        check("suspended alice cannot read",
            !gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ));
        gh.membershipManager().setStatus(IDENTITY_ALICE, ORG, MembershipStatus.ACTIVE);
        check("reactivated alice can read again",
            gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ));

        section("Scenario: pending = deny (per spec)");
        gh.membershipManager().setStatus(IDENTITY_ALICE, ORG, MembershipStatus.PENDING);
        check("pending alice cannot read",
            !gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ));
        gh.membershipManager().setStatus(IDENTITY_ALICE, ORG, MembershipStatus.ACTIVE);

        section("Scenario: wildcard grant (svc, *, read) covers any resource");
        gh.roleManager().assignToIdentity(IDENTITY_BOB, ORG, ROLE_READER);
        check("bob can read projects via wildcard",
            gh.hasPermission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_READ));
        check("bob can read documents via wildcard",
            gh.hasPermission(IDENTITY_BOB, ORG, SVC, RES_DOC, ACT_READ));
        check("bob still cannot write projects (only read is wildcarded)",
            !gh.hasPermission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_WRITE));

        section("Scenario: permission via group membership");
        gh.groupManager().createGroup(GROUP_ENG, ORG, "Engineering", "Smoke test group");
        gh.groupManager().addIdentityToGroup(GROUP_ENG, ORG, IDENTITY_BOB);
        gh.roleManager().assignToGroup(GROUP_ENG, ORG, ROLE_DEPLOYER);
        check("bob can deploy (via engineering group → deployer role)",
            gh.hasPermission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_DEPLOY));
        check("alice cannot deploy (not in group)",
            !gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_DEPLOY));

        section("Scenario: built-in owner role grants everything");
        gh.roleManager().assignToIdentity(IDENTITY_ALICE, ORG, OWNER_ROLE);
        check("owner alice can delete (full wildcard)",
            gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_DELETE));
        check("owner alice can read documents",
            gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_DOC, ACT_READ));
        check("owner alice can do something on a totally fictional resource",
            gh.hasPermission(IDENTITY_ALICE, ORG, "anyservice", "anyresource", "anyaction"));

        section("Scenario: getEffectivePermissions");
        List<EffectivePermission> bobPerms =
            gh.getEffectivePermissions(IDENTITY_BOB, ORG);
        check("bob has at least 2 effective permissions (wildcard read + deploy)",
            bobPerms.size() >= 2);
        check("bob's effective perms contain (svc, null, read) — the wildcard grant",
            bobPerms.stream().anyMatch(p ->
                SVC.equals(p.service()) && p.resource() == null && ACT_READ.equals(p.action())));
        check("bob's effective perms contain (svc, projects, deploy) — via group",
            bobPerms.stream().anyMatch(p ->
                SVC.equals(p.service()) && RES_PROJ.equals(p.resource()) && ACT_DEPLOY.equals(p.action())));

        section("Scenario: delete identity from group revokes group-derived perms");
        gh.groupManager().removeIdentityFromGroup(GROUP_ENG, ORG, IDENTITY_BOB);
        check("bob can no longer deploy (removed from group)",
            !gh.hasPermission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_DEPLOY));

        section("Scenario: revoke role from identity");
        gh.roleManager().revokeFromIdentity(IDENTITY_ALICE, ORG, OWNER_ROLE);
        check("after revoking owner, alice can no longer delete",
            !gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_DELETE));
        check("but alice can still read (editor → viewer chain still in place)",
            gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ));

        section("Scenario: missing membership = deny (no row at all)");
        check("unknown identity has no perms",
            !gh.hasPermission("noSuchIdentity", ORG, SVC, RES_PROJ, ACT_READ));
        check("unknown identity has empty effective perms",
            gh.getEffectivePermissions("noSuchIdentity", ORG).isEmpty());
    }

    // ---- cache scenarios ---------------------------------------------------

    private static void runCacheScenarios(Gatedhouse gh, InMemoryPermissionCache cache) {

        section("Cache: cold read populates");
        gh.invalidateAllCache();
        cache.resetStats();
        check("starting empty",
            cache.size() == 0
                && cache.hitCount() == 0
                && cache.missCount() == 0);
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        check("after cold read: 1 miss",  cache.missCount() == 1);
        check("after cold read: 0 hits",  cache.hitCount() == 0);
        check("after cold read: 1 put",   cache.putCount() == 1);
        check("after cold read: size 1",  cache.size() == 1);

        section("Cache: warm read serves from cache (no DB)");
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE);
        check("warm read: still 1 miss", cache.missCount() == 1);
        check("warm read: 1 hit",        cache.hitCount() == 1);
        check("warm read: still size 1", cache.size() == 1);

        section("Cache: hasPermission and getEffectivePermissions share cache");
        gh.invalidateAllCache();
        cache.resetStats();
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ); // 1 miss
        gh.getEffectivePermissions(IDENTITY_ALICE, ORG);                 // hit
        check("shared cache: 1 miss", cache.missCount() == 1);
        check("shared cache: 1 hit",  cache.hitCount() == 1);

        section("Cache: targeted invalidation on assignToIdentity");
        gh.invalidateAllCache();
        cache.resetStats();
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        gh.hasPermission(IDENTITY_BOB,   ORG, SVC, RES_PROJ, ACT_READ);
        check("both cached: size 2", cache.size() == 2);
        cache.resetStats();
        gh.roleManager().assignToIdentity(IDENTITY_ALICE, ORG, ROLE_DEPLOYER);
        check("targeted invalidate fired",
            cache.targetedInvalidationCount() == 1);
        check("no wholesale invalidation",
            cache.wholesaleInvalidationCount() == 0);
        check("only alice evicted: size 1", cache.size() == 1);
        cache.resetStats();
        gh.hasPermission(IDENTITY_BOB,   ORG, SVC, RES_PROJ, ACT_READ);
        check("bob still cached: hit, no miss",
            cache.hitCount() == 1 && cache.missCount() == 0);
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        check("alice re-fetched: 1 miss", cache.missCount() == 1);
        // restore state
        gh.roleManager().revokeFromIdentity(IDENTITY_ALICE, ORG, ROLE_DEPLOYER);

        section("Cache: wholesale invalidation on grantPermission");
        gh.invalidateAllCache();
        cache.resetStats();
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        gh.hasPermission(IDENTITY_BOB,   ORG, SVC, RES_PROJ, ACT_READ);
        check("both cached: size 2", cache.size() == 2);
        cache.resetStats();
        // Grant a harmless wildcard to viewer; no behavioral change.
        gh.roleManager().grantPermission(ROLE_VIEWER, "neverusedsvc", null, null);
        check("wholesale invalidation fired",
            cache.wholesaleInvalidationCount() == 1);
        check("everything evicted: size 0", cache.size() == 0);
        // restore
        gh.roleManager().revokePermission(ROLE_VIEWER, "neverusedsvc", null, null);

        section("Cache: setStatus invalidates and new status reflected");
        gh.invalidateAllCache();
        cache.resetStats();
        boolean activeBefore =
            gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        check("alice active can read", activeBefore);
        cache.resetStats();
        gh.membershipManager().setStatus(IDENTITY_ALICE, ORG, MembershipStatus.SUSPENDED);
        check("setStatus targeted invalidate",
            cache.targetedInvalidationCount() == 1);
        boolean readSuspended =
            gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        check("suspended alice cannot read after invalidation",
            !readSuspended);
        gh.membershipManager().setStatus(IDENTITY_ALICE, ORG, MembershipStatus.ACTIVE);
        boolean readReactivated =
            gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        check("reactivated alice can read again", readReactivated);

        section("Cache: empty effective set is cached, not re-fetched");
        gh.invalidateAllCache();
        cache.resetStats();
        String unknownId = "smoketestnobody";
        boolean a = gh.hasPermission(unknownId, ORG, SVC, RES_PROJ, ACT_READ);
        boolean b = gh.hasPermission(unknownId, ORG, SVC, RES_DOC,  ACT_READ);
        check("unknown identity always denied", !a && !b);
        check("unknown identity: 1 miss + 1 hit",
            cache.missCount() == 1 && cache.hitCount() == 1);
        check("unknown identity: empty list is cached (size 1)",
            cache.size() == 1);

        section("Cache: manual invalidateCache on Gatedhouse");
        gh.invalidateAllCache();
        cache.resetStats();
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        check("cached: size 1", cache.size() == 1);
        cache.resetStats();
        gh.invalidateCache(IDENTITY_ALICE, ORG);
        check("after invalidateCache: size 0", cache.size() == 0);
        check("after invalidateCache: targeted=1",
            cache.targetedInvalidationCount() == 1);

        section("Cache: manual invalidateAllCache on Gatedhouse");
        gh.invalidateAllCache();
        cache.resetStats();
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        gh.hasPermission(IDENTITY_BOB,   ORG, SVC, RES_PROJ, ACT_READ);
        check("two cached: size 2", cache.size() == 2);
        cache.resetStats();
        gh.invalidateAllCache();
        check("after invalidateAllCache: size 0", cache.size() == 0);
        check("after invalidateAllCache: wholesale=1",
            cache.wholesaleInvalidationCount() == 1);

        section("Cache: kill switch — bypass at runtime");
        gh.invalidateAllCache();
        cache.resetStats();
        check("bypass starts off", !gh.isCacheBypassed());
        // Warm the cache normally
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        check("warm-up: 1 miss + 1 put + size 1",
            cache.missCount() == 1 && cache.putCount() == 1 && cache.size() == 1);
        // Engage bypass
        gh.setCacheBypass(true);
        check("bypass is on", gh.isCacheBypassed());
        cache.resetStats();
        // Reads under bypass: no get(), no put(), size unchanged
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE);
        gh.hasPermission(IDENTITY_BOB,   ORG, SVC, RES_PROJ, ACT_READ);
        check("bypass: zero hits and zero misses",
            cache.hitCount() == 0 && cache.missCount() == 0);
        check("bypass: zero puts (cache not populated)",
            cache.putCount() == 0);
        check("bypass: cache size unchanged from warm-up",
            cache.size() == 1);
        // While bypass is on, writes still invalidate (consistency on resume)
        gh.roleManager().assignToIdentity(IDENTITY_ALICE, ORG, ROLE_DEPLOYER);
        check("bypass: writes still invalidate cache",
            cache.targetedInvalidationCount() == 1);
        gh.roleManager().revokeFromIdentity(IDENTITY_ALICE, ORG, ROLE_DEPLOYER);
        // Disengage bypass and verify caching resumes
        gh.setCacheBypass(false);
        check("bypass is off", !gh.isCacheBypassed());
        cache.resetStats();
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        check("resumed: cold read = 1 miss",
            cache.missCount() == 1 && cache.putCount() == 1);
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE);
        check("resumed: warm read = 1 hit",
            cache.hitCount() == 1);

        section("Cache: result consistency (cached vs fresh)");
        gh.invalidateAllCache();
        boolean fresh = gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        boolean cached = gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        check("cached result matches fresh result", fresh == cached);
        List<EffectivePermission> p1 = gh.getEffectivePermissions(IDENTITY_ALICE, ORG);
        gh.invalidateCache(IDENTITY_ALICE, ORG);
        List<EffectivePermission> p2 = gh.getEffectivePermissions(IDENTITY_ALICE, ORG);
        // Compare as sets — the underlying SELECT DISTINCT has no
        // ORDER BY, so list order between fresh queries is not guaranteed.
        check("getEffectivePermissions is consistent across cache hits & misses",
            new java.util.HashSet<>(p1).equals(new java.util.HashSet<>(p2)));
    }

    private static void runTtlScenario(Database database) {
        section("Cache: TTL expiry");
        InMemoryPermissionCache shortTtl = new InMemoryPermissionCache(Duration.ofMillis(100));
        GatedhouseConfig cfg = GatedhouseConfig.builder()
            .database(database)
            .permissionCache(shortTtl)
            .build();
        try (Gatedhouse gh2 = GatedhouseFactory.create(cfg)) {
            gh2.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
            check("ttl: cold read = 1 miss",
                shortTtl.missCount() == 1 && shortTtl.hitCount() == 0);

            gh2.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE);
            check("ttl: warm read = 1 hit",
                shortTtl.missCount() == 1 && shortTtl.hitCount() == 1);

            try {
                Thread.sleep(150); // > TTL of 100ms
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            gh2.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
            check("ttl: read after expiry = 2 misses (entry re-fetched)",
                shortTtl.missCount() == 2);
        }
    }

    // ---- harness -----------------------------------------------------------

    private static void section(String title) {
        System.out.println();
        System.out.println("=== " + title + " ===");
    }

    private static void check(String description, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("  [PASS] " + description);
        } else {
            failed++;
            System.out.println("  [FAIL] " + description);
        }
    }

    // ---- cleanup -----------------------------------------------------------

    private static void cleanup(Database database) {
        // Order reflects FK relationships: leaves first, then parents whose
        // ON DELETE CASCADE will sweep up everything that references them.
        String[] statements = new String[] {
            "DELETE FROM gatedhouse.role_assignments WHERE org_id = '" + ORG + "'",
            "DELETE FROM gatedhouse.groups WHERE org_id = '" + ORG + "'", // cascades to group_memberships, group_roles
            "DELETE FROM gatedhouse.memberships WHERE org_id = '" + ORG + "'",
            "DELETE FROM gatedhouse.roles WHERE key IN ('"
                + ROLE_VIEWER + "', '" + ROLE_EDITOR + "', '"
                + ROLE_READER + "', '" + ROLE_DEPLOYER + "')", // cascades to role_permissions, role_inherits
            "DELETE FROM gatedhouse.services WHERE service = '" + SVC + "'" // cascades to resources, actions
        };
        try (Connection conn = database.getConnection();
             Statement st = conn.createStatement()) {
            for (String sql : statements) {
                st.execute(sql);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Smoke test cleanup failed", e);
        }
    }
}
