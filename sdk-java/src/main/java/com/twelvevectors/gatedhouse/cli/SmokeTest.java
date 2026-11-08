// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse.cli;

import com.twelvevectors.gatedhouse.Database;
import com.twelvevectors.gatedhouse.EffectivePermission;
import com.twelvevectors.gatedhouse.EntityType;
import com.twelvevectors.gatedhouse.Gatedhouse;
import com.twelvevectors.gatedhouse.GatedhouseConfig;
import com.twelvevectors.gatedhouse.GatedhouseDatabaseException;
import com.twelvevectors.gatedhouse.GatedhouseFactory;
import com.twelvevectors.gatedhouse.GrantPath;
import com.twelvevectors.gatedhouse.InMemoryPermissionCache;
import com.twelvevectors.gatedhouse.MembershipStatus;
import com.twelvevectors.gatedhouse.PermissionExplanation;
import com.twelvevectors.gatedhouse.PermissionExplanation.Outcome;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
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
    private static final String IDENTITY_CAROL = "smoketestcarol";
    private static final String IDENTITY_DAVE  = "smoketestdave";
    private static final String IDENTITY_ERIN  = "smoketesterin";
    private static final String IDENTITY_GHOST = "smoketestghost";

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
                runLifecycleScenarios(gh, database);
                runExplainScenarios(gh);
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

    // ---- membership lifecycle (docs/MODEL.md) -------------------------------

    private static void runLifecycleScenarios(Gatedhouse gh, Database database) {
        var members = gh.membershipManager();
        var roles = gh.roleManager();

        section("Lifecycle: removal revokes grants and keeps the row");
        members.createMembership(IDENTITY_CAROL, ORG, EntityType.USER);
        roles.assignToIdentity(IDENTITY_CAROL, ORG, ROLE_EDITOR);
        gh.groupManager().addIdentityToGroup(GROUP_ENG, ORG, IDENTITY_CAROL);
        check("carol can write (direct editor) before removal",
            gh.hasPermission(IDENTITY_CAROL, ORG, SVC, RES_PROJ, ACT_WRITE));
        check("carol can deploy (group deployer) before removal",
            gh.hasPermission(IDENTITY_CAROL, ORG, SVC, RES_PROJ, ACT_DEPLOY));
        int roleDeletesBefore  = auditDeletes(database, "role_assignments",  IDENTITY_CAROL);
        int groupDeletesBefore = auditDeletes(database, "group_memberships", IDENTITY_CAROL);
        members.removeMembership(IDENTITY_CAROL, ORG);
        check("status is REMOVED",
            members.getStatus(IDENTITY_CAROL, ORG).orElseThrow() == MembershipStatus.REMOVED);
        check("hasMembership is false for a removed membership",
            !members.hasMembership(IDENTITY_CAROL, ORG));
        check("membership row is kept",
            membershipRows(database, IDENTITY_CAROL) == 1);
        check("carol can no longer write", !gh.hasPermission(IDENTITY_CAROL, ORG, SVC, RES_PROJ, ACT_WRITE));
        check("carol can no longer deploy", !gh.hasPermission(IDENTITY_CAROL, ORG, SVC, RES_PROJ, ACT_DEPLOY));
        check("direct roles revoked", gh.getRoles(IDENTITY_CAROL, ORG).isEmpty());
        check("group memberships revoked", gh.getGroups(IDENTITY_CAROL, ORG).isEmpty());
        check("audit log records the role-assignment delete",
            auditDeletes(database, "role_assignments", IDENTITY_CAROL) == roleDeletesBefore + 1);
        check("audit log records the group-membership delete",
            auditDeletes(database, "group_memberships", IDENTITY_CAROL) == groupDeletesBefore + 1);

        section("Lifecycle: REMOVED -> SUSPENDED is rejected");
        boolean rejected = false;
        try {
            members.setStatus(IDENTITY_CAROL, ORG, MembershipStatus.SUSPENDED);
        } catch (IllegalStateException e) {
            rejected = true;
        }
        check("setStatus(SUSPENDED) on a removed membership throws IllegalStateException", rejected);
        check("status is still REMOVED after the rejected transition",
            members.getStatus(IDENTITY_CAROL, ORG).orElseThrow() == MembershipStatus.REMOVED);

        section("Lifecycle: a grant made after removal is inert, then cleared on rejoin");
        roles.assignToIdentity(IDENTITY_CAROL, ORG, ROLE_EDITOR);
        check("late grant does not apply while removed",
            !gh.hasPermission(IDENTITY_CAROL, ORG, SVC, RES_PROJ, ACT_WRITE));
        members.createMembership(IDENTITY_CAROL, ORG, EntityType.USER);
        check("createMembership revives the removed membership as ACTIVE",
            members.getStatus(IDENTITY_CAROL, ORG).orElseThrow() == MembershipStatus.ACTIVE);
        check("revival reuses the same row", membershipRows(database, IDENTITY_CAROL) == 1);
        check("rejoin starts from a clean slate (late grant cleared)",
            gh.getRoles(IDENTITY_CAROL, ORG).isEmpty());
        check("rejoined carol cannot write",
            !gh.hasPermission(IDENTITY_CAROL, ORG, SVC, RES_PROJ, ACT_WRITE));

        section("Lifecycle: setStatus(PENDING) also revives with a clean slate");
        roles.assignToIdentity(IDENTITY_CAROL, ORG, ROLE_EDITOR);
        members.removeMembership(IDENTITY_CAROL, ORG);
        roles.assignToIdentity(IDENTITY_CAROL, ORG, ROLE_EDITOR);  // late grant again
        members.setStatus(IDENTITY_CAROL, ORG, MembershipStatus.PENDING);
        check("status is PENDING",
            members.getStatus(IDENTITY_CAROL, ORG).orElseThrow() == MembershipStatus.PENDING);
        check("grants cleared on revival via setStatus", gh.getRoles(IDENTITY_CAROL, ORG).isEmpty());
        members.setStatus(IDENTITY_CAROL, ORG, MembershipStatus.ACTIVE);
        check("activating after revival grants nothing old",
            !gh.hasPermission(IDENTITY_CAROL, ORG, SVC, RES_PROJ, ACT_WRITE));

        section("Lifecycle: suspension keeps grants");
        members.createMembership(IDENTITY_DAVE, ORG, EntityType.USER);
        roles.assignToIdentity(IDENTITY_DAVE, ORG, ROLE_VIEWER);
        members.setStatus(IDENTITY_DAVE, ORG, MembershipStatus.SUSPENDED);
        check("suspended dave cannot read", !gh.hasPermission(IDENTITY_DAVE, ORG, SVC, RES_PROJ, ACT_READ));
        check("suspended dave keeps his role", gh.getRoles(IDENTITY_DAVE, ORG).contains(ROLE_VIEWER));
        members.setStatus(IDENTITY_DAVE, ORG, MembershipStatus.ACTIVE);
        check("reactivated dave can read again", gh.hasPermission(IDENTITY_DAVE, ORG, SVC, RES_PROJ, ACT_READ));

        section("Lifecycle: createMembership on a live membership still fails");
        boolean duplicateRejected = false;
        try {
            members.createMembership(IDENTITY_DAVE, ORG, EntityType.USER);
        } catch (GatedhouseDatabaseException e) {
            duplicateRejected = e.getCause() instanceof SQLException sql && "23505".equals(sql.getSQLState());
        }
        check("duplicate createMembership raises the unique violation as before", duplicateRejected);

        section("Lifecycle: removeMembership with no membership clears stray grants");
        roles.assignToIdentity(IDENTITY_GHOST, ORG, ROLE_VIEWER);
        check("stray grant exists without a membership", gh.getRoles(IDENTITY_GHOST, ORG).contains(ROLE_VIEWER));
        members.removeMembership(IDENTITY_GHOST, ORG);
        check("stray grant cleared", gh.getRoles(IDENTITY_GHOST, ORG).isEmpty());
        check("no membership row created", members.getStatus(IDENTITY_GHOST, ORG).isEmpty());
    }

    // ---- explain (docs/MODEL.md, "Explaining a decision") ------------------

    private static void runExplainScenarios(Gatedhouse gh) {
        var members = gh.membershipManager();
        var roles = gh.roleManager();
        members.createMembership(IDENTITY_ERIN, ORG, EntityType.USER);
        roles.assignToIdentity(IDENTITY_ERIN, ORG, ROLE_EDITOR);   // editor -> viewer -> (projects, read)
        roles.assignToIdentity(IDENTITY_ERIN, ORG, ROLE_READER);   // (svc, *, read)
        gh.groupManager().addIdentityToGroup(GROUP_ENG, ORG, IDENTITY_ERIN);  // group -> deployer

        section("Explain: every path, through inheritance and wildcards");
        PermissionExplanation read = gh.explainPermission(IDENTITY_ERIN, ORG, SVC, RES_PROJ, ACT_READ);
        check("read is ALLOWED", read.outcome() == Outcome.ALLOWED && read.allowed());
        check("membership status reported as ACTIVE", read.membershipStatus() == MembershipStatus.ACTIVE);
        check("two paths grant read", read.paths().size() == 2);
        check("inherited path: DIRECT [editor, viewer] -> (svc, projects, read)",
            read.paths().stream().anyMatch(p ->
                p.source() == GrantPath.Source.DIRECT
                && p.roleChain().equals(List.of(ROLE_EDITOR, ROLE_VIEWER))
                && p.assignedRole().equals(ROLE_EDITOR) && p.grantingRole().equals(ROLE_VIEWER)
                && p.grant().equals(new EffectivePermission(SVC, RES_PROJ, ACT_READ))));
        check("wildcard path: DIRECT [reader] -> (svc, *, read)",
            read.paths().stream().anyMatch(p ->
                p.source() == GrantPath.Source.DIRECT
                && p.roleChain().equals(List.of(ROLE_READER))
                && p.grant().equals(new EffectivePermission(SVC, null, ACT_READ))));

        PermissionExplanation deploy = gh.explainPermission(IDENTITY_ERIN, ORG, SVC, RES_PROJ, ACT_DEPLOY);
        check("deploy is ALLOWED via one path", deploy.allowed() && deploy.paths().size() == 1);
        GrantPath viaGroup = deploy.paths().get(0);
        check("group path names its source and group",
            viaGroup.source() == GrantPath.Source.GROUP && GROUP_ENG.equals(viaGroup.groupId())
            && viaGroup.roleChain().equals(List.of(ROLE_DEPLOYER)));

        section("Explain: denials say why");
        PermissionExplanation delete = gh.explainPermission(IDENTITY_ERIN, ORG, SVC, RES_PROJ, ACT_DELETE);
        check("delete is NO_MATCHING_GRANT with no paths",
            delete.outcome() == Outcome.NO_MATCHING_GRANT && delete.paths().isEmpty() && !delete.allowed());

        members.setStatus(IDENTITY_ERIN, ORG, MembershipStatus.SUSPENDED);
        PermissionExplanation suspended = gh.explainPermission(IDENTITY_ERIN, ORG, SVC, RES_PROJ, ACT_READ);
        check("suspended read is MEMBERSHIP_NOT_ACTIVE", suspended.outcome() == Outcome.MEMBERSHIP_NOT_ACTIVE);
        check("suspended explanation still shows what reactivation restores", suspended.paths().size() == 2);
        check("explain and hasPermission agree for the suspended member",
            suspended.allowed() == gh.hasPermission(IDENTITY_ERIN, ORG, SVC, RES_PROJ, ACT_READ));
        members.setStatus(IDENTITY_ERIN, ORG, MembershipStatus.ACTIVE);

        PermissionExplanation unknown = gh.explainPermission("noSuchIdentity", ORG, SVC, RES_PROJ, ACT_READ);
        check("unknown identity is NO_MEMBERSHIP with no status and no paths",
            unknown.outcome() == Outcome.NO_MEMBERSHIP && unknown.membershipStatus() == null
            && unknown.paths().isEmpty());

        roles.assignToIdentity(IDENTITY_GHOST, ORG, ROLE_VIEWER);  // stray grant, no membership
        PermissionExplanation stray = gh.explainPermission(IDENTITY_GHOST, ORG, SVC, RES_PROJ, ACT_READ);
        check("stray grant is surfaced: NO_MEMBERSHIP with one path",
            stray.outcome() == Outcome.NO_MEMBERSHIP && stray.paths().size() == 1);

        section("Explain: agrees with hasPermission everywhere");
        int disagreements = 0;
        String[] identities = {IDENTITY_ALICE, IDENTITY_BOB, IDENTITY_CAROL, IDENTITY_DAVE,
                               IDENTITY_ERIN, IDENTITY_GHOST, "noSuchIdentity"};
        String[][] permissions = {{RES_PROJ, ACT_READ}, {RES_PROJ, ACT_WRITE}, {RES_PROJ, ACT_DELETE},
                                  {RES_PROJ, ACT_DEPLOY}, {RES_DOC, ACT_READ}};
        for (String identity : identities) {
            for (String[] p : permissions) {
                if (gh.explainPermission(identity, ORG, SVC, p[0], p[1]).allowed()
                        != gh.hasPermission(identity, ORG, SVC, p[0], p[1])) {
                    disagreements++;
                }
            }
        }
        check("explain().allowed() == hasPermission() for 35 identity/permission pairs", disagreements == 0);
    }

    private static int auditDeletes(Database database, String table, String identityId) {
        return count(database,
            "SELECT count(*) FROM gatedhouse.audit_log "
            + "WHERE table_name = 'gatedhouse." + table + "' AND op = 'DELETE' "
            + "AND old_row->>'identity_id' = ?", identityId);
    }

    private static int membershipRows(Database database, String identityId) {
        return count(database,
            "SELECT count(*) FROM gatedhouse.memberships WHERE identity_id = ? AND org_id = '" + ORG + "'",
            identityId);
    }

    private static int count(Database database, String sql, String param) {
        try (Connection conn = database.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, param);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Smoke test query failed: " + sql, e);
        }
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
        // Grant a harmless wildcard to viewer; no behavioral change. The
        // granted service must exist in the catalog (FK on role_permissions).
        gh.permissionCatalog().addService("smoketestneversvc", "Never-used service");
        gh.roleManager().grantPermission(ROLE_VIEWER, "smoketestneversvc", null, null);
        check("wholesale invalidation fired",
            cache.wholesaleInvalidationCount() == 1);
        check("everything evicted: size 0", cache.size() == 0);
        // restore
        gh.roleManager().revokePermission(ROLE_VIEWER, "smoketestneversvc", null, null);
        gh.permissionCatalog().removeService("smoketestneversvc");

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

        section("Cache: kill switch — disable at runtime");
        gh.invalidateAllCache();
        cache.resetStats();
        check("configured cache starts enabled", gh.isCacheEnabled());
        // Warm the cache normally
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        check("warm-up: 1 miss + 1 put + size 1",
            cache.missCount() == 1 && cache.putCount() == 1 && cache.size() == 1);
        // Disable caching at runtime
        gh.setCacheEnabled(false);
        check("cache is disabled", !gh.isCacheEnabled());
        cache.resetStats();
        // Reads while disabled: no get(), no put(), size unchanged
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ);
        gh.hasPermission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE);
        gh.hasPermission(IDENTITY_BOB,   ORG, SVC, RES_PROJ, ACT_READ);
        check("disabled: zero hits and zero misses",
            cache.hitCount() == 0 && cache.missCount() == 0);
        check("disabled: zero puts (cache not populated)",
            cache.putCount() == 0);
        check("disabled: cache size unchanged from warm-up",
            cache.size() == 1);
        // While disabled, writes still invalidate (consistency on re-enable)
        gh.roleManager().assignToIdentity(IDENTITY_ALICE, ORG, ROLE_DEPLOYER);
        check("disabled: writes still invalidate cache",
            cache.targetedInvalidationCount() == 1);
        gh.roleManager().revokeFromIdentity(IDENTITY_ALICE, ORG, ROLE_DEPLOYER);
        // Re-enable and verify caching resumes
        gh.setCacheEnabled(true);
        check("cache is enabled again", gh.isCacheEnabled());
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
            "DELETE FROM gatedhouse.services WHERE service IN ('" + SVC + "', 'smoketestneversvc')" // cascades to resources, actions
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
