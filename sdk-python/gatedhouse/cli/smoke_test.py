# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""End-to-end smoke test, ported from the Java ``SmokeTest``. Idempotent
and self-cleaning — runs against a real Postgres pointed at by the
supplied conninfo string.

Usage::

    python -m gatedhouse.cli.smoke_test <conninfo>
"""

from __future__ import annotations

import sys
import time
from datetime import timedelta

from psycopg import errors as pg_errors

from gatedhouse import (
    Database,
    EffectivePermission,
    EntityType,
    ExplanationOutcome,
    Gatedhouse,
    GatedhouseConfig,
    GatedhouseDatabaseError,
    GatedhouseFactory,
    GrantSource,
    InMemoryPermissionCache,
    MembershipStatus,
)
from gatedhouse._database import Database as _Db  # type: ignore[no-redef]


# Stable, prefix-namespaced fixtures (no underscores so cleanup is exact).
SVC = "smoketestsvc"
RES_PROJ = "projects"
RES_DOC = "documents"
ACT_READ = "read"
ACT_WRITE = "write"
ACT_DELETE = "delete"
ACT_DEPLOY = "deploy"

ROLE_VIEWER = "smoketestviewer"
ROLE_EDITOR = "smoketesteditor"
ROLE_READER = "smoketestreader"
ROLE_DEPLOYER = "smoketestdeployer"
OWNER_ROLE = "gatedhouse:owner"  # seeded by V001

ORG = "smoketestorg"
IDENTITY_ALICE = "smoketestalice"
IDENTITY_BOB = "smoketestbob"
GROUP_ENG = "smoketestgroup"
IDENTITY_CAROL = "smoketestcarol"
IDENTITY_DAVE = "smoketestdave"
IDENTITY_ERIN = "smoketesterin"
IDENTITY_GHOST = "smoketestghost"


_passed = 0
_failed = 0


def _section(title: str) -> None:
    print()
    print(f"=== {title} ===")


def _check(description: str, condition: bool) -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  [PASS] {description}")
    else:
        _failed += 1
        print(f"  [FAIL] {description}")


# ---- setup ---------------------------------------------------------------


def _setup_catalog(gh: Gatedhouse) -> None:
    _section("Setup: catalog")
    cat = gh.permission_catalog()
    cat.add_service(SVC, "Smoke test service")
    cat.add_resource(SVC, RES_PROJ, "Projects")
    cat.add_resource(SVC, RES_DOC, "Documents")
    cat.add_action(SVC, RES_PROJ, ACT_READ, "Read projects")
    cat.add_action(SVC, RES_PROJ, ACT_WRITE, "Write projects")
    cat.add_action(SVC, RES_PROJ, ACT_DELETE, "Delete projects")
    cat.add_action(SVC, RES_PROJ, ACT_DEPLOY, "Deploy projects")
    cat.add_action(SVC, RES_DOC, ACT_READ, "Read documents")
    _check("catalog.has_service", cat.has_service(SVC))
    _check("catalog.has_resource", cat.has_resource(SVC, RES_PROJ))
    _check("catalog.has_action", cat.has_action(SVC, RES_PROJ, ACT_READ))
    _check("catalog.list_actions(projects) returns 4",
           len(cat.list_actions(SVC, RES_PROJ)) == 4)


def _setup_roles_and_memberships(gh: Gatedhouse) -> None:
    _section("Setup: roles + memberships")
    rm = gh.role_manager()

    # viewer: read projects only
    rm.create_role(ROLE_VIEWER, "Viewer", "Read-only")
    rm.grant_permission(ROLE_VIEWER, SVC, RES_PROJ, ACT_READ)

    # editor: inherits viewer + can write projects
    rm.create_role(ROLE_EDITOR, "Editor", "Read+write")
    rm.add_parent_role(ROLE_EDITOR, ROLE_VIEWER)
    rm.grant_permission(ROLE_EDITOR, SVC, RES_PROJ, ACT_WRITE)

    # reader: wildcard read across all resources of svc
    rm.create_role(ROLE_READER, "Reader", "Read across all resources")
    rm.grant_permission(ROLE_READER, SVC, None, ACT_READ)

    # deployer: deploy projects (assigned to a group, not directly)
    rm.create_role(ROLE_DEPLOYER, "Deployer", "Can deploy")
    rm.grant_permission(ROLE_DEPLOYER, SVC, RES_PROJ, ACT_DEPLOY)

    gh.membership_manager().create_membership(IDENTITY_ALICE, ORG, EntityType.USER)
    gh.membership_manager().create_membership(IDENTITY_BOB, ORG, EntityType.AGENT)

    _check("role_manager.has_role(viewer)", rm.has_role(ROLE_VIEWER))
    _check("role_manager.get_parent_roles(editor) contains viewer",
           ROLE_VIEWER in rm.get_parent_roles(ROLE_EDITOR))
    _check("membership_manager.has_membership(alice)",
           gh.membership_manager().has_membership(IDENTITY_ALICE, ORG))
    _check("membership_manager.get_status(alice) == ACTIVE",
           gh.membership_manager().get_status(IDENTITY_ALICE, ORG)
           == MembershipStatus.ACTIVE)
    _check("membership_manager.get_entity_type(bob) == AGENT",
           gh.membership_manager().get_entity_type(IDENTITY_BOB, ORG)
           == EntityType.AGENT)


# ---- behavioral scenarios ------------------------------------------------


def _run_scenarios(gh: Gatedhouse) -> None:
    _section("Scenario: no roles → no perms")
    _check("alice has no perms before assignment",
           not gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ))

    _section("Scenario: direct role assignment + inheritance")
    gh.role_manager().assign_to_identity(IDENTITY_ALICE, ORG, ROLE_EDITOR)
    _check("alice can write (direct grant on editor)",
           gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE))
    _check("alice can read (inherited from viewer)",
           gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ))
    _check("alice cannot delete (not granted anywhere)",
           not gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_DELETE))
    _check("alice cannot read documents (editor only grants read on projects)",
           not gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_DOC, ACT_READ))

    _section("Scenario: suspension short-circuits to deny")
    gh.membership_manager().set_status(IDENTITY_ALICE, ORG, MembershipStatus.SUSPENDED)
    _check("suspended alice cannot read",
           not gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ))
    gh.membership_manager().set_status(IDENTITY_ALICE, ORG, MembershipStatus.ACTIVE)
    _check("reactivated alice can read again",
           gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ))

    _section("Scenario: pending = deny (per spec)")
    gh.membership_manager().set_status(IDENTITY_ALICE, ORG, MembershipStatus.PENDING)
    _check("pending alice cannot read",
           not gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ))
    gh.membership_manager().set_status(IDENTITY_ALICE, ORG, MembershipStatus.ACTIVE)

    _section("Scenario: wildcard grant (svc, *, read) covers any resource")
    gh.role_manager().assign_to_identity(IDENTITY_BOB, ORG, ROLE_READER)
    _check("bob can read projects via wildcard",
           gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_READ))
    _check("bob can read documents via wildcard",
           gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_DOC, ACT_READ))
    _check("bob still cannot write projects (only read is wildcarded)",
           not gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_WRITE))

    _section("Scenario: permission via group membership")
    gh.group_manager().create_group(GROUP_ENG, ORG, "Engineering", "Smoke test group")
    gh.group_manager().add_identity_to_group(GROUP_ENG, ORG, IDENTITY_BOB)
    gh.role_manager().assign_to_group(GROUP_ENG, ORG, ROLE_DEPLOYER)
    _check("bob can deploy (via engineering group → deployer role)",
           gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_DEPLOY))
    _check("alice cannot deploy (not in group)",
           not gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_DEPLOY))

    _section("Scenario: built-in owner role grants everything")
    gh.role_manager().assign_to_identity(IDENTITY_ALICE, ORG, OWNER_ROLE)
    _check("owner alice can delete (full wildcard)",
           gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_DELETE))
    _check("owner alice can read documents",
           gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_DOC, ACT_READ))
    _check("owner alice can do anything on a fictional resource",
           gh.has_permission(IDENTITY_ALICE, ORG, "anyservice", "anyresource", "anyaction"))

    _section("Scenario: get_effective_permissions")
    bob_perms = gh.get_effective_permissions(IDENTITY_BOB, ORG)
    _check("bob has at least 2 effective permissions (wildcard read + deploy)",
           len(bob_perms) >= 2)
    _check("bob's effective perms contain (svc, None, read) — the wildcard grant",
           any(p.service == SVC and p.resource is None and p.action == ACT_READ
               for p in bob_perms))
    _check("bob's effective perms contain (svc, projects, deploy) — via group",
           any(p.service == SVC and p.resource == RES_PROJ and p.action == ACT_DEPLOY
               for p in bob_perms))

    _section("Scenario: delete identity from group revokes group-derived perms")
    gh.group_manager().remove_identity_from_group(GROUP_ENG, ORG, IDENTITY_BOB)
    _check("bob can no longer deploy (removed from group)",
           not gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_DEPLOY))

    _section("Scenario: revoke role from identity")
    gh.role_manager().revoke_from_identity(IDENTITY_ALICE, ORG, OWNER_ROLE)
    _check("after revoking owner, alice can no longer delete",
           not gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_DELETE))
    _check("but alice can still read (editor → viewer chain still in place)",
           gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ))

    _section("Scenario: missing membership = deny (no row at all)")
    _check("unknown identity has no perms",
           not gh.has_permission("noSuchIdentity", ORG, SVC, RES_PROJ, ACT_READ))
    _check("unknown identity has empty effective perms",
           gh.get_effective_permissions("noSuchIdentity", ORG) == [])


# ---- membership lifecycle (docs/MODEL.md) ---------------------------------


def _run_lifecycle_scenarios(gh: Gatedhouse, database: _Db) -> None:
    members = gh.membership_manager()
    roles = gh.role_manager()

    _section("Lifecycle: removal revokes grants and keeps the row")
    members.create_membership(IDENTITY_CAROL, ORG, EntityType.USER)
    roles.assign_to_identity(IDENTITY_CAROL, ORG, ROLE_EDITOR)
    gh.group_manager().add_identity_to_group(GROUP_ENG, ORG, IDENTITY_CAROL)
    _check("carol can write (direct editor) before removal",
           gh.has_permission(IDENTITY_CAROL, ORG, SVC, RES_PROJ, ACT_WRITE))
    _check("carol can deploy (group deployer) before removal",
           gh.has_permission(IDENTITY_CAROL, ORG, SVC, RES_PROJ, ACT_DEPLOY))
    role_deletes_before = _audit_deletes(database, "role_assignments", IDENTITY_CAROL)
    group_deletes_before = _audit_deletes(database, "group_memberships", IDENTITY_CAROL)
    members.remove_membership(IDENTITY_CAROL, ORG)
    _check("status is REMOVED",
           members.get_status(IDENTITY_CAROL, ORG) is MembershipStatus.REMOVED)
    _check("has_membership is false for a removed membership",
           not members.has_membership(IDENTITY_CAROL, ORG))
    _check("membership row is kept", _membership_rows(database, IDENTITY_CAROL) == 1)
    _check("carol can no longer write",
           not gh.has_permission(IDENTITY_CAROL, ORG, SVC, RES_PROJ, ACT_WRITE))
    _check("carol can no longer deploy",
           not gh.has_permission(IDENTITY_CAROL, ORG, SVC, RES_PROJ, ACT_DEPLOY))
    _check("direct roles revoked", gh.get_roles(IDENTITY_CAROL, ORG) == [])
    _check("group memberships revoked", gh.get_groups(IDENTITY_CAROL, ORG) == [])
    _check("audit log records the role-assignment delete",
           _audit_deletes(database, "role_assignments", IDENTITY_CAROL) == role_deletes_before + 1)
    _check("audit log records the group-membership delete",
           _audit_deletes(database, "group_memberships", IDENTITY_CAROL) == group_deletes_before + 1)

    _section("Lifecycle: REMOVED -> SUSPENDED is rejected")
    rejected = False
    try:
        members.set_status(IDENTITY_CAROL, ORG, MembershipStatus.SUSPENDED)
    except ValueError:
        rejected = True
    _check("set_status(SUSPENDED) on a removed membership raises ValueError", rejected)
    _check("status is still REMOVED after the rejected transition",
           members.get_status(IDENTITY_CAROL, ORG) is MembershipStatus.REMOVED)

    _section("Lifecycle: a grant made after removal is inert, then cleared on rejoin")
    roles.assign_to_identity(IDENTITY_CAROL, ORG, ROLE_EDITOR)
    _check("late grant does not apply while removed",
           not gh.has_permission(IDENTITY_CAROL, ORG, SVC, RES_PROJ, ACT_WRITE))
    members.create_membership(IDENTITY_CAROL, ORG, EntityType.USER)
    _check("create_membership revives the removed membership as ACTIVE",
           members.get_status(IDENTITY_CAROL, ORG) is MembershipStatus.ACTIVE)
    _check("revival reuses the same row", _membership_rows(database, IDENTITY_CAROL) == 1)
    _check("rejoin starts from a clean slate (late grant cleared)",
           gh.get_roles(IDENTITY_CAROL, ORG) == [])
    _check("rejoined carol cannot write",
           not gh.has_permission(IDENTITY_CAROL, ORG, SVC, RES_PROJ, ACT_WRITE))

    _section("Lifecycle: set_status(PENDING) also revives with a clean slate")
    roles.assign_to_identity(IDENTITY_CAROL, ORG, ROLE_EDITOR)
    members.remove_membership(IDENTITY_CAROL, ORG)
    roles.assign_to_identity(IDENTITY_CAROL, ORG, ROLE_EDITOR)  # late grant again
    members.set_status(IDENTITY_CAROL, ORG, MembershipStatus.PENDING)
    _check("status is PENDING",
           members.get_status(IDENTITY_CAROL, ORG) is MembershipStatus.PENDING)
    _check("grants cleared on revival via set_status", gh.get_roles(IDENTITY_CAROL, ORG) == [])
    members.set_status(IDENTITY_CAROL, ORG, MembershipStatus.ACTIVE)
    _check("activating after revival grants nothing old",
           not gh.has_permission(IDENTITY_CAROL, ORG, SVC, RES_PROJ, ACT_WRITE))

    _section("Lifecycle: suspension keeps grants")
    members.create_membership(IDENTITY_DAVE, ORG, EntityType.USER)
    roles.assign_to_identity(IDENTITY_DAVE, ORG, ROLE_VIEWER)
    members.set_status(IDENTITY_DAVE, ORG, MembershipStatus.SUSPENDED)
    _check("suspended dave cannot read",
           not gh.has_permission(IDENTITY_DAVE, ORG, SVC, RES_PROJ, ACT_READ))
    _check("suspended dave keeps his role", ROLE_VIEWER in gh.get_roles(IDENTITY_DAVE, ORG))
    members.set_status(IDENTITY_DAVE, ORG, MembershipStatus.ACTIVE)
    _check("reactivated dave can read again",
           gh.has_permission(IDENTITY_DAVE, ORG, SVC, RES_PROJ, ACT_READ))

    _section("Lifecycle: create_membership on a live membership still fails")
    duplicate_rejected = False
    try:
        members.create_membership(IDENTITY_DAVE, ORG, EntityType.USER)
    except GatedhouseDatabaseError as e:
        duplicate_rejected = isinstance(e.__cause__, pg_errors.UniqueViolation)
    _check("duplicate create_membership raises the unique violation as before (as __cause__)",
           duplicate_rejected)

    _section("Lifecycle: remove_membership with no membership clears stray grants")
    roles.assign_to_identity(IDENTITY_GHOST, ORG, ROLE_VIEWER)
    _check("stray grant exists without a membership",
           ROLE_VIEWER in gh.get_roles(IDENTITY_GHOST, ORG))
    members.remove_membership(IDENTITY_GHOST, ORG)
    _check("stray grant cleared", gh.get_roles(IDENTITY_GHOST, ORG) == [])
    _check("no membership row created", members.get_status(IDENTITY_GHOST, ORG) is None)


# ---- explain (docs/MODEL.md, "Explaining a decision") ---------------------


def _run_explain_scenarios(gh: Gatedhouse) -> None:
    members = gh.membership_manager()
    roles = gh.role_manager()
    members.create_membership(IDENTITY_ERIN, ORG, EntityType.USER)
    roles.assign_to_identity(IDENTITY_ERIN, ORG, ROLE_EDITOR)  # editor -> viewer -> (projects, read)
    roles.assign_to_identity(IDENTITY_ERIN, ORG, ROLE_READER)  # (svc, *, read)
    gh.group_manager().add_identity_to_group(GROUP_ENG, ORG, IDENTITY_ERIN)  # group -> deployer

    _section("Explain: every path, through inheritance and wildcards")
    read = gh.explain_permission(IDENTITY_ERIN, ORG, SVC, RES_PROJ, ACT_READ)
    _check("read is ALLOWED", read.outcome is ExplanationOutcome.ALLOWED and read.allowed)
    _check("membership status reported as ACTIVE",
           read.membership_status is MembershipStatus.ACTIVE)
    _check("two paths grant read", len(read.paths) == 2)
    _check("inherited path: DIRECT [editor, viewer] -> (svc, projects, read)",
           any(p.source is GrantSource.DIRECT
               and p.role_chain == (ROLE_EDITOR, ROLE_VIEWER)
               and p.assigned_role == ROLE_EDITOR and p.granting_role == ROLE_VIEWER
               and p.grant == EffectivePermission(SVC, RES_PROJ, ACT_READ)
               for p in read.paths))
    _check("wildcard path: DIRECT [reader] -> (svc, *, read)",
           any(p.source is GrantSource.DIRECT
               and p.role_chain == (ROLE_READER,)
               and p.grant == EffectivePermission(SVC, None, ACT_READ)
               for p in read.paths))

    deploy = gh.explain_permission(IDENTITY_ERIN, ORG, SVC, RES_PROJ, ACT_DEPLOY)
    _check("deploy is ALLOWED via one path", deploy.allowed and len(deploy.paths) == 1)
    via_group = deploy.paths[0]
    _check("group path names its source and group",
           via_group.source is GrantSource.GROUP and via_group.group_id == GROUP_ENG
           and via_group.role_chain == (ROLE_DEPLOYER,))

    _section("Explain: denials say why")
    delete = gh.explain_permission(IDENTITY_ERIN, ORG, SVC, RES_PROJ, ACT_DELETE)
    _check("delete is NO_MATCHING_GRANT with no paths",
           delete.outcome is ExplanationOutcome.NO_MATCHING_GRANT
           and delete.paths == () and not delete.allowed)

    members.set_status(IDENTITY_ERIN, ORG, MembershipStatus.SUSPENDED)
    suspended = gh.explain_permission(IDENTITY_ERIN, ORG, SVC, RES_PROJ, ACT_READ)
    _check("suspended read is MEMBERSHIP_NOT_ACTIVE",
           suspended.outcome is ExplanationOutcome.MEMBERSHIP_NOT_ACTIVE)
    _check("suspended explanation still shows what reactivation restores",
           len(suspended.paths) == 2)
    _check("explain and has_permission agree for the suspended member",
           suspended.allowed == gh.has_permission(IDENTITY_ERIN, ORG, SVC, RES_PROJ, ACT_READ))
    members.set_status(IDENTITY_ERIN, ORG, MembershipStatus.ACTIVE)

    unknown = gh.explain_permission("noSuchIdentity", ORG, SVC, RES_PROJ, ACT_READ)
    _check("unknown identity is NO_MEMBERSHIP with no status and no paths",
           unknown.outcome is ExplanationOutcome.NO_MEMBERSHIP
           and unknown.membership_status is None and unknown.paths == ())

    roles.assign_to_identity(IDENTITY_GHOST, ORG, ROLE_VIEWER)  # stray grant, no membership
    stray = gh.explain_permission(IDENTITY_GHOST, ORG, SVC, RES_PROJ, ACT_READ)
    _check("stray grant is surfaced: NO_MEMBERSHIP with one path",
           stray.outcome is ExplanationOutcome.NO_MEMBERSHIP and len(stray.paths) == 1)

    _section("Explain: agrees with has_permission everywhere")
    identities = [IDENTITY_ALICE, IDENTITY_BOB, IDENTITY_CAROL, IDENTITY_DAVE,
                  IDENTITY_ERIN, IDENTITY_GHOST, "noSuchIdentity"]
    permissions = [(RES_PROJ, ACT_READ), (RES_PROJ, ACT_WRITE), (RES_PROJ, ACT_DELETE),
                   (RES_PROJ, ACT_DEPLOY), (RES_DOC, ACT_READ)]
    disagreements = sum(
        1
        for identity in identities
        for (res, act) in permissions
        if gh.explain_permission(identity, ORG, SVC, res, act).allowed
        != gh.has_permission(identity, ORG, SVC, res, act)
    )
    _check("explain_permission().allowed == has_permission() for 35 identity/permission pairs",
           disagreements == 0)


def _audit_deletes(database: _Db, table: str, identity_id: str) -> int:
    return _count(
        database,
        "SELECT count(*) FROM gatedhouse.audit_log "
        f"WHERE table_name = 'gatedhouse.{table}' AND op = 'DELETE' "
        "AND old_row->>'identity_id' = %s",
        identity_id,
    )


def _membership_rows(database: _Db, identity_id: str) -> int:
    return _count(
        database,
        "SELECT count(*) FROM gatedhouse.memberships "
        f"WHERE identity_id = %s AND org_id = '{ORG}'",
        identity_id,
    )


def _count(database: _Db, sql: str, param: str) -> int:
    with database.connection() as conn, conn.cursor() as cur:
        cur.execute(sql, (param,))
        return cur.fetchone()[0]



# ---- cache scenarios -----------------------------------------------------


def _run_cache_scenarios(gh: Gatedhouse, cache: InMemoryPermissionCache) -> None:

    _section("Cache: cold read populates")
    gh.invalidate_all_cache()
    cache.reset_stats()
    _check("starting empty",
           cache.size() == 0 and cache.hit_count() == 0 and cache.miss_count() == 0)
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
    _check("after cold read: 1 miss", cache.miss_count() == 1)
    _check("after cold read: 0 hits", cache.hit_count() == 0)
    _check("after cold read: 1 put", cache.put_count() == 1)
    _check("after cold read: size 1", cache.size() == 1)

    _section("Cache: warm read serves from cache (no DB)")
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE)
    _check("warm read: still 1 miss", cache.miss_count() == 1)
    _check("warm read: 1 hit", cache.hit_count() == 1)
    _check("warm read: still size 1", cache.size() == 1)

    _section("Cache: has_permission and get_effective_permissions share cache")
    gh.invalidate_all_cache()
    cache.reset_stats()
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)  # 1 miss
    gh.get_effective_permissions(IDENTITY_ALICE, ORG)                 # hit
    _check("shared cache: 1 miss", cache.miss_count() == 1)
    _check("shared cache: 1 hit", cache.hit_count() == 1)

    _section("Cache: targeted invalidation on assign_to_identity")
    gh.invalidate_all_cache()
    cache.reset_stats()
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
    gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_READ)
    _check("both cached: size 2", cache.size() == 2)
    cache.reset_stats()
    gh.role_manager().assign_to_identity(IDENTITY_ALICE, ORG, ROLE_DEPLOYER)
    _check("targeted invalidate fired",
           cache.targeted_invalidation_count() == 1)
    _check("no wholesale invalidation",
           cache.wholesale_invalidation_count() == 0)
    _check("only alice evicted: size 1", cache.size() == 1)
    cache.reset_stats()
    gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_READ)
    _check("bob still cached: hit, no miss",
           cache.hit_count() == 1 and cache.miss_count() == 0)
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
    _check("alice re-fetched: 1 miss", cache.miss_count() == 1)
    gh.role_manager().revoke_from_identity(IDENTITY_ALICE, ORG, ROLE_DEPLOYER)

    _section("Cache: wholesale invalidation on grant_permission")
    # The granted service must exist in the catalog (FK on role_permissions).
    gh.permission_catalog().add_service("smoketestneversvc", "Never-used service")
    gh.invalidate_all_cache()
    cache.reset_stats()
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
    gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_READ)
    _check("both cached: size 2", cache.size() == 2)
    cache.reset_stats()
    gh.role_manager().grant_permission(ROLE_VIEWER, "smoketestneversvc", None, None)
    _check("wholesale invalidation fired",
           cache.wholesale_invalidation_count() == 1)
    _check("everything evicted: size 0", cache.size() == 0)
    gh.role_manager().revoke_permission(ROLE_VIEWER, "smoketestneversvc", None, None)
    gh.permission_catalog().remove_service("smoketestneversvc")

    _section("Cache: set_status invalidates and new status reflected")
    gh.invalidate_all_cache()
    cache.reset_stats()
    active_before = gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
    _check("alice active can read", active_before)
    cache.reset_stats()
    gh.membership_manager().set_status(IDENTITY_ALICE, ORG, MembershipStatus.SUSPENDED)
    _check("set_status targeted invalidate",
           cache.targeted_invalidation_count() == 1)
    read_suspended = gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
    _check("suspended alice cannot read after invalidation", not read_suspended)
    gh.membership_manager().set_status(IDENTITY_ALICE, ORG, MembershipStatus.ACTIVE)
    read_reactivated = gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
    _check("reactivated alice can read again", read_reactivated)

    _section("Cache: empty effective set is cached, not re-fetched")
    gh.invalidate_all_cache()
    cache.reset_stats()
    unknown_id = "smoketestnobody"
    a = gh.has_permission(unknown_id, ORG, SVC, RES_PROJ, ACT_READ)
    b = gh.has_permission(unknown_id, ORG, SVC, RES_DOC, ACT_READ)
    _check("unknown identity always denied", not a and not b)
    _check("unknown identity: 1 miss + 1 hit",
           cache.miss_count() == 1 and cache.hit_count() == 1)
    _check("unknown identity: empty list is cached (size 1)",
           cache.size() == 1)

    _section("Cache: manual invalidate_cache on Gatedhouse")
    gh.invalidate_all_cache()
    cache.reset_stats()
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
    _check("cached: size 1", cache.size() == 1)
    cache.reset_stats()
    gh.invalidate_cache(IDENTITY_ALICE, ORG)
    _check("after invalidate_cache: size 0", cache.size() == 0)
    _check("after invalidate_cache: targeted=1",
           cache.targeted_invalidation_count() == 1)

    _section("Cache: manual invalidate_all_cache on Gatedhouse")
    gh.invalidate_all_cache()
    cache.reset_stats()
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
    gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_READ)
    _check("two cached: size 2", cache.size() == 2)
    cache.reset_stats()
    gh.invalidate_all_cache()
    _check("after invalidate_all_cache: size 0", cache.size() == 0)
    _check("after invalidate_all_cache: wholesale=1",
           cache.wholesale_invalidation_count() == 1)

    _section("Cache: kill switch — disable at runtime")
    gh.invalidate_all_cache()
    cache.reset_stats()
    _check("configured cache starts enabled", gh.is_cache_enabled())
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
    _check("warm-up: 1 miss + 1 put + size 1",
           cache.miss_count() == 1 and cache.put_count() == 1 and cache.size() == 1)
    gh.set_cache_enabled(False)
    _check("cache is disabled", not gh.is_cache_enabled())
    cache.reset_stats()
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE)
    gh.has_permission(IDENTITY_BOB, ORG, SVC, RES_PROJ, ACT_READ)
    _check("disabled: zero hits and zero misses",
           cache.hit_count() == 0 and cache.miss_count() == 0)
    _check("disabled: zero puts (cache not populated)", cache.put_count() == 0)
    _check("disabled: cache size unchanged from warm-up", cache.size() == 1)
    gh.role_manager().assign_to_identity(IDENTITY_ALICE, ORG, ROLE_DEPLOYER)
    _check("disabled: writes still invalidate cache",
           cache.targeted_invalidation_count() == 1)
    gh.role_manager().revoke_from_identity(IDENTITY_ALICE, ORG, ROLE_DEPLOYER)
    gh.set_cache_enabled(True)
    _check("cache is enabled again", gh.is_cache_enabled())
    cache.reset_stats()
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
    _check("resumed: cold read = 1 miss",
           cache.miss_count() == 1 and cache.put_count() == 1)
    gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE)
    _check("resumed: warm read = 1 hit", cache.hit_count() == 1)

    _section("Cache: result consistency (cached vs fresh)")
    gh.invalidate_all_cache()
    fresh = gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
    cached = gh.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
    _check("cached result matches fresh result", fresh == cached)
    p1 = gh.get_effective_permissions(IDENTITY_ALICE, ORG)
    gh.invalidate_cache(IDENTITY_ALICE, ORG)
    p2 = gh.get_effective_permissions(IDENTITY_ALICE, ORG)
    _check(
        "get_effective_permissions is consistent across cache hits & misses",
        set(p1) == set(p2),
    )


def _run_ttl_scenario(database: _Db) -> None:
    _section("Cache: TTL expiry")
    short_ttl = InMemoryPermissionCache(ttl=timedelta(milliseconds=100))
    cfg = GatedhouseConfig(database=database, permission_cache=short_ttl)
    with GatedhouseFactory.create(cfg) as gh2:
        gh2.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
        _check("ttl: cold read = 1 miss",
               short_ttl.miss_count() == 1 and short_ttl.hit_count() == 0)

        gh2.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_WRITE)
        _check("ttl: warm read = 1 hit",
               short_ttl.miss_count() == 1 and short_ttl.hit_count() == 1)

        time.sleep(0.150)  # > TTL of 100ms

        gh2.has_permission(IDENTITY_ALICE, ORG, SVC, RES_PROJ, ACT_READ)
        _check("ttl: read after expiry = 2 misses (entry re-fetched)",
               short_ttl.miss_count() == 2)


# ---- cleanup -------------------------------------------------------------


def _cleanup(database: _Db) -> None:
    statements = [
        f"DELETE FROM gatedhouse.role_assignments WHERE org_id = '{ORG}'",
        # cascades to group_memberships, group_roles
        f"DELETE FROM gatedhouse.groups WHERE org_id = '{ORG}'",
        f"DELETE FROM gatedhouse.memberships WHERE org_id = '{ORG}'",
        # cascades to role_permissions, role_inherits
        "DELETE FROM gatedhouse.roles WHERE key IN ("
        f"'{ROLE_VIEWER}', '{ROLE_EDITOR}', "
        f"'{ROLE_READER}', '{ROLE_DEPLOYER}')",
        # cascades to resources, actions
        f"DELETE FROM gatedhouse.services WHERE service IN "
        f"('{SVC}', 'smoketestneversvc')",
    ]
    with database.connection() as conn, conn.cursor() as cur:
        for sql in statements:
            cur.execute(sql)


# ---- main ----------------------------------------------------------------


USAGE = (
    "Usage: python -m gatedhouse.cli.smoke_test <conninfo>\n"
    "\n"
    "Example:\n"
    "  python -m gatedhouse.cli.smoke_test "
    "'postgresql://user:pass@localhost:5432/mydb'\n"
)


def main(argv: list[str] | None = None) -> int:
    global _passed, _failed
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        sys.stderr.write(USAGE)
        return 2

    conninfo = args[0]
    # URL mode: Gatedhouse runs its own (psycopg_pool) pool, closed when the
    # smoke test ends. Needs the gatedhouse[pool] extra.
    with Database.from_uri(conninfo) as database:
        return _run(database)


def _run(database: Database) -> int:
    cache = InMemoryPermissionCache()
    config = GatedhouseConfig(database=database, permission_cache=cache)

    with GatedhouseFactory.create(config) as gh:
        try:
            _cleanup(database)
            _setup_catalog(gh)
            _setup_roles_and_memberships(gh)
            _run_scenarios(gh)
            _run_lifecycle_scenarios(gh, database)
            _run_explain_scenarios(gh)
            _run_cache_scenarios(gh, cache)
            _run_ttl_scenario(database)
        finally:
            try:
                _cleanup(database)
            except Exception as e:
                sys.stderr.write(f"Cleanup failed: {e}\n")

    print(f"\n{_passed} passed, {_failed} failed")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
