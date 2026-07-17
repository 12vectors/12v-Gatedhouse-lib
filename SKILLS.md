# Gatedhouse — Implementation Guide

Embedded authorization library. Provides RBAC with role inheritance, group-based assignments, multi-tenancy, JWT verification against an OIDC-style issuer (Sphinx), permission caching, and a generic database-level audit log.

> Three SDKs are maintained in this repo from a single Postgres schema (V001 is byte-identical across all three). The **Java SDK is the reference implementation**; **Python** and **Rust** are faithful ports with the same architecture, the same fixture-named smoke test, and the same advisory-lock key so any combination of them can migrate or read the same database.
>
> **One caveat to know up front:** each SDK's default permission cache is **process-local**. Two apps using different (or the same) SDK against one database hold independent cache copies and can briefly disagree after a write, until the TTL expires. See [Permission Cache → Process-local by default](#process-local-by-default--caveat-for-multi-app-deployments) for the failure mode and how to fix it with a shared cache.
>
> | SDK | Path | Class names | Method style |
> |---|---|---|---|
> | Java | [`sdk-java/`](sdk-java/) | PascalCase | `camelCase` |
> | Python | [`sdk-python/`](sdk-python/) | PascalCase | `snake_case` (PEP 8) |
> | Rust | [`sdk-rust/`](sdk-rust/) | PascalCase | `snake_case`; methods return `Result<T, GatedhouseError>` |
>
> Code examples in this guide use Java as the canonical form unless otherwise noted. The [Language Equivalents](#language-equivalents) section maps every public method to its Python and Rust counterpart.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Language Equivalents](#language-equivalents)
3. [Core Concepts](#core-concepts)
4. [Database Schema](#database-schema)
5. [Public API Surface](#public-api-surface)
6. [Step-by-Step Setup](#step-by-step-setup)
7. [Authorization Decision Flow](#authorization-decision-flow)
8. [Authentication via Sphinx (JWT verification)](#authentication-via-sphinx-jwt-verification)
9. [Pluggable Group Source](#pluggable-group-source)
10. [Permission Cache](#permission-cache)
11. [Audit Log](#audit-log)
12. [Use Cases](#use-cases)
13. [Best Practices](#best-practices)
14. [Troubleshooting](#troubleshooting)

---

## Quick Start

### 1. Add the dependency

**Java** (`pom.xml`) — Java 17+, brings `pgjdbc`, `nimbus-jose-jwt`, `cache-api` (~7 MB total):

```xml
<dependency>
  <groupId>com.twelvevectors</groupId>
  <artifactId>gatedhouse</artifactId>
  <version>0.2.0</version>
</dependency>
```

**Python** (`pyproject.toml` / `pip`) — Python 3.10+, brings `psycopg`, `PyJWT[crypto]`:

```bash
pip install gatedhouse        # or: pip install -e ./sdk-python
```

**Rust** (`Cargo.toml`) — Rust 1.74+, brings `postgres`, `jsonwebtoken`, `ureq`, `uuid`, `serde`:

```toml
[dependencies]
gatedhouse = { path = "./sdk-rust" }
```

### 2. Run the migration once per database

The library does **not** auto-create its schema at application startup. The bundled migration tool — same V001 SQL across all three SDKs, all using the same Postgres advisory-lock key — creates the `gatedhouse` schema, all tables, the audit trigger function, and seeds the built-in `gatedhouse:owner` role. Re-running it is a no-op (versions tracked in `gatedhouse.schema_versions`).

```bash
# Java
java -cp gatedhouse-0.2.0.jar:postgresql-42.7.4.jar \
     com.twelvevectors.gatedhouse.cli.Migrate \
     jdbc:postgresql://localhost:5432/yourdb yourdbuser yourpassword

# Python
python -m gatedhouse.cli.migrate "postgresql://yourdbuser:yourpassword@localhost:5432/yourdb"

# Rust
cargo run --bin gatedhouse-migrate -- \
     "host=localhost user=yourdbuser password=yourpassword dbname=yourdb"
```

### 3. Initialize and use

The factory verifies the schema is at the expected version on creation. If it isn't, the SDK throws/returns a `SchemaNotInitialized*` or `SchemaOutOfDate*` error with the exact migration command in the message.

#### Java

```java
import com.twelvevectors.gatedhouse.*;

Database database = Database.fromUrl(
    "jdbc:postgresql://localhost:5432/yourdb", "appuser", "secret");
GatedhouseConfig config = GatedhouseConfig.builder().database(database).build();

try (Gatedhouse gh = GatedhouseFactory.create(config)) {
    gh.permissionCatalog().addService("workspace", "Workspace service");
    gh.permissionCatalog().addResource("workspace", "projects", "Project resource");
    gh.permissionCatalog().addAction("workspace", "projects", "read",  "Read projects");
    gh.permissionCatalog().addAction("workspace", "projects", "write", "Write projects");

    gh.roleManager().createRole("editor", "Editor", "Read and write projects");
    gh.roleManager().grantPermission("editor", "workspace", "projects", "read");
    gh.roleManager().grantPermission("editor", "workspace", "projects", "write");

    gh.membershipManager().createMembership("alice", "acme", EntityType.USER);
    gh.roleManager().assignToIdentity("alice", "acme", "editor");

    boolean ok = gh.hasPermission("alice", "acme", "workspace", "projects", "write");
}
```

#### Python

```python
from gatedhouse import Database, EntityType, GatedhouseConfig, GatedhouseFactory

database = Database.from_uri(
    "postgresql://appuser:secret@localhost:5432/yourdb")
config = GatedhouseConfig(database=database)

with GatedhouseFactory.create(config) as gh:
    gh.permission_catalog().add_service("workspace", "Workspace service")
    gh.permission_catalog().add_resource("workspace", "projects", "Project resource")
    gh.permission_catalog().add_action("workspace", "projects", "read",  "Read projects")
    gh.permission_catalog().add_action("workspace", "projects", "write", "Write projects")

    gh.role_manager().create_role("editor", "Editor", "Read and write projects")
    gh.role_manager().grant_permission("editor", "workspace", "projects", "read")
    gh.role_manager().grant_permission("editor", "workspace", "projects", "write")

    gh.membership_manager().create_membership("alice", "acme", EntityType.USER)
    gh.role_manager().assign_to_identity("alice", "acme", "editor")

    ok = gh.has_permission("alice", "acme", "workspace", "projects", "write")
```

#### Rust

```rust
use std::sync::Arc;
use gatedhouse::{
    ConninfoDatabase, Database, EntityType, GatedhouseConfig, GatedhouseFactory,
};

let database: Arc<dyn Database> = Arc::new(ConninfoDatabase::new(
    "host=localhost user=appuser password=secret dbname=yourdb",
));
let config = GatedhouseConfig::builder(database).build();
let gh = GatedhouseFactory::create(config)?;

gh.permission_catalog().add_service("workspace", Some("Workspace service"))?;
gh.permission_catalog().add_resource("workspace", "projects", Some("Project resource"))?;
gh.permission_catalog().add_action("workspace", "projects", "read",  Some("Read projects"))?;
gh.permission_catalog().add_action("workspace", "projects", "write", Some("Write projects"))?;

gh.role_manager().create_role("editor", "Editor", Some("Read and write projects"))?;
gh.role_manager().grant_permission(
    "editor", Some("workspace"), Some("projects"), Some("read"))?;
gh.role_manager().grant_permission(
    "editor", Some("workspace"), Some("projects"), Some("write"))?;

gh.membership_manager().create_membership("alice", "acme", EntityType::User)?;
gh.role_manager().assign_to_identity("alice", "acme", "editor")?;

let ok = gh.has_permission("alice", "acme", "workspace", "projects", "write")?;
```

---

## Language Equivalents

The three SDKs share **the same architecture, class names, and operation semantics**. Method-naming style follows each language's idiom (Java `camelCase` vs. Python/Rust `snake_case`), and Rust returns `Result<T, GatedhouseError>` everywhere instead of throwing.

### Construction & lifecycle

| Concept | Java | Python | Rust |
|---|---|---|---|
| Build a `Database` | `Database.fromUrl(jdbcUrl, u, p)` | `Database.from_uri(conninfo)` | `Arc::new(ConninfoDatabase::new(conninfo))` |
| Build the config | `GatedhouseConfig.builder().database(db).build()` | `GatedhouseConfig(database=db)` | `GatedhouseConfig::builder(db).build()` |
| Create | `GatedhouseFactory.create(config)` | `GatedhouseFactory.create(config)` | `GatedhouseFactory::create(config)?` |
| Use with auto-cleanup | `try (Gatedhouse gh = ...)` | `with ... as gh:` | RAII via `Drop` (no syntax needed) |

### Permission catalog (same operations, language-styled names)

| Java | Python | Rust |
|---|---|---|
| `gh.permissionCatalog().addService(svc, desc)` | `gh.permission_catalog().add_service(svc, desc)` | `gh.permission_catalog().add_service(svc, Some(desc))?` |
| `.addResource(svc, res, desc)` | `.add_resource(svc, res, desc)` | `.add_resource(svc, res, Some(desc))?` |
| `.addAction(svc, res, act, desc)` | `.add_action(svc, res, act, desc)` | `.add_action(svc, res, act, Some(desc))?` |
| `.removeService(svc)` / `removeResource` / `removeAction` | `.remove_service(svc)` / … | `.remove_service(svc)?` / … |
| `.hasService(svc)` / `hasResource` / `hasAction` | `.has_service(svc)` / … | `.has_service(svc)?` / … |
| `.listServices()` / `listResources` / `listActions` | `.list_services()` / … | `.list_services()?` / … |

### Roles + grants + inheritance + assignments

| Java | Python | Rust |
|---|---|---|
| `gh.roleManager().createRole(key, name, desc)` | `gh.role_manager().create_role(key, name, desc)` | `gh.role_manager().create_role(key, name, Some(desc))?` |
| `.deleteRole(key)` | `.delete_role(key)` | `.delete_role(key)?` |
| `.grantPermission(role, svc, res, act)` (nulls = wildcard) | `.grant_permission(role, svc, res, act)` (None = wildcard) | `.grant_permission(role, Some(svc), Some(res), Some(act))?` (None = wildcard) |
| `.revokePermission(...)` | `.revoke_permission(...)` | `.revoke_permission(...)?` |
| `.addParentRole(child, parent)` | `.add_parent_role(child, parent)` | `.add_parent_role(child, parent)?` |
| `.assignToIdentity(id, org, role)` | `.assign_to_identity(id, org, role)` | `.assign_to_identity(id, org, role)?` |
| `.assignToGroup(group, org, role)` | `.assign_to_group(group, org, role)` | `.assign_to_group(group, org, role)?` |
| `.getIdentityRoles(id, org)` | `.get_identity_roles(id, org)` | `.get_identity_roles(id, org)?` |

### Memberships

| Java | Python | Rust |
|---|---|---|
| `gh.membershipManager().createMembership(id, org, EntityType.USER)` | `gh.membership_manager().create_membership(id, org, EntityType.USER)` | `gh.membership_manager().create_membership(id, org, EntityType::User)?` |
| `.setStatus(id, org, MembershipStatus.SUSPENDED)` | `.set_status(id, org, MembershipStatus.SUSPENDED)` | `.set_status(id, org, MembershipStatus::Suspended)?` |
| `.getStatus(id, org)` → `Optional<MembershipStatus>` | `.get_status(id, org)` → `MembershipStatus \| None` | `.get_status(id, org)?` → `Option<MembershipStatus>` |

### Groups

| Java | Python | Rust |
|---|---|---|
| `gh.groupManager().createGroup(id, org, name, desc)` | `gh.group_manager().create_group(id, org, name, desc)` | `gh.group_manager().create_group(id, org, Some(name), Some(desc))?` |
| `.addIdentityToGroup(g, org, id)` | `.add_identity_to_group(g, org, id)` | `.add_identity_to_group(g, org, id)?` |
| `.getGroupMembers(g, org)` | `.get_group_members(g, org)` | `.get_group_members(g, org)?` |

### Authorization checks

| Java | Python | Rust |
|---|---|---|
| `gh.hasPermission(id, org, svc, res, act)` → `boolean` | `gh.has_permission(id, org, svc, res, act)` → `bool` | `gh.has_permission(id, org, svc, res, act)?` → `bool` |
| `gh.getEffectivePermissions(id, org)` → `List<EffectivePermission>` | `gh.get_effective_permissions(id, org)` → `list[EffectivePermission]` | `gh.get_effective_permissions(id, org)?` → `Vec<EffectivePermission>` |
| `gh.getRoles(id, org)` / `getGroups(id, org)` | `.get_roles(id, org)` / `.get_groups(id, org)` | `.get_roles(id, org)?` / `.get_groups(id, org)?` |

### JWT verification

```java
// Java
var cfg = GatedhouseConfig.builder()
    .database(db)
    .tokenVerifier(TokenVerifierConfig.builder()
        .jwksUri(URI.create("https://auth.example.com/.well-known/jwks.json"))
        .issuer("https://auth.example.com")
        .audience("superagent-platform")
        .build())
    .build();
try (Gatedhouse gh = GatedhouseFactory.create(cfg)) {
    AuthenticatedSubject who = gh.verifyToken(bearerToken);
    boolean ok = gh.hasPermission(who.id(), orgId, "workspace", "projects", "read");
}
```

```python
# Python
from gatedhouse import (
    Database, GatedhouseConfig, GatedhouseFactory, TokenVerifierConfig)

config = GatedhouseConfig(
    database=Database.from_uri(conninfo),
    token_verifier=TokenVerifierConfig(
        jwks_uri="https://auth.example.com/.well-known/jwks.json",
        issuer="https://auth.example.com",
        audience="superagent-platform",
    ),
)
with GatedhouseFactory.create(config) as gh:
    who = gh.verify_token(bearer_token)
    ok = gh.has_permission(who.id, org_id, "workspace", "projects", "read")
```

```rust
// Rust
use gatedhouse::{
    ConninfoDatabase, Database, GatedhouseConfig, GatedhouseFactory,
    TokenVerifierConfig,
};
use std::sync::Arc;

let database: Arc<dyn Database> = Arc::new(ConninfoDatabase::new(conninfo));
let config = GatedhouseConfig::builder(database)
    .token_verifier(TokenVerifierConfig::new(
        "https://auth.example.com/.well-known/jwks.json",
        "https://auth.example.com",
        "superagent-platform",
    ))
    .build();
let gh = GatedhouseFactory::create(config)?;

let who = gh.verify_token(&bearer_token)?;
let ok = gh.has_permission(&who.id, org_id, "workspace", "projects", "read")?;
```

### Web & Sphinx SSO integration

Same components in all three SDKs, adapted to each platform's web standard: Java uses `jakarta.servlet.Filter`, Python uses WSGI middleware (PEP 3333), and Rust — which has no servlet-like standard — exposes the same decision logic as framework-agnostic guards returning either the verified context or the response to write.

| Concept | Java | Python | Rust |
|---|---|---|---|
| Verified claims view | `GatedContext` (record) | `GatedContext` (frozen dataclass) | `GatedContext` (struct) |
| Build from subject | `GatedContext.fromSubject(subject)` | `GatedContext.from_subject(subject)` | `GatedContext::from_subject(&subject)` |
| Claim helpers | `isAdmin()` / `isHuman()` / `isDelegated()` / `hasScope(s)` | `is_admin()` / `is_human()` / `is_delegated()` / `has_scope(s)` | `is_admin()` / `is_human()` / `is_delegated()` / `has_scope(s)` |
| OAuth helper | `SphinxClient` (`java.net.http`) | `SphinxClient` (stdlib `urllib`) | `SphinxClient` (`ureq`) → `Result<_, SphinxError>` |
| API guard (Bearer → 401 JSON) | `GatedhouseApiFilter` (servlet) | `GatedhouseApiFilter` (WSGI) | `GatedhouseApiFilter::authenticate(header)` → `Result<GatedContext, FilterError>` |
| Web guard (session → login redirect) | `GatedhouseWebFilter` (servlet, reads `HttpSession`) | `GatedhouseWebFilter` (WSGI, reads session mapping from environ) | `GatedhouseWebFilter::check(token, ctx_path)` → `WebFilterOutcome` |
| Privilege asserts | `requireAdmin/requireHuman/requireScope` (throw `ForbiddenException`) | `require_admin/require_human/require_scope` (raise `ForbiddenException`) | `require_admin/require_human/require_scope` (return `FilterError::Forbidden`) |
| Verify-only instance | `GatedhouseFactory.createJustTokenVerifier(cfg)` | `GatedhouseFactory.create_just_token_verifier(cfg)` | `GatedhouseFactory::create_just_token_verifier(cfg)` |

The verify-only instance needs no database; every database-backed method on it fails fast (Java `UnsupportedOperationException`, Python `NotImplementedError`, Rust panic) with the same message. The request-context key (`com.twelvevectors.gatedhouse.context`), default login path (`/auth/login`), default session token attribute (`access_token`), security headers, and 401 JSON body shape are identical across SDKs.

### Failure-mode handling for `verify_token`

All three SDKs expose the **same nine reasons** so the host can branch on the failure:

| Reason | Java enum constant | Python / Rust enum |
|---|---|---|
| Token expired (refresh / SSO) | `Reason.EXPIRED` | `EXPIRED` |
| Not yet valid (clock skew) | `NOT_YET_VALID` | `NOT_YET_VALID` |
| Bad signature (forged) | `INVALID_SIGNATURE` | `INVALID_SIGNATURE` |
| Wrong issuer | `INVALID_ISSUER` | `INVALID_ISSUER` |
| Wrong audience | `INVALID_AUDIENCE` | `INVALID_AUDIENCE` |
| Malformed | `MALFORMED` | `MALFORMED` |
| Unknown `kid` after JWKS refresh | `UNKNOWN_KEY` | `UNKNOWN_KEY` |
| JWKS endpoint unreachable | `JWKS_UNAVAILABLE` | `JWKS_UNAVAILABLE` |
| Catch-all | `OTHER` | `OTHER` |

### Cache configuration

| Java | Python | Rust |
|---|---|---|
| `new InMemoryPermissionCache(Duration.ofSeconds(60))` | `InMemoryPermissionCache(timedelta(seconds=60))` | `InMemoryPermissionCache::with_ttl(Duration::from_secs(60))` |
| `new JCachePermissionCache(myJCache)` | *(host implements `PermissionCache` directly)* | *(host implements `PermissionCache` directly)* |
| `gh.invalidateCache(id, org)` | `gh.invalidate_cache(id, org)` | `gh.invalidate_cache(id, org)` |
| `gh.invalidateAllCache()` | `gh.invalidate_all_cache()` | `gh.invalidate_all_cache()` |
| `gh.setCacheBypass(true)` / `isCacheBypassed()` | `gh.set_cache_bypass(True)` / `is_cache_bypassed()` | `gh.set_cache_bypass(true)` / `is_cache_bypassed()` |

### Smoke tests

All three SDKs ship the same end-to-end smoke test with identical `smoketest`-prefixed fixture names. They share the same scenarios and the same per-scenario `[PASS]` / `[FAIL]` output. Run any one of them against a real Postgres:

```bash
java -cp ... com.twelvevectors.gatedhouse.cli.SmokeTest <jdbc-url> <user> <pwd>
python -m gatedhouse.cli.smoke_test "<conninfo>"
cargo run --bin gatedhouse-smoke-test -- "<conninfo>"
```

Exit code 0 = all checks pass.

---

## Core Concepts

### Why these layers exist

Authorization here is deliberately layered. The layers are independent, and not every host needs all of them — this map says what each one is *for*, why it isn't folded into another, and when you can leave it empty.

| Layer | What it is | Why it's separate | When you can ignore it |
|---|---|---|---|
| **Membership** | `(identity, org)` gate carrying `status` | A grant says *what* an identity may do; membership says *whether it may act at all* in this org. Keeping the kill-switch off the grant graph is what lets `SUSPENDED`/`PENDING` short-circuit **before** any role is evaluated — you revoke access org-wide without touching a single assignment. | Never — every check needs an `ACTIVE` membership. A single-state host can just create-and-activate and never look at `status` again. |
| **Direct role assignment** | `identity → role` | The minimal path from an identity to permissions. | Never; this is the floor of the model. |
| **Groups** | `identity → group → role` | Bulk and team management. One `assignToGroup` puts a role on every current *and future* member; one `addIdentityToGroup` gives a person everything the team has. Without it you re-assign every role per identity, and nothing answers "who is on the eng team?" in one place. | If tenants are small or the product has no team/department concept, skip groups entirely — direct assignment covers it and the three group tables sit empty at **zero cost to correctness**. |
| **Role inheritance** | `role → parent role` | Composition over duplication: `editor` inherits `viewer` as one edge instead of recopying viewer's grants. Orthogonal to groups — inheritance bundles *permissions across roles*, groups bundle *identities onto a role*. | If roles are flat and disjoint, never add a parent edge; the recursive walk simply finds none. |

**Membership is a gate, not a grant.** No permissions ever attach to a membership row — permissions attach only to roles. Membership decides whether role evaluation runs at all. This separation is intentional: it is what makes suspension O(1), independent of how many roles or groups the identity has, and auditable as a single state change.

**The cost of the layering.** An effective permission can arrive by up to four paths (direct-or-group → role, then optionally up an inheritance chain). That makes "*why* does Alice have `workspace:projects:write`?" non-obvious from the raw tables. The canonical answer is always `getEffectivePermissions(identity, org)` / `getRoles(...)` / `getGroups(...)` — treat those as the debugging surface, not the junction tables underneath.

### Permission model

A permission is a triple **`(service, resource, action)`** — three independent strings. They map directly to three columns; there is no string parsing. A `:`-joined display form is conventional for humans (`workspace:projects:read`) but never appears in the API.

Every concrete permission must be **registered in the catalog** before it can be granted, checked, or appear in role definitions.

### Wildcards

In a **role grant**, any of the three columns may be `null`. `null` means "any" at that level. A grant `(workspace, null, read)` matches concrete checks against `workspace:projects:read`, `workspace:documents:read`, and any future workspace resource — without re-granting per resource. A full wildcard `(null, null, null)` is superuser-equivalent.

Wildcards exist **only on grants**, never on checks. `hasPermission(...)` always takes a concrete `(service, resource, action)`.

The catalog tables hold only concrete entries. Composite foreign keys with nullable columns (Postgres `MATCH SIMPLE`) skip referential validation when any component is `null`, which is exactly the wildcard semantics we want.

### Multi-tenancy

Every identity-side table is org-scoped: `memberships`, `role_assignments`, `group_memberships`, `group_roles`, `groups`. The same identity can be an editor in `acme`, a viewer in `globex`, and have no membership at all in `initech` — all simultaneously, with independent roles and permissions per org.

Role definitions and the permission catalog are **global**. The role `editor` means the same thing in every org. This keeps shared role libraries shared.

### Identities

Identity IDs are **opaque strings supplied by the host application**. Gatedhouse has no `identities` table and does not validate that an identity exists in some external system; it trusts the IDs you pass in.

Each identity has an `EntityType` (`USER` or `AGENT`) recorded on its membership row. Today the type is metadata only — Gatedhouse does not branch authorization decisions on it. The distinction is preserved for audit and future policy hooks.

### Membership lifecycle

A `Membership` is the per-org link between an identity and the system. It carries:

- `entity_type` (`USER` / `AGENT`)
- `status` (`ACTIVE` / `SUSPENDED` / `PENDING`)

Status drives the decision flow:

| Status | Behavior in `hasPermission` |
|---|---|
| `ACTIVE` | Normal evaluation |
| `SUSPENDED` | **Short-circuits to DENY** before any permission check |
| `PENDING` | **Short-circuits to DENY** — the host has registered the membership but the identity is not yet provisioned for use |

The host moves between states with `gh.membershipManager().setStatus(identityId, orgId, status)`.

### Roles, inheritance, and group assignments

A role is a global named bag of permissions, optionally inheriting permissions from parent roles. Two paths bring a role to an identity:

1. **Direct assignment**: `roleManager().assignToIdentity(identityId, orgId, roleKey)` — a row in `role_assignments`.
2. **Via group**: identity is in a group (`group_memberships`); the group has a role (`group_roles`).

The set of effective roles is the **union** of both paths, plus the recursive closure over `role_inherits` (parent roles, grandparents, etc.).

Cycles in `role_inherits` are not a problem: the recursive CTE used for evaluation deduplicates via SQL `UNION` and terminates after one full traversal.

### Built-in `gatedhouse:owner` role

Seeded by the V001 migration with a single permission row of `(null, null, null)` — a full wildcard. Used to give an identity unrestricted access in an org without granting `*:*:*` ad-hoc:

```java
gh.roleManager().assignToIdentity(identityId, orgId, "gatedhouse:owner");
```

It's marked `is_system = TRUE`. `deleteRole("gatedhouse:owner")` is a no-op (system roles cannot be deleted via the public API).

### Authorization is independent of authentication

Gatedhouse never asks "who is this caller?" — that's the host's responsibility. `hasPermission(identityId, orgId, ...)` takes an already-trusted identity ID. Where that ID came from is up to the host: a session, a header, a verified JWT, anything.

For convenience the library ships a JWT verification helper (`gh.verifyToken(jwt)`) compatible with Sphinx-issued tokens — see [Authentication](#authentication-via-sphinx-jwt-verification). It's strictly opt-in. The library is fully usable without it.

---

## Database Schema

All tables live in the `gatedhouse` Postgres schema (separate from `public`).

```
                      [Permission Catalog — global]
   gatedhouse.services ─< gatedhouse.resources ─< gatedhouse.actions
                              ▲
                              │ (composite FKs; nulls skip = wildcard)
                              │
   [Roles — global]                                [Audit — internal]
   gatedhouse.roles                                gatedhouse.audit_log
       ├── gatedhouse.role_permissions ────────────────▲
       └── gatedhouse.role_inherits                    │
              (child_key, parent_key)                  │
                                                       │
   [Identity-side — per-org]                           │ (populated by triggers
   gatedhouse.memberships                              │  on every CRUD)
   gatedhouse.role_assignments                         │
   gatedhouse.groups                                   │
       └── gatedhouse.group_memberships                │
       └── gatedhouse.group_roles ─────────────────────┘

   [Migration bookkeeping]
   gatedhouse.schema_versions
```

| Table | Cardinality | Purpose |
|---|---|---|
| `services` | global | Top level of permission vocabulary |
| `resources` | global, FK→services | Mid level; composite PK `(service, resource)` |
| `actions` | global, FK→resources | Leaf; composite PK `(service, resource, action)` |
| `roles` | global | Role definitions, including `is_system` |
| `role_permissions` | global, junction | One row per granted permission tuple; supports nullable wildcards |
| `role_inherits` | global, junction | DAG edges `(child_key, parent_key)` |
| `memberships` | per-org | One row per `(identity_id, org_id)`; library-owned |
| `role_assignments` | per-org | Direct identity → role assignments |
| `groups` | per-org | Group definitions; ID supplied by host |
| `group_memberships` | per-org | Junction `(group, identity)` per org |
| `group_roles` | per-org | Junction `(group, role)` per org |
| `audit_log` | global | Generic CRUD log; populated by `gatedhouse.audit_trigger` |
| `schema_versions` | global | Migration runner bookkeeping |

ID conventions:

- **Library-generated PKs** (`memberships.id`, `role_assignments.id`, `role_permissions.id`) — Postgres `UUID`, generated in Java with `UUID.randomUUID()`.
- **Opaque host-supplied IDs** (`identity_id`, `org_id`, `group_id`) — `TEXT`. The library doesn't validate these against any external system.

---

## Public API Surface

```
com.twelvevectors.gatedhouse
├── Gatedhouse                  ← top-level interface (AutoCloseable)
│   ├── permissionCatalog() ─── PermissionCatalog
│   ├── roleManager()       ─── RoleManager
│   ├── membershipManager() ─── MembershipManager
│   ├── groupManager()      ─── GroupManager
│   ├── hasPermission(...)
│   ├── getEffectivePermissions(identityId, orgId)
│   ├── getRoles(identityId, orgId)
│   ├── getGroups(identityId, orgId)
│   ├── verifyToken(jwt)
│   └── close()
├── GatedhouseFactory
│   ├── create(GatedhouseConfig)   ← validates schema, returns Gatedhouse
│   ├── createJustTokenVerifier(TokenVerifierConfig) ← database-free, verify-only
│   └── migrate(GatedhouseConfig)  ← runs pending migrations
├── GatedhouseConfig (+ Builder)
├── Database                    ← functional interface; getConnection()
├── GroupSource (+ LocalGroupSource)
├── TokenVerifierConfig (+ Builder)
│
├── Web & Sphinx SSO integration
│   ├── GatedContext            ← type-safe view of a verified token's claims
│   ├── SphinxClient            ← OAuth 2.0 helper (code exchange, refresh, introspect, …)
│   ├── GatedhouseApiFilter     ← Bearer-token guard for REST endpoints (401 JSON)
│   └── GatedhouseWebFilter     ← session-token guard for pages (login redirect)
│
├── Value types
│   ├── EntityType              (USER, AGENT)
│   ├── MembershipStatus        (ACTIVE, SUSPENDED, PENDING)
│   ├── EffectivePermission     (record: service, resource, action)
│   └── AuthenticatedSubject    (record: id, issuer, audience, …)
│
├── Exceptions (all RuntimeException)
│   ├── GatedhouseInitializationException
│   ├── GatedhouseDatabaseException
│   ├── SchemaNotInitializedException
│   ├── SchemaOutOfDateException
│   └── TokenVerificationException     (carries a Reason enum)
│
└── cli
    ├── Migrate                 ← runs the migration; main(String[])
    └── SmokeTest               ← end-to-end smoke test against a real DB
```

### Naming conventions

| Convention | Used for |
|---|---|
| `add*` / `remove*` | Set-style operations on the catalog (services / resources / actions) |
| `create*` / `delete*` | Entity CRUD (roles, memberships, groups) |
| `set*` / `get*` | Single-attribute mutate / read |
| `has*` | Boolean existence checks |
| `list*` | Collection retrievals |
| `grant*` / `revoke*` | Permission grants on roles |
| `assign*` / `revokeFrom*` | Role assignments to identities or groups |
| Returns `Optional<T>` | Single-value getters that may be absent |
| Returns `List<T>` | Collection getters; empty list if none |

---

## Step-by-Step Setup

### 1. Migrate the schema

One-time per database, before the application starts:

```bash
java -cp gatedhouse.jar:postgresql.jar \
     com.twelvevectors.gatedhouse.cli.Migrate \
     <jdbc-url> <user> <password>
```

The runner takes a Postgres advisory lock so concurrent invocations from multiple instances don't race.

### 2. Build a `Database`

A `Database` is a thin functional interface (`Connection getConnection() throws SQLException`). Two ways to obtain one:

```java
// Direct DriverManager (no pooling)
Database db = Database.fromUrl("jdbc:postgresql://...", "user", "pwd");

// From an existing DataSource (e.g., HikariCP)
HikariDataSource ds = ...;   // host owns lifecycle
Database db = ds::getConnection;
```

The library does not bundle a connection pool. Wire your own (HikariCP is conventional) when you need pooling — Gatedhouse just calls `getConnection()`.

### 3. Build the config

```java
GatedhouseConfig config = GatedhouseConfig.builder()
    .database(db)
    // Optional — only set if you want gh.verifyToken(...) to work
    .tokenVerifier(TokenVerifierConfig.builder()
        .jwksUri(URI.create(
            "https://auth.example.com/api/sphinx/v1/.well-known/jwks.json"))
        .issuer("https://auth.example.com")
        .audience("superagent-platform")
        .build())
    // Optional — defaults to LocalGroupSource (host owns group writes)
    // .groupSource(new MyEventDrivenGroupSource(...))
    .build();
```

### 4. Construct `Gatedhouse`

```java
try (Gatedhouse gh = GatedhouseFactory.create(config)) {
    // ...
}
```

`create(...)` verifies the schema is at the expected version. If it isn't, the message tells the developer exactly which command to run. Always wrap usage in try-with-resources — `close()` shuts down any configured `GroupSource`.

### 5. Register the permission catalog

Catalog entries are global. Register what your application can do, once at boot or via a setup script:

```java
PermissionCatalog cat = gh.permissionCatalog();

cat.addService("workspace", "Workspace service");
cat.addResource("workspace", "projects",  "Project");
cat.addResource("workspace", "documents", "Document");

cat.addAction("workspace", "projects", "read",   "Read project");
cat.addAction("workspace", "projects", "write",  "Write project");
cat.addAction("workspace", "projects", "delete", "Delete project");
cat.addAction("workspace", "documents", "read",  "Read document");
```

### 6. Define roles

```java
RoleManager roles = gh.roleManager();

roles.createRole("viewer",  "Viewer",  "Read-only access to workspace");
roles.grantPermission("viewer", "workspace", null, "read"); // wildcard: any resource

roles.createRole("editor",  "Editor",  "Read and write");
roles.addParentRole("editor", "viewer"); // editor inherits viewer's reads
roles.grantPermission("editor", "workspace", "projects",  "write");
roles.grantPermission("editor", "workspace", "documents", "write");

roles.createRole("admin",   "Admin",   "Full project lifecycle");
roles.addParentRole("admin", "editor");
roles.grantPermission("admin", "workspace", "projects", "delete");
```

### 7. Create memberships, assign roles

```java
gh.membershipManager().createMembership("alice", "acme", EntityType.USER);
gh.membershipManager().createMembership("bob",   "acme", EntityType.AGENT);

roles.assignToIdentity("alice", "acme", "admin");
roles.assignToIdentity("bob",   "acme", "viewer");
```

Or via a group:

```java
gh.groupManager().createGroup("eng", "acme", "Engineering", "Engineering team");
gh.groupManager().addIdentityToGroup("eng", "acme", "alice");
gh.groupManager().addIdentityToGroup("eng", "acme", "bob");
roles.assignToGroup("eng", "acme", "editor");
```

### 8. Check at runtime

```java
boolean canDelete = gh.hasPermission(
    "alice", "acme", "workspace", "projects", "delete");

if (!canDelete) {
    throw new ForbiddenException(); // or whatever your app uses
}
```

---

## Authorization Decision Flow

A single `hasPermission` call resolves to one Postgres query — a recursive CTE that:

1. **Active membership check.** If the membership is missing or its status is anything other than `active`, return false. Suspension and pending both short-circuit here.
2. **Direct roles.** Collect role keys directly assigned to the identity in this org.
3. **Group-derived roles.** Union in role keys assigned to any group the identity belongs to in this org.
4. **Inherited roles.** Recursively walk `role_inherits` upward to collect every ancestor role.
5. **Permission match.** Return true iff some `role_permissions` row matches `(service, resource, action)`, where each `null` column in the grant matches anything.

For inspecting the full picture rather than asking yes/no:

```java
List<EffectivePermission> all =
    gh.getEffectivePermissions("alice", "acme");
// Each EffectivePermission is (service, resource, action), with nulls
// for any wildcard component on the originating grant.
```

Convenience reads on `Gatedhouse`:

```java
List<String> roleKeys  = gh.getRoles("alice", "acme");
List<String> groupIds  = gh.getGroups("alice", "acme");
```

These delegate to the corresponding `roleManager()` / `groupManager()` methods.

---

## Authentication via Sphinx (JWT verification)

Gatedhouse never authenticates anyone. It does, however, provide an opt-in helper to verify JWTs issued by a Sphinx-style OIDC issuer, so the host can move from "incoming HTTP request with `Authorization: Bearer <jwt>`" to a trusted `identity_id` in one call.

### Configure once

```java
GatedhouseConfig config = GatedhouseConfig.builder()
    .database(db)
    .tokenVerifier(TokenVerifierConfig.builder()
        .jwksUri(URI.create(
            "https://auth.example.com/api/sphinx/v1/.well-known/jwks.json"))
        .issuer("https://auth.example.com")
        .audience("superagent-platform")
        .build())
    .build();
```

The verifier is backed by `nimbus-jose-jwt`. JWKS are fetched lazily, cached, refreshed on `kid` miss, and rate-limited automatically. Thread-safe across all threads — share one `Gatedhouse` instance.

### Verify per-request

```java
try {
    AuthenticatedSubject who = gh.verifyToken(bearerToken);
    boolean ok = gh.hasPermission(
        who.id(), orgId, "workspace", "projects", "read");
} catch (TokenVerificationException e) {
    switch (e.reason()) {
        case EXPIRED          -> redirectToRefreshOrSso();
        case INVALID_SIGNATURE,
             INVALID_ISSUER,
             INVALID_AUDIENCE,
             MALFORMED,
             UNKNOWN_KEY      -> rejectAndRedirectToSso();
        case JWKS_UNAVAILABLE -> retryOrFailClosed();
        case NOT_YET_VALID    -> rejectClockSkew();
        case OTHER            -> rejectAndLog(e);
    }
}
```

`AuthenticatedSubject` exposes the `sub` claim as `id()` (feed it into `hasPermission`), plus `issuer`, `audience`, `issuedAt`, `expiresAt`, `tokenType` (`"access"` / `"refresh"` / `"delegation"` etc.), and a map of any additional claims.

### Reason → response cheatsheet

| Reason | What it usually means | Recommended client action |
|---|---|---|
| `EXPIRED` | Access token aged out | Try refresh token; otherwise SSO redirect |
| `INVALID_SIGNATURE` | Token was tampered with or signed by an unknown party | Reject; log security event |
| `INVALID_ISSUER` / `INVALID_AUDIENCE` | Token was issued for a different system | Reject; SSO redirect |
| `MALFORMED` | Not a valid JWS compact serialization | Reject; possibly malicious |
| `UNKNOWN_KEY` | `kid` not in JWKS even after refresh | Reject; treat as forged |
| `JWKS_UNAVAILABLE` | Issuer's JWKS endpoint unreachable | Transient; retry or fail-closed per policy |
| `NOT_YET_VALID` | `nbf` is in the future | Likely clock skew; reject |
| `OTHER` | Unexpected | Reject; inspect cause |

### Without it

If you don't configure `tokenVerifier(...)`, calling `gh.verifyToken(...)` throws `IllegalStateException` with a clear message. Everything else — every `hasPermission` and manager method — works unchanged. The library does not require JWT verification.

---

## Pluggable Group Source

Group data writes go through `gh.groupManager()` regardless of where they originate. The factory accepts an optional `GroupSource` to control the *origin*:

```java
public interface GroupSource extends AutoCloseable {
    void start(Gatedhouse gatedhouse);
    @Override void close();
}
```

### Default: `LocalGroupSource`

The host application calls `gh.groupManager().createGroup(...)`, `addIdentityToGroup(...)` etc. directly. This is the default if you don't configure anything.

### Custom: bridge from an external source of truth

Implement `GroupSource`. On `start`, register a listener with the host's transport (Kafka topic, HTTP webhook, etc.) and translate incoming events into `gh.groupManager()` write calls. On `close`, release the listener.

```java
public final class CitadelBridgeGroupSource implements GroupSource {
    private final CitadelClient citadel;
    private Subscription subscription;

    public CitadelBridgeGroupSource(CitadelClient citadel) {
        this.citadel = citadel;
    }

    @Override
    public void start(Gatedhouse gh) {
        subscription = citadel.subscribe("groups.*", event -> {
            switch (event.type()) {
                case GROUP_CREATED  -> gh.groupManager().createGroup(
                    event.groupId(), event.orgId(),
                    event.name(), event.description());
                case GROUP_DELETED  -> gh.groupManager().deleteGroup(
                    event.groupId(), event.orgId());
                case MEMBER_ADDED   -> gh.groupManager().addIdentityToGroup(
                    event.groupId(), event.orgId(), event.identityId());
                case MEMBER_REMOVED -> gh.groupManager().removeIdentityFromGroup(
                    event.groupId(), event.orgId(), event.identityId());
            }
        });
    }

    @Override
    public void close() {
        if (subscription != null) {
            subscription.cancel();
        }
    }
}

GatedhouseConfig config = GatedhouseConfig.builder()
    .database(db)
    .groupSource(new CitadelBridgeGroupSource(myCitadelClient))
    .build();
```

The library is transport-agnostic and ships no concrete event-driven sources — those depend on infrastructure that's outside our scope and dependency budget.

---

## Permission Cache

Every `hasPermission` and `getEffectivePermissions` call goes through a cache keyed on `(identityId, orgId)`. The cached value is the full effective-permission set for that identity in that org, so a single DB round trip serves every subsequent permission question for the identity until the entry is invalidated or expires. `hasPermission` filters the cached list in Java with the same NULL-wildcard rule as the SQL.

### Default

If you don't configure anything, the library uses an in-process `InMemoryPermissionCache` with a 60-second TTL. `ConcurrentHashMap`-backed (or the equivalent for Python/Rust — `dict` + `threading.Lock`, or `HashMap` + `Mutex`), lazy eviction on read, thread-safe across all callers.

### Process-local by default — caveat for multi-app deployments

The default `InMemoryPermissionCache` is **per-process**. Two applications pointing at the same database — whether using different SDKs (Java + Python, etc.) or two instances of the same SDK behind a load balancer — hold **independent** caches. Writes through one app's library API invalidate *that app's* cache only; the other app keeps serving its existing cached entry until the TTL expires.

Concrete failure mode:

```
T+0s   App A:  role_manager.assign_to_identity("alice", "acme", "editor")
                ─► App A's cache entry for ("alice","acme") evicted (targeted)
                ─► Postgres now reflects the new assignment

T+0s   App B:  has_permission("alice","acme","workspace","projects","read")
                ─► HIT on App B's stale cache (populated before App A's write)
                ─► returns the pre-assignment answer

T+60s  App B's cache entry expires (lazy eviction on next read)
T+60s+ App B reads → cache miss → fresh DB query → correct answer
```

The same applies to writes that bypass the library entirely (raw SQL, sibling systems): every cache instance is stale until its TTL expires or someone calls `invalidate*` on it.

If you only run one application against the database, this never bites you. If you run more than one, pick a strategy below.

#### Strategies to remove the divergence window

| Strategy | What you do | Cache hit rate | Latency to consistency |
|---|---|---|---|
| **Shared cache** (recommended) | Implement `PermissionCache` against Redis / Memcached / Hazelcast — or in Java, use `JCachePermissionCache` to wrap any JSR 107 provider. All apps now read/write the same cache state. | Same as default | Real-time (one-write fans out via the cache) |
| **Lower TTL** | Construct the cache with a shorter TTL — `new InMemoryPermissionCache(Duration.ofSeconds(2))` (Java), `InMemoryPermissionCache(timedelta(seconds=2))` (Python), `InMemoryPermissionCache::with_ttl(Duration::from_secs(2))` (Rust). | Reduced (more misses) | Bounded by TTL |
| **Cross-process invalidation** | Wire a Postgres `LISTEN`/`NOTIFY` channel or a small pub/sub topic. On notification, call `gh.invalidate_cache(id, org)` or `gh.invalidate_all_cache()`. | Same as default | Near real-time |
| **Bypass entirely** | `gh.set_cache_bypass(true)` on the affected app. Every read goes to the database. | Zero | Real-time |

For most multi-app deployments, the shared-cache strategy is the right answer — same code path, same TTL, and a single source of truth for cached entries.

### Plugging in any JSR 107 (JCache) provider

Standard path. Configure your JCache (Ehcache 3, Hazelcast, Redisson for Redis, Caffeine via its JCache adapter, …) and wrap it with the bundled `JCachePermissionCache` adapter:

```java
import javax.cache.Caching;
import javax.cache.CacheManager;
import javax.cache.Cache;
import javax.cache.configuration.MutableConfiguration;
import javax.cache.expiry.CreatedExpiryPolicy;
import javax.cache.expiry.Duration;
import static java.util.concurrent.TimeUnit.SECONDS;

CacheManager mgr = Caching.getCachingProvider().getCacheManager();

@SuppressWarnings("unchecked")
MutableConfiguration<PermissionCacheKey, List<EffectivePermission>> cfg =
    new MutableConfiguration<PermissionCacheKey, List<EffectivePermission>>()
        .setTypes(PermissionCacheKey.class,
                  (Class<List<EffectivePermission>>) (Class<?>) List.class)
        .setExpiryPolicyFactory(
            CreatedExpiryPolicy.factoryOf(new Duration(SECONDS, 60)))
        .setStatisticsEnabled(true);

Cache<PermissionCacheKey, List<EffectivePermission>> jcache =
    mgr.createCache("gatedhouse-perms", cfg);

GatedhouseConfig config = GatedhouseConfig.builder()
    .database(db)
    .permissionCache(new JCachePermissionCache(jcache))
    .build();
```

The host owns the `CacheManager` and `Cache` lifecycle; the adapter is a thin pass-through. `PermissionCacheKey` and `EffectivePermission` are both `Serializable`, so distributed providers (Redisson, Hazelcast, Infinispan) can persist values across the network.

### Custom (non-JCache) implementation

If your cache doesn't have a JCache adapter, implement `PermissionCache` directly. It's a 4-method interface; about 20–30 lines against any well-behaved cache client:

```java
public final class CustomPermissionCache implements PermissionCache {
    public Optional<List<EffectivePermission>> get(String identityId, String orgId) { ... }
    public void put(String identityId, String orgId, List<EffectivePermission> permissions) { ... }
    public void invalidate(String identityId, String orgId) { ... }
    public void invalidateAll() { ... }
}
```

### Invalidation

The library invalidates automatically on every write through its API:

| Write | Invalidation |
|---|---|
| `membershipManager.createMembership` / `deleteMembership` / `setStatus` | targeted: `(identityId, orgId)` |
| `roleManager.assignToIdentity` / `revokeFromIdentity` | targeted: `(identityId, orgId)` |
| `groupManager.addIdentityToGroup` / `removeIdentityFromGroup` | targeted: `(identityId, orgId)` |
| `roleManager.deleteRole` / `grantPermission` / `revokePermission` | wholesale (`invalidateAll`) |
| `roleManager.addParentRole` / `removeParentRole` | wholesale |
| `roleManager.assignToGroup` / `revokeFromGroup` | wholesale |
| `groupManager.deleteGroup` | wholesale |
| `permissionCatalog.removeService` / `removeResource` / `removeAction` | wholesale |

The wholesale invalidations look broad but auth-config writes are infrequent in normal operation; the throughput-sensitive paths are the writes that affect *one* identity (assignment changes, status changes, group membership changes), and those are targeted.

### Manual invalidation

If you write to the schema outside this library (raw SQL, sibling processes), the library can't invalidate for you. Two escape hatches on `Gatedhouse`:

```java
gh.invalidateCache("alice", "acme");  // one entry
gh.invalidateAllCache();              // everything
```

In normal use you should not need either.

### Runtime kill switch

There's a true bypass on the `Gatedhouse` interface itself, intended for emergency operations and debugging:

```java
gh.setCacheBypass(true);   // every read goes straight to the database
gh.setCacheBypass(false);  // caching resumes (cache starts cold)
boolean isOn = gh.isCacheBypassed();
```

When bypass is on, `hasPermission` and `getEffectivePermissions` skip the cache entirely — neither `get` nor `put` is called. **Writes still invalidate** the cache, so when you flip bypass back off the cache is consistent and refills cold.

Default is off. Thread-safe — applies on the next read in any thread once set. Backed by an `AtomicBoolean`.

### Disabling permanently (tests / development)

For tests or development that want zero caching at compile-time rather than via the kill switch, implement a `PermissionCache` whose `get` always returns `Optional.empty()`:

```java
GatedhouseConfig.builder()
    .database(db)
    .permissionCache(new PermissionCache() {
        public Optional<List<EffectivePermission>> get(String i, String o) { return Optional.empty(); }
        public void put(String i, String o, List<EffectivePermission> p) {}
        public void invalidate(String i, String o) {}
        public void invalidateAll() {}
    })
    .build();
```

---

## Audit Log

Every CRUD on the auth-config tables (services, resources, actions, roles, role_permissions, role_inherits, role_assignments, groups, group_memberships, group_roles, memberships) writes an entry into `gatedhouse.audit_log` via the `gatedhouse.audit_trigger` PL/pgSQL function. The audit log itself and the migration bookkeeping (`schema_versions`) are excluded.

Each entry records:

| Column | Value |
|---|---|
| `id` | `BIGSERIAL` |
| `table_name` | `gatedhouse.<table>` |
| `op` | `INSERT` / `UPDATE` / `DELETE` |
| `old_row` | `JSONB` snapshot of the previous row (`NULL` on INSERT) |
| `new_row` | `JSONB` snapshot of the new row (`NULL` on DELETE) |
| `changed_at` | `TIMESTAMPTZ DEFAULT NOW()` |
| `changed_by` | Optional caller-supplied identifier (see below) |

### Attributing changes to an actor

The trigger reads the optional Postgres session variable `gatedhouse.actor`. To attribute a batch of writes to a specific principal, set the variable on the connection before the writes:

```sql
SET LOCAL gatedhouse.actor = 'alice@example.com';
-- subsequent INSERT/UPDATE/DELETE in this transaction record changed_by = 'alice@example.com'
```

When unset, `changed_by` is `NULL`.

### Querying

```sql
-- All changes to a specific role
SELECT op, new_row, changed_by, changed_at
FROM gatedhouse.audit_log
WHERE table_name = 'gatedhouse.roles'
  AND new_row->>'key' = 'editor'
ORDER BY changed_at DESC;

-- All changes by a specific actor
SELECT table_name, op, new_row, changed_at
FROM gatedhouse.audit_log
WHERE changed_by = 'alice@example.com'
ORDER BY changed_at DESC;
```

### Note on volume

This is **change audit**, not **decision audit**. `hasPermission` calls do not write to the audit log. If you need a record of every authorization decision (allow/deny outcomes), emit a structured log line at decision time in your application — that's a high-volume concern better served by a log pipeline than a database table.

---

## Use Cases

### Multi-tenant SaaS with shared role library

```java
// Catalog and roles defined once, shared across all tenants
cat.addService("workspace", "Workspace");
cat.addResource("workspace", "projects",  "Project");
cat.addAction("workspace", "projects", "read",   "Read project");
cat.addAction("workspace", "projects", "write",  "Write project");
cat.addAction("workspace", "projects", "delete", "Delete project");

roles.createRole("viewer", "Viewer", "Read-only");
roles.grantPermission("viewer", "workspace", null, "read");

roles.createRole("editor", "Editor", "Read + write");
roles.addParentRole("editor", "viewer");
roles.grantPermission("editor", "workspace", "projects", "write");

// Per-tenant: invitations result in (membership + role assignment)
String orgId = "acme";
gh.membershipManager().createMembership(userId, orgId, EntityType.USER);
roles.assignToIdentity(userId, orgId, "editor");
// First user of the org can be marked owner:
roles.assignToIdentity(orgFounderId, orgId, "gatedhouse:owner");
```

### Wildcards for cross-resource grants

```java
// Single grant covers any current and future resource of the workspace service
roles.createRole("workspace_reader", "Workspace Reader", "Read everything");
roles.grantPermission("workspace_reader", "workspace", null, "read");

// Adding a new resource later doesn't require touching the grant
cat.addResource("workspace", "comments", "Comment");
cat.addAction("workspace", "comments", "read", "Read comments");
// Anyone with workspace_reader now also has comments:read
```

### Group-based team permissions

```java
gh.groupManager().createGroup("engineering", "acme", "Engineering", null);
gh.groupManager().createGroup("sales",       "acme", "Sales",       null);

roles.assignToGroup("engineering", "acme", "developer");
roles.assignToGroup("sales",       "acme", "crm_user");

gh.groupManager().addIdentityToGroup("engineering", "acme", "alice");
gh.groupManager().addIdentityToGroup("sales",       "acme", "bob");

// Alice now has the developer role in acme by virtue of group membership.
```

### Suspending an identity

```java
gh.membershipManager().setStatus(
    userId, orgId, MembershipStatus.SUSPENDED);

// Every subsequent hasPermission(userId, orgId, ...) returns false
// — even for permissions explicitly granted, even gatedhouse:owner.

// To restore:
gh.membershipManager().setStatus(
    userId, orgId, MembershipStatus.ACTIVE);
```

### JWT-authenticated request handler

```java
public boolean canDeleteProject(String bearerToken,
                                 String orgId,
                                 String projectId) {
    AuthenticatedSubject who;
    try {
        who = gh.verifyToken(bearerToken);
    } catch (TokenVerificationException e) {
        // Caller maps reason → 401 response
        throw new AuthenticationFailure(e.reason());
    }
    return gh.hasPermission(
        who.id(), orgId, "workspace", "projects", "delete");
}
```

### Bootstrapping a brand-new tenant

```java
String orgId = "newco";

// Membership for the founder, marked active
String founderId = "user_42";
gh.membershipManager().createMembership(founderId, orgId, EntityType.USER);

// Owner role grants superuser within this org
gh.roleManager().assignToIdentity(founderId, orgId, "gatedhouse:owner");

// Founder can now do anything in newco that the catalog covers,
// without further per-permission grants.
```

---

## Best Practices

### Naming

- Use the three-part `(service, resource, action)` shape consistently. Don't smuggle compound nouns into a single component (e.g., prefer `(workspace, projects, archive)` over `(workspace, projects_archive, do)`).
- Action verbs should read naturally for the resource: `read`, `write`, `delete`, `list`, `approve`, `archive`, `deploy`. Don't reuse a verb for substantively different operations across resources without thinking about it.

### Role design

- Compose with inheritance rather than copying permissions. `editor` inheriting `viewer` is a single edge; redefining all of viewer's grants on editor is a maintenance trap.
- Keep roles focused: one cohesive responsibility per role. Use multiple role assignments rather than building "kitchen-sink" roles.
- Mark only roles whose deletion would be catastrophic as `is_system`. The library currently seeds one (`gatedhouse:owner`) — adding more requires direct DDL today.

### Security

- **Always verify the JWT before using its `sub` claim.** A `hasPermission` call against an unverified `identity_id` is a vulnerability the library cannot detect.
- Store database credentials with secrets management; do not commit them.
- The `gatedhouse:owner` role is total. Audit who holds it; consider time-bounded grants (custom application logic — `expires_at` is not currently a column on `role_assignments`, but the library will permit you to add it in a follow-on migration if you need it).
- The migration tool requires `CREATE` privilege on the target database. In production, run it as part of a controlled deploy step, not as the application user.

### Performance

- The recursive CTE in `hasPermission` is fully indexed (every join touches a primary or secondary index). For low-millisecond decisions, that's already what you have.
- Use connection pooling (HikariCP) — wire it via `Database`, the library doesn't bundle a pool.
- The `audit_log` is append-only; depending on retention policy you may want a periodic `VACUUM`/partition strategy.

### Testing

- The bundled `cli/SmokeTest` exercises the main paths (catalog, roles, inheritance, wildcards, groups, suspension, owner role, `getEffectivePermissions`). It's idempotent and self-cleaning, safe to run repeatedly against a real Postgres.
- Each test scenario uses `smoketest`-prefixed identifiers so it doesn't collide with real data. You can adapt it as a template for application-specific integration tests.

---

## Troubleshooting

### `SchemaNotInitializedException` at startup

The configured database does not have the `gatedhouse` schema yet. The exception message includes the exact migration command — run it once, then start the application again.

### `SchemaOutOfDateException` after upgrading the library

The library version expects a newer schema version than what's applied. The exception carries `currentVersion()` and `expectedVersion()` and the message tells you to run the migration tool. The runner will apply only the pending migrations (anything beyond `currentVersion`).

### `hasPermission` always returns false

Walk down the decision flow:

1. **Membership exists and is `active`?**
   ```java
   gh.membershipManager().getStatus(identityId, orgId)
       .ifPresentOrElse(
           s -> System.out.println("status=" + s),
           () -> System.out.println("no membership"));
   ```
2. **Roles assigned?**
   ```java
   System.out.println(gh.getRoles(identityId, orgId));
   System.out.println(gh.getGroups(identityId, orgId));
   ```
3. **Effective permissions include what you expect?**
   ```java
   gh.getEffectivePermissions(identityId, orgId).forEach(System.out::println);
   ```
4. **Catalog entry registered?** A grant references columns that need to exist in `services` / `resources` / `actions` (unless they're nulls/wildcards).

### Role inheritance not working

`addParentRole(child, parent)` writes a row to `gatedhouse.role_inherits`. Verify:

```java
gh.roleManager().getParentRoles("editor"); // should contain "viewer"
```

If the parent role doesn't exist (`hasRole(parent) == false`), the FK insert will fail at write time — not at check time.

### `TokenVerificationException(JWKS_UNAVAILABLE)`

Your application can't reach the configured `jwksUri`. Network-level issue, not a token issue. Curl the JWKS URL from the host running Gatedhouse to confirm.

### Migration command fails: "permission denied for database"

The DB user invoking the migration tool needs `CREATE` privilege on the target database (to create the `gatedhouse` schema) and `CREATE` on that schema (to create tables and the trigger function). Application users typically have lower privileges; have a DBA or your CI run the migration with an elevated role.

### `IllegalStateException`: `verifyToken` was not configured

`tokenVerifier(...)` was not supplied to the `GatedhouseConfig.Builder`. Either configure it, or stop calling `gh.verifyToken(...)` — the library is fully usable without JWT verification.

### Two application instances racing on first migration

Not actually a problem. The migrator takes a Postgres advisory lock (`pg_advisory_lock`) before doing anything. The first instance to acquire it migrates; the second instance waits, reacquires, sees the schema is current, and exits cleanly.
