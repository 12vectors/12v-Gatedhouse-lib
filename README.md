# Gatedhouse

Embedded authorization library — RBAC with role inheritance, group memberships, multi-tenancy, JWT verification (Sphinx-compatible), permission caching, and a generic audit log.

Three SDKs maintained side-by-side from this repo. They share the same Postgres schema (V001 is byte-identical across all three) and the same advisory-lock key, so a single database can be migrated and read from any combination of them.

| SDK | Path | Runtime deps | Status |
|---|---|---|---|
| **Java** (reference) | [`sdk-java/`](sdk-java/) | `pgjdbc`, `nimbus-jose-jwt`, `cache-api` | Reference implementation |
| **Python** | [`sdk-python/`](sdk-python/) | `psycopg`, `PyJWT[crypto]` | Faithful port |
| **Rust** | [`sdk-rust/`](sdk-rust/) | `postgres`, `jsonwebtoken`, `ureq`, `uuid`, `serde` | Faithful port |

## What it does

Gatedhouse answers a single runtime question:

> Given an identity (user or agent), an organization, and a `(service, resource, action)` tuple — is the action allowed?

It does this in-process, with one indexed Postgres query (or a cache hit) per check, no network round-trip to a separate authorization service. Everything else in the library — role definitions, permission catalog, group management, audit, JWT verification, caching — exists to make that one decision auditable, configurable, and trustworthy.

## What it is not

- **Not an authentication service.** Authentication is delegated to an OIDC-style issuer (e.g., [Sphinx](https://github.com/12vectors/12v-Sphinx-SSO)). Each SDK provides a helper to verify those JWTs but never issues them.
- **Not an HTTP service.** No REST endpoints, no controllers. It's a library you embed.
- **Not a multi-DB ORM.** Postgres only.

## Quick start

The same workflow in each language. Pick one:

### Java

```java
Database database = Database.fromUrl("jdbc:postgresql://localhost:5432/mydb", "user", "pwd");
GatedhouseConfig config = GatedhouseConfig.builder().database(database).build();

try (Gatedhouse gh = GatedhouseFactory.create(config)) {
    gh.permissionCatalog().addService("workspace", "Workspace");
    gh.permissionCatalog().addResource("workspace", "projects", "Project");
    gh.permissionCatalog().addAction("workspace", "projects", "read", "Read project");

    gh.roleManager().createRole("viewer", "Viewer", "Read-only");
    gh.roleManager().grantPermission("viewer", "workspace", "projects", "read");

    gh.membershipManager().createMembership("alice", "acme", EntityType.USER);
    gh.roleManager().assignToIdentity("alice", "acme", "viewer");

    boolean ok = gh.hasPermission("alice", "acme", "workspace", "projects", "read"); // true
}
```

### Java Web & Sphinx SSO Integration

For web applications (REST APIs or browser-facing UIs), Gatedhouse provides built-in Sphinx-compatible servlet integration:

*   **`SphinxClient`**: A lightweight HTTP client wrapper utilizing standard `java.net.http.HttpClient` to coordinate OAuth 2.0 authorization code exchanges, client credentials, token exchanges, token refreshes, and introspections.
*   **`GatedhouseWebFilter`**: A standard `jakarta.servlet.Filter` that protects browser-facing UI pages (e.g., `/dashboard/*`). It reads tokens from the `HttpSession` and redirects unauthorized users' browsers to a local or absolute `loginPath` on failure.
*   **`GatedhouseApiFilter`**: A standard `jakarta.servlet.Filter` that protects REST API endpoints (e.g., `/api/*`). It extracts and validates `Authorization: Bearer <token>` headers and returns a standardized `401 Unauthorized` JSON body on failure.
*   **`GatedContext`**: A type-safe record representation of a verified token's claims, accessible via `GatedhouseApiFilter.getContext(request)`.

#### Configuration Example

See [`sdk-java/sample-web.xml`](sdk-java/sample-web.xml) for a complete `web.xml` declaration and mapping template for both security filters.

#### OAuth Callback Example

To handle the OAuth authorization callback in a custom servlet using `SphinxClient`:

```java
public final class AuthCallbackServlet extends HttpServlet {
    private final SphinxClient sphinx = new SphinxClient("https://sphinx.12v.sh", "client_id", "client_secret");

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String code = req.getParameter("code");
        if (code == null) {
            resp.sendRedirect("/auth/login");
            return;
        }

        try {
            String redirectUri = "http://localhost:8080/auth/callback";
            TokenResponse tokenResp = sphinx.exchangeCode(code, redirectUri);

            // Store token in session (GatedhouseWebFilter reads this by default)
            req.getSession(true).setAttribute("access_token", tokenResp.accessToken());
            resp.sendRedirect("/dashboard");
        } catch (Exception e) {
            resp.sendError(500, "OAuth Token Exchange Failed: " + e.getMessage());
        }
    }
}
```

### Python

```python
from gatedhouse import Database, EntityType, GatedhouseConfig, GatedhouseFactory

database = Database.from_uri("postgresql://user:pwd@localhost:5432/mydb")
config = GatedhouseConfig(database=database)

with GatedhouseFactory.create(config) as gh:
    gh.permission_catalog().add_service("workspace", "Workspace")
    gh.permission_catalog().add_resource("workspace", "projects", "Project")
    gh.permission_catalog().add_action("workspace", "projects", "read", "Read project")

    gh.role_manager().create_role("viewer", "Viewer", "Read-only")
    gh.role_manager().grant_permission("viewer", "workspace", "projects", "read")

    gh.membership_manager().create_membership("alice", "acme", EntityType.USER)
    gh.role_manager().assign_to_identity("alice", "acme", "viewer")

    ok = gh.has_permission("alice", "acme", "workspace", "projects", "read")  # True
```

### Rust

```rust
use std::sync::Arc;
use gatedhouse::{
    ConninfoDatabase, Database, EntityType, GatedhouseConfig, GatedhouseFactory,
};

let database: Arc<dyn Database> = Arc::new(ConninfoDatabase::new(
    "host=localhost user=user password=pwd dbname=mydb",
));
let config = GatedhouseConfig::builder(database).build();
let gh = GatedhouseFactory::create(config)?;

gh.permission_catalog().add_service("workspace", Some("Workspace"))?;
gh.permission_catalog().add_resource("workspace", "projects", Some("Project"))?;
gh.permission_catalog().add_action("workspace", "projects", "read", Some("Read project"))?;

gh.role_manager().create_role("viewer", "Viewer", Some("Read-only"))?;
gh.role_manager().grant_permission("viewer", Some("workspace"), Some("projects"), Some("read"))?;

gh.membership_manager().create_membership("alice", "acme", EntityType::User)?;
gh.role_manager().assign_to_identity("alice", "acme", "viewer")?;

let ok = gh.has_permission("alice", "acme", "workspace", "projects", "read")?; // true
```

## Caveat for multi-app deployments — caches are process-local

Each SDK ships an in-memory permission cache (60-second TTL) by default. The cache is **process-local**: two applications pointing at the same database hold **independent** cache copies. A write through one app invalidates *that app's* cache only — the other app keeps serving its existing cached entry until the TTL expires.

```
T+0s   App A: gh.role_manager().assign_to_identity("alice", "acme", "editor")
              → App A's cache for ("alice","acme") evicted
T+0s   App B: gh.has_permission("alice","acme","ws","projects","read")
              → returns the stale pre-assignment answer (cache hit on App B)
T+60s  App B's TTL expires; next check is a fresh DB query
```

For lockstep consistency across processes, plug a shared cache by implementing the `PermissionCache` interface (Python/Rust) or the `JCachePermissionCache` adapter (Java) against Redis, Memcached, Hazelcast, etc. See [SKILLS.md → Permission Cache](SKILLS.md#permission-cache) for details.

If you only run one application against the database, this caveat does not apply.

## Schema migration

Schema lives in `gatedhouse.*` (separate Postgres schema). Each SDK embeds the same V001 SQL and runs it under a Postgres advisory lock so multiple instances or languages can call migrate concurrently.

| SDK | Command |
|---|---|
| Java | `java -cp gatedhouse-0.1.0.jar:postgresql-42.7.4.jar com.twelvevectors.gatedhouse.cli.Migrate <jdbc-url> <user> <pwd>` |
| Python | `python -m gatedhouse.cli.migrate "<conninfo>"` |
| Rust | `cargo run --bin gatedhouse-migrate -- "<conninfo>"` |

## Smoke tests

Every SDK ships an end-to-end smoke test using the same fixture names (`smoketestsvc`, `smoketestalice`, …) and the same scenarios. They're idempotent and self-cleaning — safe to run repeatedly against a real Postgres.

| SDK | Command |
|---|---|
| Java | `java ... com.twelvevectors.gatedhouse.cli.SmokeTest <jdbc-url> <user> <pwd>` |
| Python | `python -m gatedhouse.cli.smoke_test "<conninfo>"` |
| Rust | `cargo run --bin gatedhouse-smoke-test -- "<conninfo>"` |

## Where to start

- New to the library: read [SKILLS.md](SKILLS.md) for concepts, schema design, and the full API surface.
- Building against it: open the SDK directory for your language and follow the quick-start in SKILLS.md.
