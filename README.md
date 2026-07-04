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

*   **`LoginFlow`**: The **recommended** entry point for browser login. Binds the flow to the user's browser with **PKCE** (`beginLogin` → redirect to Sphinx; `completeLogin` → verify + redeem before adopting identity), which prevents login-CSRF / session-swap. Use this for any browser-facing login — see [Browser login](#browser-login-loginflow--the-safe-way).
*   **`SphinxClient`**: A lower-level HTTP client wrapper (standard `java.net.http.HttpClient`) for the OAuth 2.0 token endpoint — code exchange, client credentials, token exchange, refresh, introspection. Prefer `LoginFlow` for the browser login flow; use `SphinxClient` directly for machine-to-machine grants.
*   **`GatedhouseWebFilter`**: A standard `jakarta.servlet.Filter` that protects browser-facing UI pages (e.g., `/dashboard/*`). It reads tokens from the `HttpSession` and redirects unauthorized users' browsers to a local or absolute `loginPath` on failure.
*   **`GatedhouseApiFilter`**: A standard `jakarta.servlet.Filter` that protects REST API endpoints (e.g., `/api/*`). It extracts and validates `Authorization: Bearer <token>` headers and returns a standardized `401 Unauthorized` JSON body on failure.
*   **`GatedContext`**: A type-safe record representation of a verified token's claims, accessible via `GatedhouseApiFilter.getContext(request)`.

#### Configuration Example

See [`sdk-java/sample-web.xml`](sdk-java/sample-web.xml) for a complete `web.xml` declaration and mapping template for both security filters.

#### Browser login (`LoginFlow`) — the safe way

Browser login **must** bind the flow to the user's browser, or an attacker can drop their own
authorization `code` into your callback and seat the victim in the *attacker's* account (login-CSRF).
`LoginFlow` does this with **PKCE**: `beginLogin` stashes a `code_verifier` in a signed, `HttpOnly`,
`SameSite=Lax` cookie and redirects to Sphinx's `/oauth/authorize`; `completeLogin` requires that
cookie and redeems the code **with** the verifier, so a code minted for a different browser's flow is
rejected by Sphinx *before* your app adopts any identity.

> ⚠️ **Do not** hand-roll the callback with `SphinxClient.exchangeCode(code, redirectUri)` +
> `req.getSession(true)` for browser login — that pattern has no browser binding and is login-CSRF /
> session-fixation vulnerable. Use `LoginFlow`, and rotate the session id on elevation.

```java
// One LoginFlow per app. The signingKey (HMAC for the cookie) never leaves the app — use the
// client secret or a dedicated random key.
LoginFlow login = new LoginFlow(
    "https://sphinx.12v.sh", "client_id", "https://app.example.com/auth/callback",
    "openid email", clientSecret.getBytes(StandardCharsets.UTF_8),
    new SphinxClient("https://sphinx.12v.sh", "client_id", clientSecret));

// Login entry point — redirect the browser to Sphinx (sets the PKCE cookie).
public final class AuthLoginServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.sendRedirect(login.beginLogin(resp));
    }
}

// Callback — verify + redeem BEFORE touching the session; rotate the session id on elevation.
public final class AuthCallbackServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        SphinxClient.TokenResponse tokenResp;
        try {
            tokenResp = login.completeLogin(req, resp);   // throws LoginCsrfException on a foreign/absent code
        } catch (LoginCsrfException e) {
            resp.sendError(400, "Invalid login");         // attacker's code rejected; no session written
            return;
        }
        req.changeSessionId();                            // anti-fixation on privilege elevation
        req.getSession(true).setAttribute("access_token", tokenResp.accessToken());
        // Deep-link back to where the user was headed, or "/dashboard" if there's no return target.
        resp.sendRedirect(login.consumeReturnTo(req, resp, "/dashboard"));
    }
}
```

**Deep linking.** When `GatedhouseWebFilter` bounces an unauthenticated request to login, it records
the original path in a short-lived `gh_return` cookie (`HttpOnly`, `Secure`, `SameSite=Lax`), and
`LoginFlow.consumeReturnTo(req, resp, home)` returns an **open-redirect-safe** relative path to send
the user back to (absolute/protocol-relative URLs, backslash tricks, and control characters are
rejected in favour of `home`). This is controlled by the filter's **`deepLinkEnabled`** toggle
(init-param or constructor arg, default `true`): set it to `false` to disable capture entirely — no
`gh_return` cookie is set and login always lands on `home`.

For **machine-to-machine** grants (no browser), call `SphinxClient` directly —
`clientCredentials(...)`, `tokenExchange(...)`, `refreshToken(...)`, `introspect(...)`.

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

## JWKS key rotation & caching

Sphinx rotates its RS256 signing key periodically (every ~90 days), keeping the prior key published in JWKS for a grace window so tokens it already signed keep verifying. All three SDKs are compatible with this: each caches the JWKS and, on a token whose `kid` is **not** in the cached set, **refetches the JWKS and retries** before failing. So a newly-rotated signing key is picked up automatically — the brief cache-staleness window after a rotation is self-healing, costing at most one extra JWKS fetch on first sight of the new `kid`.

- **Rust** (`sdk-rust`): refetch-on-miss, rate-limited to once per 10s (`MIN_REFRESH_INTERVAL`).
- **Java** (`sdk-java`, Nimbus `JWKSourceBuilder` defaults): refetch-on-miss, rate-limited (~30s), plus a 5-min cache TTL and outage tolerance.
- **Python** (`sdk-python`, PyJWT ≥2.8): `PyJWKClient.get_signing_key` retries with a forced JWKS refresh on a miss.

**Known limitations (Python SDK only — not yet fixed):**
1. **Refetch is not rate-limited.** Unlike Rust (10s) and Java/Nimbus (~30s), PyJWT refetches on *every* unknown-`kid` token. A flood of tokens carrying bogus `kid`s therefore drives one JWKS fetch each — mild request amplification against the issuer's `/auth/jwks`. Acceptable for normal traffic; worth a rate-limit wrapper if exposure is a concern.
2. **Reason mis-mapping on a genuine unknown key.** PyJWT raises `Unable to find a signing key that matches: "<kid>"`; the SDK's message match looks for `"could not find"`/`"no matching"`, so a true unknown-`kid` failure surfaces as `JWKS_UNAVAILABLE` rather than `UNKNOWN_KEY`. Cosmetic — it does not affect verification or the refetch behavior above.

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
