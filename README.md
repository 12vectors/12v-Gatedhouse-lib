# Gatedhouse

Embedded RBAC library for multi-tenant applications. Answers, in-process with
one indexed PostgreSQL query (or a cache hit): may identity X, in
organization O, perform `(service, resource, action)`?

Features: permission catalog, roles with wildcards and inheritance,
per-organization memberships with a lifecycle, groups, decision explanations,
optional permission cache, JWT verification (Sphinx SSO compatible), web
filters, change audit log.

Not included: issuing tokens (authentication is delegated to an identity
provider such as [Sphinx](https://github.com/12vectors/12v-Sphinx-SSO)), an
HTTP service, databases other than PostgreSQL.

| SDK | Path | Runtime dependencies | Optional |
|---|---|---|---|
| Java 17+ (reference) | [`sdk-java/`](sdk-java/) | pgjdbc, nimbus-jose-jwt, cache-api | HikariCP |
| Python 3.10+ | [`sdk-python/`](sdk-python/) | psycopg, PyJWT[crypto] | psycopg-pool (`gatedhouse[pool]`) |
| Rust 1.74+ | [`sdk-rust/`](sdk-rust/) | postgres, jsonwebtoken, ureq, uuid, serde | r2d2, r2d2_postgres (feature `r2d2`) |

All SDKs share one schema (`gatedhouse`, version 2) and can use the same
database concurrently.

## Example (Java)

```java
// Schema created beforehand: java -cp ... com.twelvevectors.gatedhouse.cli.Migrate <jdbc-url> <user> <pwd>
Gatedhouse gh = GatedhouseFactory.create(GatedhouseConfig.builder()
    .database(Database.fromDataSource(dataSource))      // your connection pool
    .build());

gh.permissionCatalog().addService("workspace", null);
gh.permissionCatalog().addResource("workspace", "projects", null);
gh.permissionCatalog().addAction("workspace", "projects", "read", null);
gh.roleManager().createRole("project-reader", "Project reader", null);
gh.roleManager().grantPermission("project-reader", "workspace", "projects", "read");
gh.membershipManager().createMembership("alice", "acme", EntityType.USER);
gh.roleManager().assignToIdentity("alice", "acme", "project-reader");

gh.hasPermission("alice", "acme", "workspace", "projects", "read");   // true
```

Python and Rust versions: [Getting started](docs/guide/01-getting-started.md).

## Documentation

| Document | Content |
|---|---|
| [User guide](docs/guide/README.md) | behaviour and usage of every feature |
| [SKILLS.md](SKILLS.md) | API reference: names across the three SDKs, defaults, errors |
| [docs/MODEL.md](docs/MODEL.md) | authorization model, design decisions, compatibility notes |
