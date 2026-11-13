# Gatedhouse API reference

Names across the three SDKs. Behaviour: [User guide](docs/guide/README.md).
Design: [docs/MODEL.md](docs/MODEL.md).

| SDK | Source | Package |
|---|---|---|
| Java (reference) | [`sdk-java/`](sdk-java/) | `com.twelvevectors.gatedhouse` |
| Python | [`sdk-python/`](sdk-python/) | `gatedhouse` (ASGI: `gatedhouse.asgi`) |
| Rust | [`sdk-rust/`](sdk-rust/) | `gatedhouse` |

Conventions: Python and Rust use the snake_case form of each Java name. Rust
takes `Option<&str>` for optional text, returns `Result`, and uses
`CamelCase` enum variants (`MembershipStatus::Active`). Java returns
`Optional<T>` / `List<T>`; Python `T | None` / `list`; Rust `Option<T>` /
`Vec<T>`. Method prefixes: `add/remove` (catalog), `create/delete` (roles,
groups, memberships), `grant/revoke` (role permissions), `assign/revokeFrom`
(role assignments), `has` (existence), `list/get` (reads).

## Construction

| Java | Python | Rust |
|---|---|---|
| `GatedhouseConfig.builder().database(db).permissionCache(c).tokenVerifier(t).groupSource(g).build()` | `GatedhouseConfig(database=db, permission_cache=c, token_verifier=t, group_source=g)` | `GatedhouseConfig::builder(db).permission_cache(c).token_verifier(t).group_source(g).build()` |
| `GatedhouseFactory.create(config)` | `GatedhouseFactory.create(config)` | `GatedhouseFactory::create(config)?` → `Arc<dyn Gatedhouse>` |
| `GatedhouseFactory.migrate(config)` | `GatedhouseFactory.migrate(config)` | `GatedhouseFactory::migrate(&config)?` |
| `GatedhouseFactory.createJustTokenVerifier(t)` | `create_just_token_verifier(t)` | `create_just_token_verifier(t)` |
| `gh.close()` / try-with-resources | `gh.close()` / `with` | drop |
| `Database.fromDataSource(ds)` | `Database.from_pool(pool)` | `Arc::new(r2d2_pool)` (feature `r2d2`), `from_fn(closure)` |
| `Database.fromUrl(url, user, pwd[, PooledDatabase.Settings])` → `PooledDatabase` | `Database.from_uri(conninfo, **settings)` → `PooledDatabase` | `PooledDatabase::from_url(conninfo)?`, `from_url_with(conninfo, PoolSettings)?`, `from_url_with_tls(conninfo, tls, settings)?` |
| `Database` (lambda returning `Connection`) | `Database` subclass; `connection()` returns a context manager | `Database` trait; `connection()` returns `PooledClient`; `OwnedClient(Client)` |
| CLI `com.twelvevectors.gatedhouse.cli.Migrate <url> <user> <pwd>` | `gatedhouse-migrate <conninfo>` | `gatedhouse-migrate <conninfo>` |

## Operations

| On | Java names |
|---|---|
| `gh` (checks) | `hasPermission(id, org, svc, res, act)`, `getEffectivePermissions(id, org)`, `explainPermission(id, org, svc, res, act)`, `getRoles(id, org)`, `getGroups(id, org)` |
| `gh` (cache) | `invalidateCache(id, org)`, `invalidateAllCache()`, `setCacheEnabled(bool)`, `isCacheEnabled()` |
| `gh` (auth) | `verifyToken(jwt)` |
| `permissionCatalog()` | `addService(s, desc)`, `addResource(s, r, desc)`, `addAction(s, r, a, desc)`, `removeService/Resource/Action`, `hasService/Resource/Action`, `listServices()`, `listResources(s)`, `listActions(s, r)` |
| `roleManager()` | `createRole(key, name, desc)`, `deleteRole`, `hasRole`, `listRoles`, `grantPermission(role, s, r, a)`, `revokePermission`, `addParentRole(child, parent)`, `removeParentRole`, `getParentRoles`, `assignToIdentity(id, org, role)`, `revokeFromIdentity`, `getIdentityRoles`, `assignToGroup(group, org, role)`, `revokeFromGroup`, `getGroupRoles` |
| `membershipManager()` | `createMembership(id, org, entityType)`, `removeMembership`, `hasMembership`, `setStatus(id, org, status)`, `getStatus`, `getEntityType` |
| `groupManager()` | `createGroup(group, org, name, desc)`, `deleteGroup`, `hasGroup`, `listGroups(org)`, `addIdentityToGroup(group, org, id)`, `removeIdentityFromGroup`, `getGroupMembers`, `getIdentityGroups(id, org)` |

Rust wildcard and optional-text arguments are `Option<&str>`:
`grant_permission(role, Some("svc"), None, Some("read"))`.

## Types

| Type | Members |
|---|---|
| `EntityType` | `USER`, `AGENT` |
| `MembershipStatus` | `ACTIVE`, `PENDING`, `SUSPENDED`, `REMOVED` |
| `EffectivePermission` | `service`, `resource`, `action` (null = wildcard) |
| `PermissionExplanation` | `outcome` (`ALLOWED`, `NO_MEMBERSHIP`, `MEMBERSHIP_NOT_ACTIVE`, `NO_MATCHING_GRANT`), `membershipStatus`, `paths`, `allowed` (Python: property) |
| `GrantPath` | `source` (`DIRECT`, `GROUP`), `groupId`, `roleChain`, `grant`, `assignedRole`, `grantingRole` |
| `AuthenticatedSubject` | `id`, `issuer`, `audience`, `issuedAt`, `expiresAt`, `tokenType`, `claims` |
| `GatedContext` | `personId`, `email`, `role`, `identityType`, `authMethod`, `mfaVerified`, `emailVerified`, `clientId`, `scope`, `delegationId`, `actorClaims`, `rawClaims`; `isAdmin()`, `isHuman()`, `isDelegated()`, `hasScope(s)`; `fromSubject(subject)` |
| `TokenVerifierConfig` | Java builder `jwksUri`, `issuer`, `audience`, `jwksTimeout`; Python `(jwks_uri, issuer, audience, jwks_timeout=)`; Rust `new(uri, iss, aud).with_jwks_timeout(d)` |
| `InMemoryPermissionCache` | Java `(ttl[, maxEntries])`; Python `(ttl, clock=None, *, max_entries=)`; Rust `new()`, `with_ttl`, `with_ttl_and_max_entries`; counters `hitCount`, `missCount`, `putCount`, `targetedInvalidationCount`, `wholesaleInvalidationCount`, `evictionCount`, `size`, `resetStats` |
| `PermissionCache` | `get`, `put`, `invalidate`, `invalidateAll`; Java adapter `JCachePermissionCache(Cache)` |
| `GroupSource` | `start(gatedhouse)`, `close()`; default `LocalGroupSource` |
| `TokenVerificationException` (Rust `TokenVerificationError`) | `reason`: `EXPIRED`, `NOT_YET_VALID`, `INVALID_SIGNATURE`, `INVALID_ISSUER`, `INVALID_AUDIENCE`, `MALFORMED`, `UNKNOWN_KEY`, `JWKS_UNAVAILABLE`, `OTHER`; Rust `reason.code()` |
| `GatedhouseDatabaseException` (Python `GatedhouseDatabaseError`, Rust `GatedhouseError::Database`) | `kind`: `UNAVAILABLE`, `QUERY` (Rust `database_kind()`) |
| `SphinxException` (Python/Rust `SphinxError`) | `kind`: `TIMEOUT`, `TRANSPORT`, `HTTP_STATUS`, `INVALID_RESPONSE` (Rust also `InvalidArgument`); `statusCode`; `errorCode` (Sphinx's `error` field) |
| `ProvisionedPerson` | `id`, `email`, `emailVerified`, `displayName`, `phone`, `phoneVerified`, `allowAutoLink`, `status`, `createdAt`, `passwordResetSent` |

All error types: [guide ch. 12](docs/guide/12-errors.md).

## Web

| Java | Python (WSGI; ASGI in `gatedhouse.asgi`) | Rust |
|---|---|---|
| `GatedhouseApiFilter(gh)` | `GatedhouseApiFilter(app, gh)` | `GatedhouseApiFilter::new(gh).authenticate(header)` → `Result<GatedContext, FilterError>` |
| `GatedhouseWebFilter(gh, loginPath, sessionTokenAttr)` | `GatedhouseWebFilter(app, gh, login_path=, session_token_attr=, session_environ_key=)`; ASGI `session_scope_key=` | `GatedhouseWebFilter::with_config(gh, login_path, attr).check(token, ctx_path)` → `WebFilterOutcome` |
| `getContext(req)`, `requireAdmin`, `requireHuman`, `requireScope(req, s)` | `get_context(environ or scope)`, `require_*` | `require_admin(&ctx)`, `require_human`, `require_scope(&ctx, s)` |
| `ForbiddenException`, `UnauthorizedException` | same names | `FilterError::{Forbidden, Unauthorized, Unavailable}` |
| `SphinxClient(baseUrl, clientId, secret[, timeout])` | `SphinxClient(url, id, secret, timeout=)` | `SphinxClient::new(url, id, secret).with_timeout(d)` |
| `exchangeCode`, `clientCredentials`, `tokenExchange`, `refreshToken`, `introspect`, `loginUrl`, `federatedLoginUrl` | snake_case | snake_case |
| `createPerson(NewPerson.builder(email).displayName(..).phone(..).emailVerified(b).allowAutoLink(b).build())` → `ProvisionedPerson` | `create_person(email, *, display_name=, phone=, email_verified=, allow_auto_link=)` → `ProvisionedPerson` | `create_person(&NewPerson::new(email).display_name(..).phone(..).email_verified(b).allow_auto_link(b))?` → `ProvisionedPerson` |

Constants: request attribute `com.twelvevectors.gatedhouse.context`, login
path `/auth/login`, session attribute `access_token`, `Retry-After` 30 s.

## Defaults

| Setting | Default |
|---|---|
| URL-mode pool: max size / connection wait / max lifetime / statement timeout | 10 / 10 s / 30 min / 30 s |
| URL-mode pool: no liveness check for connections used within | 0.5 s |
| `InMemoryPermissionCache` TTL / max entries | 60 s / 10,000 |
| JWKS fetch timeout / key lifetime / min interval between fetches | 5 s / 5 min / 30 s |
| `SphinxClient` timeout | 10 s |
| token clock-skew leeway | none |
| schema version | 2 |
