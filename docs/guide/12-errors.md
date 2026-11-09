# 12. Errors

Gatedhouse reports failures through a small set of types. This chapter lists
all of them, what triggers each, and how to respond, including the HTTP
status an API would normally return.

## The rule that matters most

**A failed permission check grants nothing.** If `hasPermission` throws or
returns an error, the answer is "deny". When the cause is a database or
identity-provider outage, tell the client to retry (`503`); never fall back
to "allowed".

## Database errors

Every operation that touches the database reports failures as one type:

| Java | Python | Rust |
|---|---|---|
| `GatedhouseDatabaseException` | `GatedhouseDatabaseError` | `GatedhouseError::Database { kind, message }` |

Each carries a **kind**:

| Kind | Meaning | Typical causes | Respond with |
|---|---|---|---|
| `UNAVAILABLE` | no usable connection, or the database couldn't do the work right now | pool timeout (pool exhausted), database unreachable or restarting, connection lost, statement timeout, database out of resources | `503`, retry later |
| `QUERY` | the database refused the statement | a duplicate, an unknown role, group or catalog entry, a role inheriting from itself | depends on the operation, usually `409` or `400` for admin APIs |

```java
try {
    allowed = gh.hasPermission(id, org, "billing", "invoices", "refund");
} catch (GatedhouseDatabaseException e) {
    if (e.kind() == GatedhouseDatabaseException.Kind.UNAVAILABLE) {
        return serviceUnavailable();      // 503
    }
    throw e;                              // a bug or data problem: 500
}
```

```python
try:
    allowed = gh.has_permission(id, org, "billing", "invoices", "refund")
except GatedhouseDatabaseError as e:
    if e.kind is GatedhouseDatabaseError.Kind.UNAVAILABLE:
        return service_unavailable()
    raise
```

```rust
match gh.has_permission(id, org, "billing", "invoices", "refund") {
    Ok(allowed) => { /* ... */ }
    Err(e) if e.database_kind() == Some(DatabaseErrorKind::Unavailable) => { /* 503 */ }
    Err(e) => return Err(e.into()),
}
```

### Recognizing duplicates and other refusals

Creating something that already exists (a service, role, group, membership,
assignment or grant) is a `QUERY` error caused by a unique violation,
PostgreSQL SQLSTATE `23505`. Until dedicated error types exist, recognize it
through the underlying error:

| SDK | How |
|---|---|
| Java | `e.getCause() instanceof SQLException s && "23505".equals(s.getSQLState())` |
| Python | `isinstance(e.__cause__, psycopg.errors.UniqueViolation)` |
| Rust | the message contains `(23505)` |

Other useful states: `23503` (foreign key: an unknown role, group or catalog
entry) and `23514` (check constraint, e.g. a role inheriting from itself).
For idempotent setup code, checking first (`hasRole`, `hasGroup`, ...) is
usually simpler.

## Errors that mean "you can't do that"

| Situation | Java | Python | Rust |
|---|---|---|---|
| role inheritance would create a cycle | `IllegalArgumentException` | `ValueError` | `GatedhouseError::InvalidArgument` |
| suspending a removed membership | `IllegalStateException` | `ValueError` | `GatedhouseError::InvalidTransition` |
| a borrowed connection is inside your own transaction | `IllegalStateException` | `RuntimeError` | (cannot happen) |

These are programming errors: fix the calling code rather than retrying.

## Startup and migration errors

| Situation | Java | Python | Rust |
|---|---|---|---|
| schema never migrated | `SchemaNotInitializedException` | `SchemaNotInitializedError` | `GatedhouseError::SchemaNotInitialized` |
| schema older than the library | `SchemaOutOfDateException` | `SchemaOutOfDateError` | `GatedhouseError::SchemaOutOfDate { current_version, expected_version }` |
| database unreachable at startup, or a migration failed | `GatedhouseInitializationException` (the cause holds the database error and its kind) | `GatedhouseInitializationError` (same, as `__cause__`) | the database error itself (`GatedhouseError::Database`, with its kind) |
| a group source's `start` failed | `GatedhouseInitializationException` | `GatedhouseInitializationError` | (Rust's `start` cannot fail) |

The schema errors' messages include the exact migration command. Fail the
deployment on any of these; don't serve traffic.

In Python, `SchemaNotInitializedError` and `SchemaOutOfDateError` are
subclasses of `GatedhouseInitializationError`; in Java they are separate
exception types.

## Token verification errors

`TokenVerificationException` (Java, Python) / `TokenVerificationError`
(Rust), with one of nine reasons. See
[chapter 10](10-authentication.md#why-verification-failed). Respond `401` for
everything except `JWKS_UNAVAILABLE`, which is `503`.

## Sphinx client errors

`SphinxException` (Java) / `SphinxError` (Python, Rust), with a kind:
`TIMEOUT`, `TRANSPORT`, `HTTP_STATUS` (with the status code) or
`INVALID_RESPONSE`. See [chapter 11](11-web.md#timeouts-and-errors). They are
also `RuntimeException` (Java) / `RuntimeError` (Python), so older generic
handlers still catch them.

## Configuration errors

| Situation | Java | Python | Rust |
|---|---|---|---|
| URL-mode pool without its optional dependency | `IllegalStateException` naming HikariCP | `ImportError` naming `gatedhouse[pool]` | compile error |
| invalid pool or cache settings | `IllegalArgumentException` | `ValueError` | panic |
| `from_pool` given an async or unknown pool | n/a | `TypeError` | n/a |
| `verifyToken` without a token verifier | `IllegalStateException` | `RuntimeError` | `TokenVerificationError` with reason `OTHER` |
| a database method on a verify-only instance | `UnsupportedOperationException` | `NotImplementedError` | panic |
| invalid connection string (URL mode) | from the driver, at first use | from psycopg, at first use | `GatedhouseError::Initialization` |

## Status codes at a glance

| Error | HTTP |
|---|---|
| database `UNAVAILABLE`, `JWKS_UNAVAILABLE`, Sphinx `TIMEOUT` / `TRANSPORT` | `503` |
| token verification failure (other reasons) | `401` |
| permission check returned false, `ForbiddenException` | `403` |
| duplicate on create | `409` |
| cycle, invalid transition, unknown role or catalog entry in an admin request | `400` or `422` |
| everything else | `500` |
