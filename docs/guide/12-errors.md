# 12. Errors

A failed permission check grants nothing: on any error, deny.

## Database errors

Java `GatedhouseDatabaseException`, Python `GatedhouseDatabaseError`, Rust
`GatedhouseError::Database { kind, message }` (`database_kind()`).

| Kind | Causes | HTTP |
|---|---|---|
| `UNAVAILABLE` | pool timeout, database unreachable or shutting down, connection lost, statement timeout (57014), insufficient resources (class 53) | 503 |
| `QUERY` | statement refused: duplicate (23505), unknown referenced entity (23503), check constraint (23514), other | 409 / 400 / 500 |

```java
catch (GatedhouseDatabaseException e) {
    if (e.kind() == GatedhouseDatabaseException.Kind.UNAVAILABLE) return serviceUnavailable();
    throw e;
}
```

The SQLSTATE is available from the underlying error: Java
`((SQLException) e.getCause()).getSQLState()`, Python
`e.__cause__.sqlstate` (e.g. `psycopg.errors.UniqueViolation`), Rust in the
message as `(23505)`.

## Other errors

| Situation | Java | Python | Rust |
|---|---|---|---|
| inheritance cycle | `IllegalArgumentException` | `ValueError` | `InvalidArgument` |
| suspend a removed membership | `IllegalStateException` | `ValueError` | `InvalidTransition` |
| connection inside caller's transaction | `IllegalStateException` | `RuntimeError` | n/a |
| schema missing | `SchemaNotInitializedException` | `SchemaNotInitializedError` | `SchemaNotInitialized` |
| schema older than library | `SchemaOutOfDateException` | `SchemaOutOfDateError` | `SchemaOutOfDate { current_version, expected_version }` |
| database unreachable at startup / migration failure | `GatedhouseInitializationException` (cause: database error) | `GatedhouseInitializationError` (`__cause__`) | `Database { kind, .. }` |
| group source `start` failed | `GatedhouseInitializationException` | `GatedhouseInitializationError` | n/a |
| token rejected | `TokenVerificationException` | `TokenVerificationException` | `TokenVerificationError` |
| Sphinx call failed | `SphinxException` | `SphinxError` | `SphinxError` |
| URL mode without its dependency | `IllegalStateException` | `ImportError` | compile error |
| invalid pool or cache settings | `IllegalArgumentException` | `ValueError` | panic |
| `from_pool` with an async/unknown pool | | `TypeError` | |
| `verifyToken` without a verifier | `IllegalStateException` | `RuntimeError` | `TokenVerificationError` (`OTHER`) |
| database method on a verify-only instance | `UnsupportedOperationException` | `NotImplementedError` | panic |
| invalid connection string (URL mode) | driver error at first use | psycopg error at first use | `Initialization` |

Rust variants are of `GatedhouseError` unless stated. Python's schema errors
subclass `GatedhouseInitializationError`; Java's are separate types. All
Python errors except the built-in ones (`ValueError`, ...) subclass
`GatedhouseError`. `SphinxException`/`SphinxError` also subclass
`RuntimeException`/`RuntimeError`.

## HTTP mapping

| Error | HTTP |
|---|---|
| database `UNAVAILABLE`, `JWKS_UNAVAILABLE`, Sphinx `TIMEOUT`/`TRANSPORT` | 503 |
| other token verification failures | 401 |
| permission denied, `ForbiddenException` | 403 |
| duplicate on create | 409 |
| cycle, invalid transition, unknown referenced entity (admin APIs) | 400 / 422 |
| other | 500 |
