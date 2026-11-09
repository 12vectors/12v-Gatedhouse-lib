# 13. Operations

## Schema

All objects are in schema `gatedhouse`. Current version: **2**
(1: base schema and `gatedhouse:owner`; 2: `REMOVED` membership status).

| Table | Scope | Key / content |
|---|---|---|
| `services`, `resources`, `actions` | global | catalog; composite keys `(service[, resource[, action]])` |
| `roles` | global | `key`, `name`, `description`, `is_system` |
| `role_permissions` | global | `(role_key, service, resource, action)`; nullable parts = wildcards; unique per role |
| `role_inherits` | global | `(child_key, parent_key)`, `child <> parent` |
| `memberships` | per org | unique `(identity_id, org_id)`, `entity_type`, `status` |
| `role_assignments` | per org | unique `(identity_id, org_id, role_key)` |
| `groups` | per org | key `(id, org_id)`, `name`, `description` |
| `group_memberships`, `group_roles` | per org | `(group_id, org_id, identity_id)`, `(group_id, org_id, role_key)` |
| `audit_log` | | change history (below) |
| `schema_versions` | | applied migrations |

Foreign keys cascade on delete (catalog → grants; roles → grants,
inheritance, assignments; groups → members, group roles). There is no
foreign key from grants to memberships. Library-generated keys are UUIDs;
identity, org and group IDs are host-supplied text. All lookups used by
checks are indexed.

## Migrations

- Run only on request (CLI or `GatedhouseFactory.migrate`).
- Each version applies once in its own transaction; recorded in
  `schema_versions` with a SHA-256 checksum (recorded, not verified later).
- Serialized by a PostgreSQL advisory lock: concurrent runs are safe; later
  runs wait, then find nothing to do.
- Privileges: `CREATE` on the database and on the schema. Run from a deploy
  step with a dedicated role, not the application user.
- `create` fails if the schema is missing or older than the library.

Upgrade order: read [MODEL.md compatibility notes](../MODEL.md#compatibility),
migrate, deploy. Services sharing a database must run compatible versions
(e.g. a schema-1 release cannot read `REMOVED` memberships).

## Audit log

A trigger on every Gatedhouse table except `audit_log` and `schema_versions`
records every insert, update and delete, including direct SQL:

| Column | Content |
|---|---|
| `id` | sequence |
| `table_name` | e.g. `gatedhouse.role_assignments` |
| `op` | `INSERT`, `UPDATE`, `DELETE` |
| `old_row`, `new_row` | JSONB; `NULL` for insert / delete respectively |
| `changed_at` | timestamp |
| `changed_by` | value of setting `gatedhouse.actor`, else `NULL` |

```sql
SELECT op, coalesce(new_row, old_row)->>'role_key' AS role, changed_at, changed_by
FROM gatedhouse.audit_log
WHERE table_name = 'gatedhouse.role_assignments'
  AND coalesce(new_row, old_row)->>'org_id' = 'acme'
ORDER BY changed_at;
```

Actor attribution: library writes run in their own transactions, so the actor
cannot be set per request (planned, issue #9). A per-role default works:
`ALTER ROLE billing_service SET gatedhouse.actor = 'billing-service'`. Direct
SQL can use `SET LOCAL gatedhouse.actor = '...'`.

Permission checks are not logged; log decisions in the application if
required. The table only grows; plan archiving or partitioning.

## Production checklist

- Migrations run as a deploy step with a dedicated role.
- Gatedhouse uses the application's pool, sized for checks; statement timeout
  set on the pool or role.
- One shared instance per process.
- Cache off, or TTL chosen as the tolerated revocation delay.
- `UNAVAILABLE` and `JWKS_UNAVAILABLE` → 503; no error path allows access.
- Token verifier issuer/audience correct; JWKS reachable.
- `hasPermission` called only with authenticated identities.
- Holders of `gatedhouse:owner` and wildcard roles reviewed.
- All services sharing the database on compatible versions.

## Monitoring

Gatedhouse does not log; it reports through return values and errors.

| Signal | Source | Indicates |
|---|---|---|
| `UNAVAILABLE` rate | error handling | pool exhaustion, database trouble, slow queries |
| pool waiters / active connections | HikariCP MXBean, `psycopg_pool.get_stats()`, `r2d2` `state()` | undersized pool |
| cache hits, misses, evictions | `InMemoryPermissionCache` counters | TTL or bound mis-sized |
| `JWKS_UNAVAILABLE` | verification errors | IdP unreachable |
| `UNKNOWN_KEY`, `INVALID_SIGNATURE` bursts | verification errors | forged tokens |

## Testing

Test against PostgreSQL (evaluation is in SQL). `explainPermission` lets
tests assert the granting path, not only the outcome.

Smoke test (122 checks; creates and deletes `smoketest*` fixtures; not
shipped in packages), from each SDK directory:

| SDK | Command |
|---|---|
| Java | `mvn test-compile dependency:build-classpath -Dmdep.outputFile=cp.txt` then `java -cp "target/classes:target/test-classes:$(cat cp.txt)" com.twelvevectors.gatedhouse.cli.SmokeTest <jdbc-url> <user> <password>` |
| Python | `python tests/smoke_test.py "<conninfo>"` (needs `gatedhouse[pool]`) |
| Rust | `cargo run --features r2d2 --example smoke_test -- "<conninfo>"` |

Library test suites read `GATEDHOUSE_TEST_JDBC_URL` (Java) or
`GATEDHOUSE_TEST_DATABASE_URL` (Python, Rust).
