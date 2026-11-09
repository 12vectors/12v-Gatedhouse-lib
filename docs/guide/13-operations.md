# 13. Operations

## Schema migrations

Gatedhouse keeps its tables in the `gatedhouse` schema and versions them.
The current schema version is **2**.

| Version | Adds |
|---|---|
| 1 | catalog, roles, grants, inheritance, memberships, groups, audit log, the `gatedhouse:owner` role |
| 2 | the `REMOVED` membership status |

How migrations behave:

- They run only when you ask (CLI or `GatedhouseFactory.migrate`), never at
  application startup.
- Each version is applied once, in its own transaction, and recorded in
  `gatedhouse.schema_versions` with its name and a SHA-256 checksum. The
  checksum is recorded for reference; it is not compared on later runs.
- A PostgreSQL advisory lock serializes concurrent runs, so several
  instances can run the migration at the same time safely.
- The migration user needs `CREATE` on the database (to create the schema);
  the application user needs only `USAGE` on the schema and read/write on its
  tables and sequences. Run migrations as part of a controlled deploy step,
  not as the application user.

**At startup**, `create` compares the database's version with the one the
library expects and refuses to start if it is older or missing.

### Upgrading

1. Read the release notes and the compatibility notes in
   [MODEL.md](../MODEL.md#compatibility).
2. Run the new version's migration against the database.
3. Deploy the new library version.

**Several services, one database.** When services built with different SDKs
(or different versions) share a database, upgrade them together: an older
library may not understand data that only a newer schema allows (for example,
a release built for schema 1 cannot read a `REMOVED` membership).

## The audit log

Every change to Gatedhouse's tables (catalog, roles, grants, inheritance,
memberships, groups, group members, group roles) is recorded by a database
trigger in `gatedhouse.audit_log`, including changes made directly in SQL:

| Column | Content |
|---|---|
| `id` | sequence number |
| `table_name` | e.g. `gatedhouse.role_assignments` |
| `op` | `INSERT`, `UPDATE` or `DELETE` |
| `old_row` | the row before the change, as JSON (`NULL` for inserts) |
| `new_row` | the row after the change, as JSON (`NULL` for deletes) |
| `changed_at` | timestamp |
| `changed_by` | the actor, if one was set (see below) |

Revoked grants are deleted from the live tables; their history lives here.

```sql
-- Who had which roles in acme, and when did that change?
SELECT op, coalesce(new_row, old_row) AS assignment, changed_at, changed_by
FROM gatedhouse.audit_log
WHERE table_name = 'gatedhouse.role_assignments'
  AND coalesce(new_row, old_row)->>'org_id' = 'acme'
ORDER BY changed_at;

-- Everything that happened to alice's membership in acme
SELECT op, old_row->>'status' AS before, new_row->>'status' AS after, changed_at
FROM gatedhouse.audit_log
WHERE table_name = 'gatedhouse.memberships'
  AND coalesce(new_row, old_row)->>'identity_id' = 'alice'
  AND coalesce(new_row, old_row)->>'org_id' = 'acme'
ORDER BY changed_at;
```

### Who made the change

The trigger fills `changed_by` from the PostgreSQL setting `gatedhouse.actor`.
Gatedhouse runs each change in its own transaction on a connection your code
doesn't see, so **you cannot currently set the actor per request** through the
library; per-request attribution is planned. What works today is a default
per database role, which attributes changes to the service that made them:

```sql
ALTER ROLE billing_service SET gatedhouse.actor = 'billing-service';
```

Record the human actor in your own application log alongside the change.

### What the audit log is not

It records **changes**, not **decisions**: permission checks are not logged.
If you need a record of every allow/deny, log it in your application at
decision time; that volume belongs in a log pipeline, not a database table.

The table grows with every change. Plan retention (periodic archiving or
partitioning) according to your compliance requirements.

## Production checklist

- [ ] Schema migrated as a deploy step, with a dedicated migration user.
- [ ] Gatedhouse uses your application's connection pool
      ([chapter 3](03-connecting.md)), and the pool is sized for permission
      checks too.
- [ ] A statement timeout is set on that pool or the database role.
- [ ] One Gatedhouse instance per process, shared by all threads.
- [ ] Caching decided deliberately: off, or a TTL you accept for revoked
      permissions in a multi-instance deployment ([chapter 9](09-caching.md)).
- [ ] `UNAVAILABLE` database errors and `JWKS_UNAVAILABLE` map to `503`, and
      nothing treats an error as "allowed" ([chapter 12](12-errors.md)).
- [ ] Token verifier configured with the right issuer and audience, and the
      JWKS URI reachable from production.
- [ ] Roles named after capabilities; per-org titles are groups
      ([chapter 2](02-concepts.md)).
- [ ] Holders of `gatedhouse:owner` and wildcard roles reviewed.
- [ ] Every service sharing the database runs a compatible library version.

## Monitoring

| Signal | Where | Watch for |
|---|---|---|
| database errors by kind | your error handling | spikes of `UNAVAILABLE` (pool exhaustion, database trouble, slow queries) |
| pool metrics | your pool (HikariCP MXBeans, `psycopg_pool` `get_stats()`, `r2d2` `state()`) | waiting threads, connections near the maximum |
| cache counters | `InMemoryPermissionCache` hit/miss/eviction counts | low hit rate (TTL too short), constant evictions (bound too small) |
| token failures by reason | your filter or error handling | `JWKS_UNAVAILABLE` (identity provider trouble), bursts of `UNKNOWN_KEY` or `INVALID_SIGNATURE` (forged tokens) |
| audit log growth | `gatedhouse.audit_log` | unexpected bulk changes |

Gatedhouse itself doesn't log; it reports through return values and
exceptions, so your application decides what to record.

## Testing

**Against a real database.** The behaviour that matters (inheritance,
wildcards, membership states) lives in SQL, so test against PostgreSQL rather
than a mock. A disposable database per test run works well; run the migration
first.

**Smoke test.** Each SDK has an end-to-end smoke test (122 checks covering the
catalog, roles, inheritance, wildcards, groups, the membership lifecycle,
explanations and caching). It creates and deletes `smoketest`-prefixed
fixtures, so it is a development tool and is not shipped in the packages. Run
it from a checkout against a development database:

| SDK | Command, from the SDK's directory |
|---|---|
| Java | `mvn test-compile dependency:build-classpath -Dmdep.outputFile=cp.txt`, then `java -cp "target/classes:target/test-classes:$(cat cp.txt)" com.twelvevectors.gatedhouse.cli.SmokeTest <jdbc-url> <user> <password>` |
| Python | `python tests/smoke_test.py "<conninfo>"` (needs `gatedhouse[pool]`) |
| Rust | `cargo run --features r2d2 --example smoke_test -- "<conninfo>"` |

**The library's own test suites** need a database URL to run their database
tests: `GATEDHOUSE_TEST_JDBC_URL` (Java, a JDBC URL with credentials) or
`GATEDHOUSE_TEST_DATABASE_URL` (Python and Rust); CI runs all of them against
PostgreSQL 16.

**In your tests**, `explainPermission` makes assertions readable: assert the
outcome *and* the path you expect, so a test fails if access starts arriving
by an unintended route.
