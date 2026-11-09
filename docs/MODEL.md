# Gatedhouse authorization model

The model, the reasons behind it, and compatibility notes. Applies to all
three SDKs. Usage: [user guide](guide/README.md).

## Concepts

| Concept | Scope | Is | Is not |
|---|---|---|---|
| Permission catalog | global | the defined vocabulary `service → resource → action`; foreign keys reject grants of undefined permissions | a grant of anything |
| Role | global | a capability of the platform (`policy-editor`) | a job title |
| Group | per org | a title or team in one org (`acme/brokers`) | shared across orgs |
| Membership | per org | the gate: an identity's presence in an org, with a status | a grant |

A resource is a resource **type** (`policy`, `quote`). Gatedhouse does not
grant access to individual records ("policy #123"); hosts check record
ownership themselves.

Roles are global because platform functionality is the same for every tenant;
groups are per org because titles differ between tenants. Per-org variation
comes from which roles a group holds, never from a role meaning different
things in different orgs. Use direct assignments only for one-person
exceptions.

## Decision rule

```
allowed(identity, org, s, r, a) =
      membership(identity, org).status = ACTIVE
  AND some role in closure(direct roles(identity, org) ∪ roles of groups(identity, org))
      holds a grant matching (s, r, a)
```

`closure` adds all ancestors via inheritance; a grant matches when each part
is `null` or equal. Properties:

- **Additive.** No deny rules; removing a permission means removing every path
  that grants it.
- **Org-isolated.** Nothing held in one org affects another.
- **Gated.** Without an `ACTIVE` membership no grant counts.

## Membership lifecycle

| Status | Grants | Meaning |
|---|---|---|
| `PENDING` | kept, ignored | invited / being provisioned |
| `ACTIVE` | apply | member |
| `SUSPENDED` | kept, ignored | temporarily barred; reactivation restores everything |
| `REMOVED` | revoked | left the org; row kept as history |

- Removal revokes direct role assignments and group memberships in that org,
  in the same transaction; other orgs are unaffected.
- Revival (`createMembership`, or `setStatus` to `ACTIVE`/`PENDING`) clears
  grants left in the org first, so no pre-removal access returns.
- `REMOVED → SUSPENDED` is rejected: nothing to pause.
- No delete operation; history stays in the live table.

Grants are rows deleted on revocation; the audit trigger records each delete
with the old row. No foreign key ties grants to memberships: grants come from
independent writers (admin actions, group sources) without ordering
guarantees, and the lifecycle clears them at removal and revival instead. A
grant committed after a removal is inert while removed and is cleared on
revival; a grant written concurrently with a revival is indistinguishable
from one made just after it.

## Entity type

`USER` / `AGENT` per membership. Not read by the check today. Reserved for a
check that the authentication layer's `person_type` matches
(`human` ↔ `USER`, `agent` ↔ `AGENT`), so an agent cannot use permissions
granted to it as a human.

## Roles

One definition per role, shared by all orgs: editing or deleting a role
affects every org, so roles belong to the platform owner. Deletion cascades to
every assignment in every org. Planned extension (not implemented): per-org
roles inheriting from global ones, as an additive migration.

## Explanations

`explainPermission` returns the outcome and every granting path, including
for denials (for a suspended member: what reactivation restores; for no
membership: inert leftover grants). It always reads the database and bypasses
the cache; it is a diagnostic, not for hot request paths.

## Compatibility

Changes in the release after 0.3.0 (all breaking changes are bundled):

- Schema version 2 adds the `removed` status. Migrate before deploying. A
  schema-1 release cannot read a `REMOVED` membership: upgrade all services
  sharing a database together.
- `deleteMembership` is removed; use `removeMembership`.
- URL mode runs a Gatedhouse-owned pool with an optional dependency: Java
  `Database.fromUrl` returns `PooledDatabase` (needs HikariCP); Python
  `Database.from_uri` returns `PooledDatabase` (needs `gatedhouse[pool]`);
  Rust `ConninfoDatabase` is replaced by `PooledDatabase::from_url` (feature
  `r2d2`). The Rust `Database` trait returns `PooledClient` and a boxed error;
  `GatedhouseError::Database` has a `kind`. See
  [guide ch. 3](guide/03-connecting.md).
- `addParentRole` rejects cycles. Existing cycles are not removed; evaluation
  tolerates them.
- Filters: 401 bodies carry a `reason` code and fixed `detail`; IdP outages
  are 503 with `Retry-After`; session filters keep the session on outages.
  Rust `FilterError::Unauthorized` is a struct variant; `FilterError` and
  `WebFilterOutcome` gain `Unavailable`.
- Rust token verification no longer allows 60 s of clock skew.
- Smoke tests are no longer shipped (`gatedhouse-smoketest` script and
  `gatedhouse-smoke-test` binary removed).

## Decision log

| # | Decision | Reason |
|---|---|---|
| D1 | Memberships are never deleted; `REMOVED` revokes grants in the org; revival clears them again | Keeps history in the live table; a delete that kept grants would duplicate `SUSPENDED` and let old access return on rejoin |
| D2 | Grants are hard-deleted; the audit trigger is their history | Temporal rows would add a validity filter to every query for questions the audit log answers |
| D3 | No foreign key from grants to memberships | Independent writers without ordering; a constraint turns races into failures |
| D4 | Entity type is a per-membership label | No identity registry; reserved for an authentication/authorization consistency check |
| D5 | Roles are global templates | The platform owns its capabilities; per-org roles would make a role's meaning org-dependent |
| D6 | Roles = platform capabilities; groups = per-org titles | Tenants compose the same capabilities differently without forking roles |
| D7 | Explanations include all paths, also for denials | Removing an additive permission requires seeing every path |
| D8 | Inheritance is acyclic, enforced under an advisory lock shared by all SDKs | A cycle makes its roles equivalent; without the lock two concurrent edits can each pass the check |

Deferred: erasure of an identity's personal data (including the audit log);
archiving instead of deleting roles and groups; entity-type enforcement.
