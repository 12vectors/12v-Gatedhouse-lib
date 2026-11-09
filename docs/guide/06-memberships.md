# 6. Memberships

Operations on `gh.membershipManager()`. A membership `(identity, org)` must be
`ACTIVE` for any permission in that org to apply.

| Operation | Behaviour |
|---|---|
| `createMembership(id, org, entityType)` | creates as `ACTIVE`; existing non-removed membership → `QUERY` error; on a `REMOVED` membership: revives it (see below) |
| `setStatus(id, org, status)` | no membership → no-op; `REMOVED` → same as `removeMembership` |
| `removeMembership(id, org)` | status `REMOVED`; in the same transaction revokes the identity's direct roles and group memberships in that org; no membership → clears grants prepared in that org |
| `getStatus(id, org)` | status, or empty if none; `REMOVED` for removed |
| `hasMembership(id, org)` | false for `REMOVED` |
| `getEntityType(id, org)` | `USER` or `AGENT` |

To create a `PENDING` membership: `createMembership`, then
`setStatus(..., PENDING)`.

## Status transitions

```
PENDING ⇄ ACTIVE ⇄ SUSPENDED      any of them → REMOVED
REMOVED → ACTIVE or PENDING       (createMembership or setStatus; clean slate)
REMOVED → SUSPENDED               rejected
```

- Suspension blocks all access in the org with one change; reactivation
  restores all grants.
- Removal revokes grants. Revival clears any grants left in the org first, so
  nothing from before the removal returns. A grant written concurrently with
  a revival may survive it (indistinguishable from one made just after).
- `REMOVED → SUSPENDED` fails: Java `IllegalStateException`, Python
  `ValueError`, Rust `GatedhouseError::InvalidTransition`.
- Memberships are never deleted; there is no delete operation.
- Each transition runs in one transaction holding a row lock on the
  membership; concurrent transitions serialize.

## Entity type

`USER` or `AGENT`, stored per membership. Not used by the permission check
today. A planned check will compare it with the token's `person_type`
(`human` ↔ `USER`, `agent` ↔ `AGENT`), so set it accurately.

## Grants without a membership

Role assignments and group memberships are accepted for identities with no
membership (for example during invitation) and are inert until the
membership is `ACTIVE`. No foreign key enforces membership, so out-of-order
writes from external sources succeed.
