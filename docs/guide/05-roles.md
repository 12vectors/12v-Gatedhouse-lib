# 5. Roles

Operations on `gh.roleManager()`.

## Definitions

| Operation | Behaviour |
|---|---|
| `createRole(key, name, description)` | key unique; duplicate → `QUERY` error |
| `deleteRole(key)` | deletes the role, its grants, its inheritance edges (both directions) and all its assignments to identities and groups in every org; built-in roles are left unchanged |
| `hasRole(key)`, `listRoles()` | |

Built-in role: `gatedhouse:owner`, grant `(null, null, null)`, cannot be
deleted. `assignToIdentity(id, org, "gatedhouse:owner")` gives full access in
that org. New built-in roles require direct SQL (`is_system = TRUE`).

## Grants

```java
roles.grantPermission("billing-auditor", "billing", null, "read");   // null = any resource
roles.revokePermission("billing-auditor", "billing", null, "read");
```

- Each named part must exist in the catalog (`QUERY` error otherwise), except
  that parts below a wildcard are not validated: in `(billing, null, read)`
  the action `read` is not checked.
- Duplicate grant → `QUERY` error.
- `revokePermission` removes the exactly matching grant (wildcards compared
  as values); a missing grant → no-op.
- Wildcard grants cover catalog entries added later.

## Inheritance

| Operation | Behaviour |
|---|---|
| `addParentRole(child, parent)` | child gains all of parent's permissions, transitively; multiple parents allowed; duplicate edge → `QUERY` error |
| `removeParentRole(child, parent)` | |
| `getParentRoles(child)` | direct parents only |

Cycles are rejected: if `parent` already inherits from `child`, the call fails
with Java `IllegalArgumentException`, Python `ValueError`, Rust
`GatedhouseError::InvalidArgument`. The check and insert run under an advisory
lock shared by all SDKs. `addParentRole(r, r)` → `QUERY` error (check
constraint).

## Assignments

| Operation | Behaviour |
|---|---|
| `assignToIdentity(id, org, role)` | role must exist; duplicate → `QUERY` error; allowed without a membership, effective only while the membership is `ACTIVE`; revoked by membership removal |
| `revokeFromIdentity(id, org, role)` | |
| `getIdentityRoles(id, org)` | direct assignments only |
| `assignToGroup(group, org, role)` | group must exist in the org; applies to all current and future members |
| `revokeFromGroup(group, org, role)`, `getGroupRoles(group, org)` | |

## Cache effect

Identity assignment changes invalidate that `(identity, org)` cache entry.
Grants, inheritance, group-role changes and role deletion invalidate the whole
cache (same process only, [ch. 9](09-caching.md)).
