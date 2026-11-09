# 8. Checking access

| Operation | Returns | Uses cache |
|---|---|---|
| `hasPermission(id, org, service, resource, action)` | boolean | yes |
| `getEffectivePermissions(id, org)` | all grants effective for the identity in the org, as stored (wildcard parts `null`); empty unless the membership is `ACTIVE` | yes |
| `getRoles(id, org)` | direct role assignments only | no |
| `getGroups(id, org)` | direct group memberships | no |
| `explainPermission(id, org, service, resource, action)` | decision and all granting paths | no |

## hasPermission

- The identity must come from an authenticated source (e.g. a verified
  token's `sub`); Gatedhouse cannot detect a forged identity.
- Unknown identities, orgs or permissions return `false`.
- Gatedhouse does not check that a resource instance belongs to the org;
  the host must.
- On error (e.g. database unavailable) the call fails. Treat it as deny
  (typically HTTP 503), never allow.
- Cost: one indexed query per cache miss; none on a hit.

## explainPermission

```java
PermissionExplanation why = gh.explainPermission("alice", "acme", "billing", "invoices", "refund");
```

| Field | Java | Python | Rust |
|---|---|---|---|
| outcome | `outcome()` | `outcome` | `outcome` |
| equals `hasPermission` | `allowed()` | `allowed` (property) | `allowed()` |
| membership status, or null | `membershipStatus()` | `membership_status` | `membership_status` |
| granting paths | `paths()` | `paths` | `paths` |

| Outcome | Meaning | Paths |
|---|---|---|
| `ALLOWED` | active membership, ≥1 path | all granting paths |
| `NO_MEMBERSHIP` | no membership | grants prepared for the identity (inert) |
| `MEMBERSHIP_NOT_ACTIVE` | `PENDING`, `SUSPENDED` or `REMOVED` | paths that would apply if active |
| `NO_MATCHING_GRANT` | active, nothing grants it | none |

Each `GrantPath` has `source` (`DIRECT` or `GROUP`), `groupId` (for `GROUP`),
`roleChain` (assigned role first, then up the inheritance chain to the role
holding the grant), `grant` (the matching grant), and helpers
`assignedRole` / `grantingRole` (first and last of the chain).

```
GROUP  brokers  [policy-editor, policy-viewer]  (policies, policy, view)
```

reads: in group `brokers`, which holds `policy-editor`, which inherits
`policy-viewer`, which grants view.

Paths are ordered direct first, then by group, then by chain length. Status
and paths come from one database snapshot. It always queries the database
(no cache): use it for diagnostics, not on hot request paths.

## Diagnosing an unexpected deny

`explainPermission` gives the answer in one call: `NO_MEMBERSHIP` or
`MEMBERSHIP_NOT_ACTIVE` points to the membership, `NO_MATCHING_GRANT` to
missing roles or grants. If paths exist but the result is still unexpected,
check the catalog spelling of the checked permission.
