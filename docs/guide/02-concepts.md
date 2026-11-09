# 2. Concepts

| Entity | Scope | Definition |
|---|---|---|
| Permission | global | `(service, resource, action)`, three separate strings, registered in the catalog |
| Role | global | named set of permission grants; may inherit other roles |
| Membership | per org | `(identity, org)` with a status; gates all access in the org |
| Group | per org | set of identities in one org; holds roles for its members |
| Role assignment | per org | role given directly to one identity in one org |

Identity and org IDs are opaque strings supplied by the host; Gatedhouse has
no identity table and validates neither.

## Decision rule

`hasPermission(identity, org, service, resource, action)` is true iff:

1. a membership `(identity, org)` exists with status `ACTIVE`, and
2. some role of the identity in that org grants a matching permission. The
   identity's roles are: direct assignments in the org, roles of its groups in
   the org, and all roles those inherit, transitively.

A grant matches when each part equals the checked value or is `null`
(wildcard). There are no deny rules. Checks take concrete values only.

## Wildcards

| Grant | Matches |
|---|---|
| `(billing, invoices, read)` | that permission |
| `(billing, null, read)` | `read` on every resource of `billing`, including ones added later |
| `(billing, null, null)` | all of `billing` |
| `(null, null, null)` | everything |

## Membership statuses

| Status | Checks | Grants in the org |
|---|---|---|
| `ACTIVE` | evaluated | apply |
| `PENDING` | deny | kept, ignored |
| `SUSPENDED` | deny | kept, ignored; restored on reactivation |
| `REMOVED` | deny | revoked on removal |

## Modelling convention

Roles are global, so name them after a platform capability
(`policy-editor`), never a job title. Groups are per org, so titles
(`admins`, `brokers`) are groups; per-org differences come from which roles a
group holds. Use direct assignments only for one-person exceptions.

## Example

```
Roles   policy-viewer  grants (policies, policy, view)
        policy-editor  grants (policies, policy, edit); inherits policy-viewer
        policy-binder  grants (policies, policy, bind)
acme    group brokers holds policy-viewer;  alice ACTIVE, in brokers, assigned policy-binder
beacon  group brokers holds policy-editor;  alice SUSPENDED, in brokers
```

| Check | Result | Reason |
|---|---|---|
| alice, acme, view | allow | brokers → policy-viewer |
| alice, acme, edit | deny | acme's brokers hold only policy-viewer |
| alice, acme, bind | allow | direct assignment |
| alice, beacon, view | deny | membership suspended |

Design rationale: [MODEL.md](../MODEL.md).
