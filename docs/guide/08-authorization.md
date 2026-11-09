# 8. Checking and explaining access

## The permission check

```java
boolean allowed = gh.hasPermission("alice", "acme", "billing", "invoices", "refund");
```

```python
allowed = gh.has_permission("alice", "acme", "billing", "invoices", "refund")
```

```rust
let allowed = gh.has_permission("alice", "acme", "billing", "invoices", "refund")?;
```

It returns `true` exactly when the identity has an `ACTIVE` membership in the
org and one of its roles there (direct, through groups, or inherited) holds a
matching grant. The full rule is in [Concepts](02-concepts.md#how-a-decision-is-made).

Things to know:

- The identity and org are whatever **you** trust. Gatedhouse doesn't know
  who is calling; pass the identity you authenticated (for example the
  `sub` of a verified token, see [chapter 10](10-authentication.md)) and the
  org the request acts on.
- Checks always name one concrete action; there are no wildcards in checks.
- An unknown identity, org or permission simply yields `false`.
- **A failed check is never "allowed".** If the database cannot be reached
  the call fails with an error ([chapter 12](12-errors.md)); treat that as a
  denial (typically HTTP 503), never as permission.

### Where to check

Check at the point where your application decides, as close to the action as
practical:

```java
if (!gh.hasPermission(subject.id(), orgId, "billing", "invoices", "refund")) {
    return forbidden();     // 403
}
refundService.refund(invoiceId);
```

Keep org selection honest: take the org from the request (path, header or
token claim) and make sure the resource being acted on actually belongs to
that org. Gatedhouse answers "may Alice refund invoices in Acme?", not
"does invoice 42 belong to Acme?".

### Cost

Without a cache, one check is one database query, which resolves memberships,
groups, inheritance and wildcards in a single statement on indexed tables.
With the [permission cache](09-caching.md), repeated checks for the same
identity and org cost no query at all until the entry expires or is
invalidated.

## Listing what someone can do

```java
List<EffectivePermission> perms = gh.getEffectivePermissions("alice", "acme");
for (EffectivePermission p : perms) {
    System.out.println(p.service() + ":" + p.resource() + ":" + p.action());   // parts may be null
}
```

```python
for p in gh.get_effective_permissions("alice", "acme"):
    print(p.service, p.resource, p.action)   # parts may be None (wildcards)
```

```rust
for p in gh.get_effective_permissions("alice", "acme")? {
    println!("{:?} {:?} {:?}", p.service, p.resource, p.action);   // Option<String>s
}
```

This returns every grant the identity effectively holds in the org, through
every path, as the grants are written: a wildcard grant comes back with
`null` parts. If the membership is not `ACTIVE`, the list is empty. It is
useful for building UIs ("show the Refund button?") with one call instead of
many checks; for a yes/no decision, use `hasPermission`.

## Direct roles and groups

```java
gh.getRoles("alice", "acme");    // roles assigned directly to alice in acme
gh.getGroups("alice", "acme");   // groups alice belongs to in acme
```

```python
gh.get_roles("alice", "acme")
gh.get_groups("alice", "acme")
```

```rust
gh.get_roles("alice", "acme")?;
gh.get_groups("alice", "acme")?;
```

These list **direct** facts only: `getRoles` does not include roles that
come through groups or inheritance. To see everything that grants a
particular permission, explain it.

## Explaining a decision

`explainPermission` returns the decision **and** every path that grants the
permission, even when the answer is "deny". Use it for support tools ("why
can't Alice refund?"), for audits ("what would we have to remove so she
can't?"), and in tests.

```java
PermissionExplanation why = gh.explainPermission("alice", "acme", "billing", "invoices", "refund");
why.outcome();            // ALLOWED, NO_MEMBERSHIP, MEMBERSHIP_NOT_ACTIVE or NO_MATCHING_GRANT
why.allowed();            // same answer as hasPermission
why.membershipStatus();   // ACTIVE, SUSPENDED, ... or null when there is no membership
for (GrantPath path : why.paths()) {
    path.source();        // DIRECT or GROUP
    path.groupId();       // the group, for GROUP paths
    path.roleChain();     // [assigned role, ..., role holding the grant]
    path.grant();         // the matching grant, wildcards included
}
```

```python
why = gh.explain_permission("alice", "acme", "billing", "invoices", "refund")
why.outcome            # ExplanationOutcome.ALLOWED, ...
why.allowed            # property
why.membership_status
for path in why.paths:
    path.source, path.group_id, path.role_chain, path.grant
    path.assigned_role, path.granting_role      # first and last of role_chain
```

```rust
let why = gh.explain_permission("alice", "acme", "billing", "invoices", "refund")?;
why.outcome;                 // ExplanationOutcome::Allowed, ...
why.allowed();
why.membership_status;       // Option<MembershipStatus>
for path in &why.paths {
    (&path.source, &path.group_id, &path.role_chain, &path.grant);
    path.assigned_role();
    path.granting_role();
}
```

### Outcomes

| Outcome | Meaning | Paths |
|---|---|---|
| `ALLOWED` | active membership and at least one path | every granting path |
| `NO_MEMBERSHIP` | the identity is not a member of the org | grants prepared for it, which have no effect |
| `MEMBERSHIP_NOT_ACTIVE` | the membership is `PENDING`, `SUSPENDED` or `REMOVED` | what *would* apply if it were active |
| `NO_MATCHING_GRANT` | active, but nothing grants this permission | none |

### Reading a path

A path's role chain starts at the role that was assigned and walks up the
inheritance chain to the role holding the grant:

```
source GROUP, group "brokers", chain [policy-editor, policy-viewer], grant (policies, policy, view)
```

means: Alice is in `brokers`; `brokers` holds `policy-editor`;
`policy-editor` inherits `policy-viewer`; `policy-viewer` grants view. To take
this permission away you could remove her from the group, revoke the role
from the group, remove the inheritance link or revoke the grant. Each choice
affects different people, and the paths show you which.

Paths are sorted: direct before group, then by group, then shortest chain
first. Explanations are always computed from the database, never from the
cache, and the status and paths come from one consistent snapshot.
