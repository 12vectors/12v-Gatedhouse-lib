# 2. Concepts

Gatedhouse has five building blocks. Two are **global** (defined once for
the whole platform) and three are **per organization** (repeated for every
tenant).

| Building block | Scope | What it is | Example |
|---|---|---|---|
| Permission catalog | global | Everything that *can* be done: `service → resource → action` | `policies / policy / edit` |
| Role | global | A named bundle of permissions; can inherit other roles | `policy-editor` |
| Membership | per org | An identity's presence in an organization, with a status | `alice` is `ACTIVE` in `acme` |
| Group | per org | A team or title within one organization; holds roles for its members | `acme`'s `brokers` |
| Role assignment | per org | A role given directly to one identity in one organization | `alice` has `policy-binder` in `acme` |

The full design, with the reasoning behind each decision, is in
[docs/MODEL.md](../MODEL.md). This chapter gives you what you need to use it.

## Identities and organizations

Gatedhouse has no user table. An **identity** is whatever string your
application uses for a user or an automated agent (`"alice"`, a UUID, the
`sub` of a token). An **organization** ("org") is likewise your own string:
a tenant, customer or workspace ID. Gatedhouse stores and compares these
strings and never validates them against anything else.

The same identity can belong to many orgs and have completely different
access in each.

## Permissions

A permission is three strings: **service**, **resource** and **action**, for
example `workspace / projects / read`. There is no parsing; the three parts
are separate arguments everywhere. (`workspace:projects:read` is a handy way
to write one for humans, and only that.)

Every concrete permission must be registered in the catalog before a role can
grant it. A check for an unregistered permission simply returns "deny".

## Roles are capabilities; groups are titles

This is the convention that makes one set of roles serve every tenant:

- **A role describes a capability of your platform**, named for what it
  unlocks: `policy-viewer`, `invoice-refunder`. Your platform's features are
  the same for every customer, so roles are global.
- **A group describes a title or team inside one org**: `admins`, `brokers`,
  `compliance`. What "admin" means differs between customers, so groups are
  per org.
- **Per-org differences come from which roles a group holds**, never from a
  role meaning different things in different orgs. Acme's `admins` group can
  hold only `policy-viewer` while Beacon's holds `policy-viewer` and
  `policy-editor`.

Name roles after what they allow, never after a job title a customer might
want to redefine. Use a direct role assignment only for a one-person
exception; if a second person might ever need the same access, use a group.

## How a decision is made

`hasPermission(identity, org, service, resource, action)` answers **allow**
exactly when:

1. the identity has a membership in the org, **and**
2. that membership's status is `ACTIVE`, **and**
3. at least one of the identity's roles in that org grants a matching
   permission, where the identity's roles are:
   - roles assigned to it directly in that org, plus
   - roles held by the groups it belongs to in that org, plus
   - every role those roles inherit from, transitively.

A grant matches when each of its three parts equals the checked value or is
a wildcard (`null` / `None`). Otherwise the answer is **deny**. There are no
"deny" rules: permissions only add up.

```
identity ── membership (must be ACTIVE) ──┐
                                          ├── direct roles ──┐
                                          └── groups ── group roles ──┤
                                                                      ├── + inherited roles ── grants ── match?
```

The membership is a gate, not a grant. Suspending a membership blocks every
permission in that org at once, without touching a single role, and
reactivating restores them.

## Wildcards

In a **grant**, any of the three parts can be left empty to mean "any":

| Grant | Matches |
|---|---|
| `(workspace, projects, read)` | exactly that |
| `(workspace, null, read)` | `read` on every resource of `workspace`, including resources added later |
| `(workspace, null, null)` | everything in `workspace` |
| `(null, null, null)` | everything: superuser |

Checks never take wildcards: you always ask about one concrete action.

Because a wildcard covers things added to the catalog later, a wildcard role
silently gains power as your platform grows. Prefer explicit grants unless
"everything in this service, now and later" is really what you mean.

## The membership lifecycle

| Status | Checks | The identity's grants in the org |
|---|---|---|
| `ACTIVE` | evaluated normally | apply |
| `PENDING` | always deny | can be prepared in advance (onboarding) |
| `SUSPENDED` | always deny | kept; reactivating restores them |
| `REMOVED` | always deny | revoked when the membership is removed |

Memberships are never deleted. Leaving an org is the `REMOVED` status, which
revokes the identity's roles and group memberships in that org and keeps the
membership as history. Details in [chapter 6](06-memberships.md).

## A worked example

A policy platform with two customer orgs, `acme` and `beacon`:

```
Catalog     policies / policy / {view, edit, bind}

Roles       policy-viewer   grants (policies, policy, view)
            policy-editor   grants (policies, policy, edit), inherits policy-viewer
            policy-binder   grants (policies, policy, bind)

acme        group "brokers"   holds policy-viewer
            alice  ACTIVE  member of brokers; directly assigned policy-binder

beacon      group "brokers"   holds policy-editor
            alice  SUSPENDED  member of brokers
```

| Check | Answer | Why |
|---|---|---|
| alice, acme, `view` | allow | brokers → policy-viewer |
| alice, acme, `edit` | deny | Acme's brokers only view |
| alice, acme, `bind` | allow | direct assignment |
| alice, beacon, `view` | deny | suspended in Beacon, although Beacon's brokers hold policy-editor (which inherits view) |

[Chapter 8](08-authorization.md) shows how `explainPermission` produces
exactly this kind of "why" for you.
