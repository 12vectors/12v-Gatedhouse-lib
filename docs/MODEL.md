# The Gatedhouse authorization model

This document is the definitive description of how Gatedhouse models
authorization: what each concept is for, how a permission decision is made,
and how memberships and grants behave over time. It applies to all three SDKs
(Java reference, Python, Rust); they share one Postgres schema and the same
contract. Code samples use the Java reference API. Python and Rust expose the
same operations under their own naming conventions (`remove_membership`,
`explain_permission`, …).

The decisions that shaped the model are recorded in the
[decision log](#decision-log) at the end, with the reasoning behind each.

## The four concepts

| Concept | Scope | What it is | Analogy |
|---|---|---|---|
| **Permission catalog** | global | The vocabulary of what *can* be done: `service → resource → action` | The list of buttons in the product |
| **Role** | global | A named bundle of permissions, optionally inheriting other roles | A capability: "can edit policies" |
| **Group** | per org | A set of identities in one org that receive roles together | A team or job title: "Acme's admins" |
| **Membership** | per org | An identity's presence in an org, with a lifecycle status | Being on the payroll |

```
 GLOBAL (defined once, shared by every org)       PER ORG (repeated for each tenant)
 ──────────────────────────────────────────       ─────────────────────────────────────────
 Catalog:  service → resource → action            Membership: identity ∈ org (+ status)  ◄── the gate
             "what CAN be done"                        │
                    ▲                                  ├── direct role assignment  (identity, org, role)
 Role: named bundle of permissions ───────────────────┤
       (+ inherits from parent roles)                  └── group membership ──► group ──► group role
```

### Roles are global capabilities; groups are per-org titles and teams

This is the most important convention in the model, and it is what lets one
set of roles serve every tenant.

- **A role describes a capability of the platform.** It answers "what does
  this unlock in the product?", for example `policy-viewer`, `policy-editor` or
  `invoice-refunder`. Roles are tied to the platform's *functionality*, which
  is the same for every tenant, so roles are global. The host platform defines
  them, alongside the features they unlock.
- **A group describes a title or team inside one organization.** It answers
  "who works here, and in what capacity?", for example `admins`, `brokers` or
  `compliance`. Titles mean different things in different organizations, so
  groups are per org.
- **Per-org variation comes from which roles a group holds, never from
  changing what a role means.** "Admin" can mean view-only at Acme and
  view-and-edit at Beacon:

```java
// Global capabilities, named for what they allow
roles.createRole("policy-viewer", "Policy viewer", "View policies");
roles.grantPermission("policy-viewer", "policies", "policy", "view");
roles.createRole("policy-editor", "Policy editor", "Edit policies");
roles.grantPermission("policy-editor", "policies", "policy", "edit");

// Per-org titles: each org decides what its "admins" can do
groups.createGroup("admins", "acme", "Admins", null);
roles.assignToGroup("admins", "acme", "policy-viewer");      // Acme: view only

groups.createGroup("admins", "beacon", "Admins", null);
roles.assignToGroup("admins", "beacon", "policy-viewer");    // Beacon: view …
roles.assignToGroup("admins", "beacon", "policy-editor");    // … and edit
```

Name roles after what they allow (`policy-editor`). **Never name a role after a
job title a tenant might want to redefine (`admin`)**: a global `admin` role
would have to mean the same thing everywhere, and the first tenant that wants a
different "admin" forces either a fork of the role or an org-dependent role
meaning, which the model rules out (see [D5](#decision-log)).

Direct role assignments are for individual exceptions that should not become a
group of one, such as the single person allowed to bind policies. The rule of
thumb: **if a second person would ever need the same access, use a group.**

## Worked example

A policy-administration platform hosts two brokerages, the orgs **`acme`** and
**`beacon`**.

### 1. Catalog: what can be done (once, at deploy)

```java
var cat = gh.permissionCatalog();
cat.addService("policies", "Policy administration");
cat.addResource("policies", "policy", "Insurance policies");
cat.addAction("policies", "policy", "view", null);
cat.addAction("policies", "policy", "edit", null);
cat.addAction("policies", "policy", "bind", null);   // make a policy legally binding
cat.addResource("policies", "quote", "Quotes");
cat.addAction("policies", "quote", "view", null);
cat.addAction("policies", "quote", "create", null);
cat.addService("billing", "Billing");
cat.addResource("billing", "invoice", "Invoices");
cat.addAction("billing", "invoice", "view", null);
cat.addAction("billing", "invoice", "refund", null);
```

The catalog grants nothing. It exists so that a role cannot grant a permission
nobody defined: the schema's foreign keys reject a typo such as
`policies/polcy/view`.

A **resource** is a resource *type* (`policy`, `quote`), not a record. Gatedhouse
does not grant access to individual records such as "policy #123".

### 2. Roles: global capabilities

```java
var roles = gh.roleManager();

roles.createRole("policy-viewer", "Policy viewer", "Read policies and quotes");
roles.grantPermission("policy-viewer", "policies", "policy", "view");
roles.grantPermission("policy-viewer", "policies", "quote",  "view");

roles.createRole("policy-editor", "Policy editor", "Day-to-day policy work");
roles.addParentRole("policy-editor", "policy-viewer");          // editor ⊇ viewer
roles.grantPermission("policy-editor", "policies", "policy", "edit");
roles.grantPermission("policy-editor", "policies", "quote",  "create");

roles.createRole("policy-binder", "Policy binder", "Make policies binding");
roles.addParentRole("policy-binder", "policy-editor");          // binder ⊇ editor ⊇ viewer
roles.grantPermission("policy-binder", "policies", "policy", "bind");

roles.createRole("auditor", "Auditor", "Read everything, change nothing");
roles.grantPermission("auditor", "policies", null, "view");     // view ANY policies resource
roles.grantPermission("auditor", "billing",  null, "view");     // view ANY billing resource

roles.createRole("quote-drafter", "Quote drafter", "Draft renewal quotes");
roles.grantPermission("quote-drafter", "policies", "quote",  "create");
roles.grantPermission("quote-drafter", "policies", "policy", "view");
```

- **Inheritance** keeps roles small. `addParentRole(child, parent)` gives the
  child every permission of the parent, transitively. Inheritance is a DAG:
  an edge that would close a cycle is rejected, checked under a lock so two
  concurrent edits cannot together create one.
- **Wildcards.** `null` at any level of a grant means "any" at that level,
  matched column by column. `(policies, null, view)` covers every resource in
  `policies`, *including resources added to the catalog later*: a wildcard role
  silently widens as the catalog grows. `(null, null, null)` grants
  everything; the seeded `gatedhouse:owner` role is exactly that.
- Wildcards appear only in grants. A permission check is always concrete.

### 3. Memberships: who belongs to which org

```java
var m = gh.membershipManager();
m.createMembership("alice", "acme",   EntityType.USER);
m.createMembership("alice", "beacon", EntityType.USER);   // same person, second org
m.createMembership("bob",   "acme",   EntityType.USER);
m.createMembership("carol", "acme",   EntityType.USER);
m.createMembership("renewal-bot", "acme", EntityType.AGENT);
```

A membership grants nothing by itself. It is the **gate** that lets the
identity's grants in that org count. See [the membership
lifecycle](#the-membership-lifecycle) for what each status means.

### 4. Grants: groups for titles, direct assignments for exceptions

```java
var groups = gh.groupManager();
groups.createGroup("brokers",    "acme", "Brokers",    null);
groups.createGroup("compliance", "acme", "Compliance", null);
roles.assignToGroup("brokers",    "acme", "policy-editor");
roles.assignToGroup("compliance", "acme", "auditor");

groups.addIdentityToGroup("brokers",    "acme", "alice");
groups.addIdentityToGroup("brokers",    "acme", "bob");
groups.addIdentityToGroup("compliance", "acme", "carol");

roles.assignToIdentity("bob",         "acme",   "policy-binder");   // Bob alone may bind
roles.assignToIdentity("alice",       "beacon", "policy-viewer");   // Alice consults for Beacon
roles.assignToIdentity("renewal-bot", "acme",   "quote-drafter");
```

### 5. Checking access

```java
gh.hasPermission(identityId, orgId, service, resource, action);
```

| Question | Answer | Why |
|---|---|---|
| Alice, `acme`, `policies/policy/edit` | ✅ | active in acme → group `brokers` → `policy-editor` |
| Alice, `acme`, `policies/policy/bind` | ❌ | neither `policy-editor` nor `policy-viewer` grants bind |
| Alice, `beacon`, `policies/policy/edit` | ❌ | at Beacon she holds only `policy-viewer`; nothing crosses orgs |
| Bob, `acme`, `policies/policy/bind` | ✅ | direct `policy-binder` |
| Carol, `acme`, `billing/invoice/view` | ✅ | `compliance` → `auditor` → `(billing, *, view)` |
| Carol, `acme`, `billing/invoice/refund` | ❌ | the wildcard is on the resource, not the action |
| Carol after `setStatus(carol, acme, SUSPENDED)` | ❌ everything | gate closed; her grants are kept but ignored |
| `renewal-bot`, `acme`, `policies/quote/create` | ✅ | agents resolve exactly like users |

## How a decision is made

```
allowed(identity, org, service, resource, action) =
      membership(identity, org).status = ACTIVE
  AND some role R in  closure( direct roles(identity, org)
                             ∪ roles of groups(identity, org) )
      holds a grant matching (service, resource, action)
```

where `closure` adds every ancestor through role inheritance, and a grant
matches when each of its three components is either `null` or equal to the
requested value.

Three properties follow, and hosts should rely on them:

- **Purely additive.** There are no deny rules. A group or role can never take a
  permission away. To remove a permission, remove every path that grants it;
  [`explainPermission`](#explaining-a-decision) lists those paths.
- **Org-isolated.** Every check names exactly one org. Nothing held in one org
  has any effect in another.
- **Gated.** Without an `ACTIVE` membership, no grant counts, however many
  grants exist.

## The membership lifecycle

Memberships are never deleted. An identity's history in an org stays visible in
the live table, so "never a member" and "former member" remain distinguishable.

| Status | Grants | Meaning |
|---|---|---|
| `PENDING` | may be prepared, **ignored** | invited or being provisioned, not yet let in |
| `ACTIVE` | **apply** | a member in good standing |
| `SUSPENDED` | **kept**, ignored | temporarily barred (leave of absence, security hold); reactivating restores everything |
| `REMOVED` | **revoked** | has left the org; the row remains as history |

```
                createMembership
                      │
                      ▼
    PENDING ◄──────► ACTIVE ◄──────► SUSPENDED
       │               │                  │
       └───────────────┼──────────────────┘
                       ▼
                    REMOVED ──── createMembership / setStatus(ACTIVE|PENDING)
                       │              (rejoin with a clean slate)
                       └──────────────────► ACTIVE or PENDING
```

The rules:

- **Removing** (`removeMembership`, or `setStatus(…, REMOVED)`) sets the status
  and, in the same transaction, revokes the identity's direct role assignments
  and group memberships *in that org*. Each revocation is recorded by the audit
  trigger. Grants held in other orgs are untouched.
- **Suspending keeps grants; removing revokes them.** That difference is the
  reason both statuses exist.
- **Rejoining starts from a clean slate.** `createMembership` on a `REMOVED`
  membership revives the same row as `ACTIVE`, with the given entity type;
  `setStatus(…, ACTIVE)` or `setStatus(…, PENDING)` revives it too. In every
  case, grants left in that org are cleared first, in the same transaction, so
  no access from before the removal can return.
- **`REMOVED → SUSPENDED` is rejected.** Suspension pauses a membership, and a
  removed identity has nothing to pause.
- **`hasMembership` is false for a `REMOVED` membership**; `getStatus` reports
  `REMOVED`.
- **There is no delete operation.** `deleteMembership` was removed from the
  API; `removeMembership` is the only way to take an identity out of an org.

### Grants are hard-deleted and audited

Grant rows (role assignments, group memberships, group roles) are facts, not
entities with a lifecycle. Revoking one deletes the row. The audit trigger on
every authorization table records each delete with the full old row, so history
lives in `gatedhouse.audit_log`, not in the live tables.

### Grants do not require a membership

Gatedhouse does not enforce, at the database level, that a grant has a
membership. A role assigned to an identity with no membership in the org is
accepted and is inert, because the gate ignores it. This is deliberate: grants
are written by several independent paths (the host's admin actions, and
external group sources that receive events in no guaranteed order), and a hard
constraint would turn every out-of-order write into a failure that callers
would have to race against.

The lifecycle closes the gap instead. Removing a membership clears the
identity's grants in that org, and reviving one clears them again. A grant that
arrives *after* a removal (a late group-sync event, say) is therefore inert
while the identity is removed, and cannot survive into a rejoin. The guarantee
covers grants committed before the transition; a grant written concurrently
with a rejoin is indistinguishable from a grant made just after it.

## Entity type

Each membership records whether the identity is a `USER` or an `AGENT`.

- Today it is a **descriptive label**. The permission check does not read it.
  Agents resolve exactly like users.
- It is stored per membership, so it is set when the identity joins each org.
- **Hosts must set it accurately.** A future authorization check will compare
  the entity type that the *authentication* layer reports (the Sphinx token's
  `person_type`, exposed as `GatedContext.identityType()` / `isHuman()`)
  against the membership's entity type, so that an agent cannot exercise
  permissions granted to it as a human, and the other way round.
- **Vocabulary mapping.** The authentication layer says `human` / `agent`; the
  authorization schema says `user` / `agent`. They correspond as
  `human` ↔ `USER` and `agent` ↔ `AGENT`.

## Roles are global templates

There is one definition of each role, shared by every org. Editing a role's
permissions changes it for every org that uses it, so role definitions belong to
whoever owns the platform's features, not to tenants. Tenants shape their access
through groups (see [above](#roles-are-global-capabilities-groups-are-per-org-titles-and-teams)).

Deleting a role cascades: every assignment of it, in every org, disappears with
it. Treat role deletion as a platform change, not a tenant action.

If tenants ever need to define their own roles, the planned extension is
*additional* per-org roles that can inherit from the global ones, introduced as
an additive migration. The model deliberately does not provide that today.

## Explaining a decision

Because permissions are additive and can arrive through several paths,
"why does Bob have `bind`?" needs an answer an operator can act on.
`explainPermission` returns one:

```java
PermissionExplanation e = gh.explainPermission("bob", "acme", "policies", "policy", "bind");

e.allowed();            // true
e.outcome();            // ALLOWED
e.membershipStatus();   // ACTIVE
for (GrantPath p : e.paths()) {
    p.source();         // DIRECT, or GROUP with p.groupId()
    p.roleChain();      // [policy-binder]: the assigned role first, the granting role last
    p.grant();          // (policies, policy, bind), possibly with null wildcards
}
```

- `outcome` is one of `ALLOWED`, `NO_MEMBERSHIP`, `MEMBERSHIP_NOT_ACTIVE` and
  `NO_MATCHING_GRANT`. `allowed()` is true only for `ALLOWED`, and it always
  agrees with `hasPermission` for the same inputs.
- `paths` lists **every** path that would grant the permission, *even when the
  decision is a denial*. For a suspended member it shows what reactivation would
  restore. For an identity with no membership it reveals inert grants left
  behind, which is useful when tracing data-quality problems.
- A path's `roleChain` runs from the role that is assigned (directly, or to the
  group) through inheritance to the role that holds the matching grant. For
  example, Alice's `view` at Acme reads
  `GROUP brokers: [policy-editor, policy-viewer] → (policies, policy, view)`.
- It is a diagnostic. It bypasses the permission cache and always reads the
  database, so don't use it on hot request paths.

## Compatibility

- Schema version **2** (migration `V002`) adds the `removed` membership status.
  Run the migrator before deploying an SDK version that expects schema 2.
- SDKs that share one database should be upgraded together. A release built for
  schema 1 does not know the `removed` status and fails to read a membership in
  that state.
- **Breaking change:** `deleteMembership` no longer exists. Replace calls with
  `removeMembership`, which revokes the identity's grants in the org and keeps
  the membership row instead of deleting it.
- **Breaking change (connections):** URL mode now runs a Gatedhouse-owned
  pool backed by an optional dependency: Java `Database.fromUrl` returns a
  `PooledDatabase` and needs HikariCP; Python `Database.from_uri` returns a
  `PooledDatabase` and needs `gatedhouse[pool]`; Rust replaces
  `ConninfoDatabase` with `PooledDatabase::from_url` (feature `r2d2`). The
  Rust `Database` trait now returns a boxed handle (`PooledClient`) and a
  boxed error, so pools can implement it, and `GatedhouseError::Database`
  carries a `kind`. See [Connecting to the Database](../SKILLS.md#connecting-to-the-database).
- `addParentRole` now rejects an edge that would create an inheritance cycle.
  Existing cycles are not removed; evaluation tolerates them.

## Decision log

| # | Decision | Why |
|---|---|---|
| D1 | Memberships are never deleted; leaving an org is the status `REMOVED`, which revokes the identity's grants in that org. Reviving a removed membership clears its grants again | A membership is an entity with a lifecycle, and its history should stay in the live table. A delete that kept the grants would duplicate `SUSPENDED` and let old access reappear on rejoin |
| D2 | Grants are hard-deleted; the audit trigger is their history | Grants are facts, not entities. Temporal rows would add a validity filter to every query for point-in-time questions the audit log already answers |
| D3 | No foreign key from grants to memberships | Grants come from independent writers with no ordering guarantee; a constraint would turn races into failures. The lifecycle clears grants at removal and rejoin instead |
| D4 | Entity type stays a per-membership label | Gatedhouse treats identity IDs as opaque and does not own an identity registry. The label is reserved for a future authentication-vs-authorization consistency check |
| D5 | Roles are global templates | The host platform owns its features and therefore its capabilities. Per-org roles would multiply definitions and make a role's meaning depend on the org |
| D6 | Roles are global capabilities tied to platform functionality; groups are per-org titles and teams | Lets every tenant compose the same capabilities differently without forking roles or giving a role an org-dependent meaning |
| D7 | `explainPermission` reports every granting path, including for denials | Additive permissions arrive through several paths, so removing one needs a way to see all of them |
| D8 | Role inheritance is acyclic, enforced in a transaction under an advisory lock shared by all SDKs | A cycle makes every role in it equivalent, which is never intended. A check without the lock lets two concurrent edits each pass and together close a cycle |

### Deferred

- **Erasure.** A deliberate, privileged way to purge an identity's personal data
  (including from the audit log) for data-protection requests.
- **Role and group deletion.** Whether roles and groups should be archived
  rather than deleted, given that deletion cascades through every assignment.
- **Entity-type enforcement.** The authentication-vs-authorization check
  described under [entity type](#entity-type).
