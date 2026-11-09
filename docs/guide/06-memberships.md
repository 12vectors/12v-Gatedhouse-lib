# 6. Memberships

A membership says that an identity belongs to an organization, and in what
state. Every permission check needs an `ACTIVE` membership first: it is the
gate that lets the identity's roles in that org count at all.

All membership operations live on `gh.membershipManager()` /
`gh.membership_manager()`.

## Adding an identity to an organization

```java
MembershipManager members = gh.membershipManager();
members.createMembership("alice", "acme", EntityType.USER);
members.createMembership("invoice-bot", "acme", EntityType.AGENT);
```

```python
members = gh.membership_manager()
members.create_membership("alice", "acme", EntityType.USER)
members.create_membership("invoice-bot", "acme", EntityType.AGENT)
```

```rust
let members = gh.membership_manager();
members.create_membership("alice", "acme", EntityType::User)?;
members.create_membership("invoice-bot", "acme", EntityType::Agent)?;
```

A new membership is `ACTIVE`. Creating one that already exists (and is not
`REMOVED`) is an error. To admit someone in a waiting state, create the
membership and immediately set it to `PENDING`.

## Statuses

| Status | Permission checks | The identity's grants in this org | Typical use |
|---|---|---|---|
| `ACTIVE` | evaluated | apply | a member in good standing |
| `PENDING` | always deny | can be prepared; ignored until active | invited, awaiting acceptance or provisioning |
| `SUSPENDED` | always deny | kept, ignored | leave of absence, security hold, unpaid account |
| `REMOVED` | always deny | revoked | has left the organization |

```
               createMembership
                     │
                     ▼
   PENDING ◄──────► ACTIVE ◄──────► SUSPENDED
      │               │                  │
      └───────────────┼──────────────────┘
                      ▼
                   REMOVED ──── createMembership, or setStatus(ACTIVE / PENDING)
                                (rejoin with a clean slate)
```

## Changing status

```java
members.setStatus("alice", "acme", MembershipStatus.SUSPENDED);   // blocks everything in acme
members.setStatus("alice", "acme", MembershipStatus.ACTIVE);      // restores everything
members.getStatus("alice", "acme");                               // Optional[ACTIVE]
members.hasMembership("alice", "acme");                           // true
```

```python
members.set_status("alice", "acme", MembershipStatus.SUSPENDED)
members.set_status("alice", "acme", MembershipStatus.ACTIVE)
members.get_status("alice", "acme")        # MembershipStatus.ACTIVE, or None
members.has_membership("alice", "acme")    # True
```

```rust
members.set_status("alice", "acme", MembershipStatus::Suspended)?;
members.set_status("alice", "acme", MembershipStatus::Active)?;
members.get_status("alice", "acme")?;      // Some(MembershipStatus::Active)
members.has_membership("alice", "acme")?;  // true
```

- **Suspension is instant and complete.** One status change blocks every
  permission the identity has in that org, however many roles and groups it
  has, and reactivating restores all of them unchanged.
- `setStatus` on an identity with no membership in the org does nothing.
- `getStatus` returns nothing (`Optional.empty()`, `None`) when there is no
  membership, and `REMOVED` for a removed one.

## Removing an identity from an organization

```java
members.removeMembership("alice", "acme");
```

```python
members.remove_membership("alice", "acme")
```

```rust
members.remove_membership("alice", "acme")?;
```

Removal sets the status to `REMOVED` and, in the same transaction, revokes
the identity's direct role assignments and group memberships **in that org**.
Grants in other orgs are untouched. Each revocation is recorded in the
[audit log](13-operations.md#the-audit-log). `setStatus(..., REMOVED)` does the
same.

Memberships are never deleted, so "never a member" and "former member" stay
distinguishable, and there is no delete operation. After removal,
`hasMembership` is `false` and `getStatus` is `REMOVED`.

Calling `removeMembership` for an identity with no membership is allowed and
clears any grants that were prepared for it in that org.

### Rejoining

`createMembership` on a removed membership revives the same record as
`ACTIVE` (with the entity type you pass); `setStatus` to `ACTIVE` or `PENDING`
revives it too. Either way, grants left in that org are cleared first, so
nothing from before the removal comes back: the identity starts with a clean
slate, and you assign its roles and groups again.

Suspending a removed membership is rejected, because there is nothing to
pause: Java throws `IllegalStateException`, Python raises `ValueError`, Rust
returns `GatedhouseError::InvalidTransition`.

## Suspend or remove?

| | Suspend | Remove |
|---|---|---|
| Access | blocked | blocked |
| Roles and groups | kept | revoked |
| Coming back | `setStatus(ACTIVE)`: everything returns | rejoin: start from nothing |
| Use for | temporary situations | the person or agent has left |

## Entity type: users and agents

Each membership records whether the identity is a `USER` (a person) or an
`AGENT` (an automated actor):

```java
members.getEntityType("invoice-bot", "acme");   // Optional[AGENT]
```

```python
members.get_entity_type("invoice-bot", "acme")  # EntityType.AGENT
```

```rust
members.get_entity_type("invoice-bot", "acme")?; // Some(EntityType::Agent)
```

Today the entity type is a label: permission checks don't use it, and agents
are evaluated exactly like users. **Set it accurately anyway.** A planned
check will compare it with what the authentication layer reports (a token's
`person_type`, available as `GatedContext.identityType()`), so that an agent
cannot use permissions granted to it as a person. The vocabularies map as
`human` ↔ `USER` and `agent` ↔ `AGENT`.

## Grants without a membership

Gatedhouse lets you assign roles and groups to an identity that has no
membership yet, for example while preparing an invitation. Such grants are
inert until the membership is `ACTIVE`. This is deliberate: grants can arrive
from several independent sources in any order, and rejecting out-of-order
writes would make those integrations fragile.

## Concurrency

Each membership change runs in one transaction that first locks the
membership, so simultaneous changes to the same membership, from any
process, happen one after the other and never interleave.
