# 5. Roles

A role is a named, global bundle of permissions: a **capability** of your
platform such as `policy-editor` or `invoice-refunder`. Roles reach people in
two ways: assigned directly to an identity in an org, or held by a group the
identity belongs to ([chapter 7](07-groups.md)).

All role operations live on `gh.roleManager()` / `gh.role_manager()`.

## Creating and deleting roles

```java
RoleManager roles = gh.roleManager();
roles.createRole("invoice-refunder", "Invoice refunder", "Can refund customer invoices");
roles.hasRole("invoice-refunder");   // true
roles.listRoles();                   // every role key, sorted
roles.deleteRole("invoice-refunder");
```

```python
roles = gh.role_manager()
roles.create_role("invoice-refunder", "Invoice refunder", "Can refund customer invoices")
roles.has_role("invoice-refunder")   # True
roles.list_roles()
roles.delete_role("invoice-refunder")
```

```rust
let roles = gh.role_manager();
roles.create_role("invoice-refunder", "Invoice refunder", Some("Can refund customer invoices"))?;
roles.has_role("invoice-refunder")?;   // true
roles.list_roles()?;
roles.delete_role("invoice-refunder")?;
```

- The **key** (`invoice-refunder`) identifies the role everywhere and must be
  unique. Creating an existing key is an error. The name and description are
  for people.
- **Deleting a role removes everything attached to it**: its grants, its
  inheritance links (in both directions), and every assignment of it to
  identities and groups in every org. Use it only for roles your platform no
  longer has.
- Built-in roles (currently only `gatedhouse:owner`) cannot be deleted;
  `deleteRole` leaves them in place.

Name roles after what they allow, not after job titles; see
[Concepts](02-concepts.md#roles-are-capabilities-groups-are-titles).

## Granting permissions to a role

```java
roles.grantPermission("invoice-refunder", "billing", "invoices", "read");
roles.grantPermission("invoice-refunder", "billing", "invoices", "refund");
roles.revokePermission("invoice-refunder", "billing", "invoices", "read");
```

```python
roles.grant_permission("invoice-refunder", "billing", "invoices", "read")
roles.grant_permission("invoice-refunder", "billing", "invoices", "refund")
roles.revoke_permission("invoice-refunder", "billing", "invoices", "read")
```

```rust
roles.grant_permission("invoice-refunder", Some("billing"), Some("invoices"), Some("read"))?;
roles.grant_permission("invoice-refunder", Some("billing"), Some("invoices"), Some("refund"))?;
roles.revoke_permission("invoice-refunder", Some("billing"), Some("invoices"), Some("read"))?;
```

- Each named part must exist in the [catalog](04-catalog.md); granting
  `(billing, invoices, refund)` before registering `refund` is an error.
- Granting the same permission twice to a role is an error.
- `revokePermission` removes the grant that matches exactly, wildcards
  included: revoking `(billing, null, read)` removes that wildcard grant, not
  the concrete `(billing, invoices, read)`. Revoking a grant the role doesn't
  have does nothing.

### Wildcards

Pass `null` (`None` in Python and Rust) for any part to mean "any":

```java
roles.grantPermission("billing-auditor", "billing", null, "read");   // read anything in billing
roles.grantPermission("billing-admin", "billing", null, null);       // everything in billing
```

```python
roles.grant_permission("billing-auditor", "billing", None, "read")
roles.grant_permission("billing-admin", "billing", None, None)
```

```rust
roles.grant_permission("billing-auditor", Some("billing"), None, Some("read"))?;
roles.grant_permission("billing-admin", Some("billing"), None, None)?;
```

A wildcard grant also covers entries added to the catalog later. Only the
parts a grant names are checked against the catalog: in
`(billing, null, read)`, `billing` must exist, but `read` is not checked
because there is no specific resource to look it up under. Spell such
actions carefully.

## Inheritance

A role can inherit every permission of other roles. Use it to build larger
capabilities from smaller ones instead of copying grants:

```java
roles.createRole("policy-viewer", "Policy viewer", null);
roles.grantPermission("policy-viewer", "policies", "policy", "view");

roles.createRole("policy-editor", "Policy editor", null);
roles.grantPermission("policy-editor", "policies", "policy", "edit");
roles.addParentRole("policy-editor", "policy-viewer");   // editors can also view

roles.getParentRoles("policy-editor");                    // ["policy-viewer"]
roles.removeParentRole("policy-editor", "policy-viewer");
```

```python
roles.add_parent_role("policy-editor", "policy-viewer")
roles.get_parent_roles("policy-editor")      # ["policy-viewer"]
roles.remove_parent_role("policy-editor", "policy-viewer")
```

```rust
roles.add_parent_role("policy-editor", "policy-viewer")?;
roles.get_parent_roles("policy-editor")?;    // vec!["policy-viewer"]
roles.remove_parent_role("policy-editor", "policy-viewer")?;
```

- Inheritance is transitive: if `A` inherits `B` and `B` inherits `C`, `A`
  has `C`'s permissions too. `getParentRoles` lists only direct parents; use
  [`explainPermission`](08-authorization.md#explaining-a-decision) to see full
  chains.
- A role may have several parents.
- **Cycles are rejected.** `addParentRole(child, parent)` fails when `parent`
  already inherits from `child`, directly or through others: Java throws
  `IllegalArgumentException`, Python raises `ValueError`, Rust returns
  `GatedhouseError::InvalidArgument`. The check runs under a database lock,
  so two simultaneous edits cannot together create a cycle. A role
  inheriting from itself is rejected by the database (a *query* error).
- Adding the same parent twice is an error.

## Assigning roles to identities

A direct assignment gives one identity a role in one org:

```java
roles.assignToIdentity("alice", "acme", "policy-binder");
roles.getIdentityRoles("alice", "acme");         // ["policy-binder"] (direct assignments only)
roles.revokeFromIdentity("alice", "acme", "policy-binder");
```

```python
roles.assign_to_identity("alice", "acme", "policy-binder")
roles.get_identity_roles("alice", "acme")
roles.revoke_from_identity("alice", "acme", "policy-binder")
```

```rust
roles.assign_to_identity("alice", "acme", "policy-binder")?;
roles.get_identity_roles("alice", "acme")?;
roles.revoke_from_identity("alice", "acme", "policy-binder")?;
```

- The role must exist; assigning the same role twice is an error.
- An assignment can be made before the identity has a membership (for
  example while preparing an invitation), but it has no effect until the
  membership is `ACTIVE`. Removing the membership revokes it.
- Prefer groups for anything more than a one-person exception.

## Assigning roles to groups

```java
roles.assignToGroup("brokers", "acme", "policy-viewer");
roles.getGroupRoles("brokers", "acme");          // ["policy-viewer"]
roles.revokeFromGroup("brokers", "acme", "policy-viewer");
```

```python
roles.assign_to_group("brokers", "acme", "policy-viewer")
roles.get_group_roles("brokers", "acme")
roles.revoke_from_group("brokers", "acme", "policy-viewer")
```

```rust
roles.assign_to_group("brokers", "acme", "policy-viewer")?;
roles.get_group_roles("brokers", "acme")?;
roles.revoke_from_group("brokers", "acme", "policy-viewer")?;
```

The group must already exist in that org ([chapter 7](07-groups.md)). Every
current and future member of the group receives the role.

## The built-in owner role

The schema ships one role, `gatedhouse:owner`, which grants
`(null, null, null)`: everything. Assign it to give someone unrestricted
access within one org:

```java
roles.assignToIdentity("founder", "acme", "gatedhouse:owner");
```

It cannot be deleted. Audit who holds it.

## Caching

Every role change clears the affected [cache](09-caching.md) entries in the
same process: changes to one identity's assignments clear that identity's
entry; changes that can affect many identities (grants, inheritance, group
roles, deleting a role) clear the whole cache.
