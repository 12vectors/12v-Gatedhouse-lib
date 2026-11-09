# 4. The permission catalog

The catalog is the vocabulary of your platform: every action that can be
controlled, organized as **service → resource → action**. It is global (the
same for every organization) and normally changes only when your platform
ships a feature.

| Level | Typical meaning | Examples |
|---|---|---|
| Service | a product area or microservice | `workspace`, `billing`, `policies` |
| Resource | a kind of thing inside it | `projects`, `invoices`, `policy` |
| Action | what can be done to it | `read`, `write`, `delete`, `refund`, `bind` |

## Registering permissions

Register parents before children: a resource needs its service, an action
needs its resource. Descriptions are optional (`null` / `None`).

```java
PermissionCatalog cat = gh.permissionCatalog();
cat.addService("billing", "Billing");
cat.addResource("billing", "invoices", "Customer invoices");
cat.addAction("billing", "invoices", "read", "View invoices");
cat.addAction("billing", "invoices", "refund", "Refund an invoice");
```

```python
cat = gh.permission_catalog()
cat.add_service("billing", "Billing")
cat.add_resource("billing", "invoices", "Customer invoices")
cat.add_action("billing", "invoices", "read", "View invoices")
cat.add_action("billing", "invoices", "refund", "Refund an invoice")
```

```rust
let cat = gh.permission_catalog();
cat.add_service("billing", Some("Billing"))?;
cat.add_resource("billing", "invoices", Some("Customer invoices"))?;
cat.add_action("billing", "invoices", "read", Some("View invoices"))?;
cat.add_action("billing", "invoices", "refund", Some("Refund an invoice"))?;
```

Adding something that already exists is an error (a database error of kind
*query*, see [chapter 12](12-errors.md)). For idempotent setup, check first:

```java
if (!cat.hasAction("billing", "invoices", "refund")) {
    cat.addAction("billing", "invoices", "refund", "Refund an invoice");
}
```

A good place for catalog registration is a deploy-time step (next to
migrations) that declares your platform's full catalog idempotently.

## Reading the catalog

| Java | Python | Rust | Returns |
|---|---|---|---|
| `hasService(s)` | `has_service(s)` | `has_service(s)?` | boolean |
| `hasResource(s, r)` | `has_resource(s, r)` | `has_resource(s, r)?` | boolean |
| `hasAction(s, r, a)` | `has_action(s, r, a)` | `has_action(s, r, a)?` | boolean |
| `listServices()` | `list_services()` | `list_services()?` | names, sorted |
| `listResources(s)` | `list_resources(s)` | `list_resources(s)?` | names, sorted |
| `listActions(s, r)` | `list_actions(s, r)` | `list_actions(s, r)?` | names, sorted |

## Removing permissions

`removeService`, `removeResource` and `removeAction` delete the entry **and
everything under it, including every role grant that names it**. Removing
`billing` removes its resources, their actions, and every `(billing, ...)`
grant from every role. The change is recorded in the audit log and the
permission cache is cleared.

Removing something that does not exist does nothing.

Because removal cascades into roles, treat it like dropping a database
column: only after the feature is gone from every deployed version of your
platform.

## Wildcard grants and the catalog

A grant with a wildcard (`null`) at some level only refers to the catalog
entries it actually names. Removing an entry it names removes the grant:
removing the `billing` service removes `(billing, null, read)`. Removing
an entry it doesn't name leaves it alone: removing the `invoices` resource
does not. Wildcard grants automatically cover entries added later. See
[chapter 5](05-roles.md#wildcards).
