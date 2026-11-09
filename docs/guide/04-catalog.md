# 4. Permission catalog

Global registry of permissions: service → resource → action. A role can grant
a concrete permission only if it is registered. A resource is a type
(`invoices`), not a record; checking that a record belongs to the org is the
host's job.

```java
PermissionCatalog cat = gh.permissionCatalog();
cat.addService("billing", "Billing");                       // description may be null
cat.addResource("billing", "invoices", "Customer invoices");
cat.addAction("billing", "invoices", "refund", "Refund an invoice");
```

| Operation | Behaviour |
|---|---|
| `addService(s, d)`, `addResource(s, r, d)`, `addAction(s, r, a, d)` | parent must exist; duplicate → `QUERY` error |
| `hasService`, `hasResource`, `hasAction` | boolean |
| `listServices()`, `listResources(s)`, `listActions(s, r)` | sorted names |
| `removeService`, `removeResource`, `removeAction` | deletes the entry, its children, and every grant that names any of them; clears the permission cache; absent entry → no-op |

Removal and wildcard grants: a grant is deleted only if a removed entry is one
it names. Removing service `billing` deletes `(billing, null, read)`;
removing resource `invoices` does not.

Use the three parts as intended, `(workspace, projects, archive)`, not
`(workspace, projects_archive, do)`. Register the catalog idempotently in a
deploy step (`hasX` before `addX`).
