# Gatedhouse User Guide

Gatedhouse is an embedded RBAC library for multi-tenant applications. It
stores its data in your PostgreSQL database (schema `gatedhouse`) and answers:
may identity X, in organization O, perform action A on resource R of service
S? Java (reference), Python and Rust SDKs share one schema and one behaviour,
and can use the same database concurrently.

| # | Chapter | Content |
|---|---|---|
| 1 | [Getting started](01-getting-started.md) | install, migrate, first check |
| 2 | [Concepts](02-concepts.md) | data model, decision rule |
| 3 | [Connecting](03-connecting.md) | connection sources, pools, timeouts |
| 4 | [Catalog](04-catalog.md) | services, resources, actions |
| 5 | [Roles](05-roles.md) | grants, wildcards, inheritance, assignments |
| 6 | [Memberships](06-memberships.md) | statuses, removal, entity type |
| 7 | [Groups](07-groups.md) | groups, group sources |
| 8 | [Checking access](08-authorization.md) | checks, effective permissions, explanations |
| 9 | [Caching](09-caching.md) | permission cache, invalidation |
| 10 | [Authentication](10-authentication.md) | JWT verification, JWKS caching |
| 11 | [Web integration](11-web.md) | filters, Sphinx OAuth client |
| 12 | [Errors](12-errors.md) | error types, kinds, HTTP mapping |
| 13 | [Operations](13-operations.md) | schema, migrations, audit log, monitoring, testing |

Related: [SKILLS.md](../../SKILLS.md) (name-by-name API reference across the
SDKs), [MODEL.md](../MODEL.md) (design decisions).

## Naming across SDKs

Examples for single calls are in Java. The other SDKs use the same operations:

| | Java | Python | Rust |
|---|---|---|---|
| methods | `hasPermission` | `has_permission` | `has_permission` |
| optional text argument | `null` | `None` | `Option<&str>` (`None`, `Some("x")`) |
| optional result | `Optional<T>` | `T \| None` | `Option<T>` |
| failure | exception | exception | `Result<T, E>` |
| enums | `MembershipStatus.ACTIVE` | `MembershipStatus.ACTIVE` | `MembershipStatus::Active` |
| instance | `Gatedhouse` | `Gatedhouse` | `Arc<dyn Gatedhouse>` |

Where the SDKs differ beyond naming, chapters show all three.
