# Gatedhouse User Guide

Gatedhouse is an embedded authorization library for multi-tenant
applications. It answers one question, fast and consistently:

> May identity **X**, acting in organization **O**, perform **action** on
> **resource** of **service**?

It runs inside your application process (no separate service to deploy),
stores its data in your PostgreSQL database under a `gatedhouse` schema, and
comes as three SDKs with the same behaviour and the same database layout:

| SDK | Package | Minimum runtime |
|---|---|---|
| Java (reference implementation) | Maven `com.twelvevectors:gatedhouse` | Java 17 |
| Python | PyPI `gatedhouse` | Python 3.10 |
| Rust | crates.io `gatedhouse` | Rust 1.74 |

All three can share one database at the same time: a role created from a
Java service is enforced by a Python service, and so on.

## What it does

- **Authorization (RBAC):** a catalog of permissions, roles that bundle them
  (with inheritance and wildcards), per-organization memberships with a
  lifecycle, groups for teams, and a permission check that combines them all.
- **Explanations:** for any decision, every path that grants the permission,
  even when the answer is "deny".
- **Optional caching** of effective permissions, with automatic invalidation.
- **Optional authentication helpers:** JWT verification against an identity
  provider's JWKS (Sphinx SSO compatible), web filters for APIs and pages,
  and an OAuth 2.0 client.
- **Change auditing:** every change to authorization data is recorded by a
  database trigger.

Authorization never depends on authentication: you can use the RBAC core with
any login system and ignore the JWT helpers entirely.

## Chapters

| # | Chapter | Read it when you want to... |
|---|---|---|
| 1 | [Getting started](01-getting-started.md) | install, create the schema and run a first permission check |
| 2 | [Concepts](02-concepts.md) | understand services, roles, groups, memberships and how a decision is made |
| 3 | [Connecting to the database](03-connecting.md) | wire Gatedhouse to your connection pool for production |
| 4 | [The permission catalog](04-catalog.md) | register what can be done in your platform |
| 5 | [Roles](05-roles.md) | define capabilities, wildcards, inheritance and assign roles |
| 6 | [Memberships](06-memberships.md) | add identities to organizations and manage their lifecycle |
| 7 | [Groups](07-groups.md) | model teams and titles, or sync groups from another system |
| 8 | [Checking and explaining access](08-authorization.md) | ask "may they?", list what someone can do, and see why |
| 9 | [Caching](09-caching.md) | make checks cheaper and understand invalidation |
| 10 | [Authentication](10-authentication.md) | verify JWTs from your identity provider |
| 11 | [Web integration](11-web.md) | protect APIs and pages, and talk to Sphinx SSO |
| 12 | [Errors](12-errors.md) | handle every failure correctly, including outages |
| 13 | [Operations](13-operations.md) | migrate, audit, deploy, monitor and test |

Background material:

- [docs/MODEL.md](../MODEL.md): the authorization model's design and the
  decisions behind it.
- [SKILLS.md](../../SKILLS.md): a compact reference with name-by-name tables
  across the three SDKs.

## Conventions in this guide

Every feature is shown in all three languages, in this order: **Java,
Python, Rust**. Names follow each language's style (`hasPermission` /
`has_permission`); the behaviour is identical unless a section says
otherwise. In the examples:

- `gh` is a `Gatedhouse` instance (`Arc<dyn Gatedhouse>` in Rust).
- Rust snippets run inside a function returning
  `Result<_, Box<dyn std::error::Error>>`, so `?` works.
- Identity and organization IDs are your application's own strings;
  Gatedhouse treats them as opaque.
