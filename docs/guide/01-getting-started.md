# 1. Getting started

## Requirements

- PostgreSQL 12+, UTF-8 database encoding (all SDKs; `SQL_ASCII` and other
  encodings are not supported).
- For migrations: a user with `CREATE` on the database. The application user
  needs read/write on the `gatedhouse` schema only.

## Install

Version numbers below are placeholders; this guide describes the release
after 0.3.0.

| SDK | Dependency | Optional add-on (only for URL mode, [ch. 3](03-connecting.md)) |
|---|---|---|
| Java 17+ | `com.twelvevectors:gatedhouse:VERSION` (includes the PostgreSQL driver) | `com.zaxxer:HikariCP:6.2.1` |
| Python 3.10+ | `pip install gatedhouse` | `pip install 'gatedhouse[pool]'` |
| Rust 1.74+ | `gatedhouse = "VERSION"` | `features = ["r2d2"]` |

## Create the schema

Migrations never run at application startup. Run them once per database and
after each upgrade; re-runs apply only missing versions, under an advisory
lock.

```bash
java -cp gatedhouse-VERSION.jar:postgresql-42.7.4.jar com.twelvevectors.gatedhouse.cli.Migrate \
     jdbc:postgresql://localhost:5432/mydb myuser mypassword
gatedhouse-migrate "postgresql://myuser:mypassword@localhost:5432/mydb"
cargo run --bin gatedhouse-migrate -- "host=localhost user=myuser password=mypassword dbname=mydb"
```

From code: `GatedhouseFactory.migrate(config)` (all SDKs).
`GatedhouseFactory.create` refuses to start against a missing or older schema;
the error message contains the migration command.

## First permission check

Uses URL mode (a pool owned by Gatedhouse), suitable for development.

**Java**

```java
try (PooledDatabase db = Database.fromUrl(
         "jdbc:postgresql://localhost:5432/mydb", "myuser", "mypassword");
     Gatedhouse gh = GatedhouseFactory.create(
         GatedhouseConfig.builder().database(db).build())) {

    gh.permissionCatalog().addService("workspace", "Workspace service");
    gh.permissionCatalog().addResource("workspace", "projects", "Projects");
    gh.permissionCatalog().addAction("workspace", "projects", "read", "Read projects");

    gh.roleManager().createRole("project-reader", "Project reader", null);
    gh.roleManager().grantPermission("project-reader", "workspace", "projects", "read");

    gh.membershipManager().createMembership("alice", "acme", EntityType.USER);
    gh.roleManager().assignToIdentity("alice", "acme", "project-reader");

    System.out.println(gh.hasPermission("alice", "acme", "workspace", "projects", "read")); // true
}
```

**Python**

```python
from gatedhouse import Database, EntityType, GatedhouseConfig, GatedhouseFactory

with Database.from_uri("postgresql://myuser:mypassword@localhost:5432/mydb") as db, \
        GatedhouseFactory.create(GatedhouseConfig(database=db)) as gh:

    gh.permission_catalog().add_service("workspace", "Workspace service")
    gh.permission_catalog().add_resource("workspace", "projects", "Projects")
    gh.permission_catalog().add_action("workspace", "projects", "read", "Read projects")

    gh.role_manager().create_role("project-reader", "Project reader", None)
    gh.role_manager().grant_permission("project-reader", "workspace", "projects", "read")

    gh.membership_manager().create_membership("alice", "acme", EntityType.USER)
    gh.role_manager().assign_to_identity("alice", "acme", "project-reader")

    print(gh.has_permission("alice", "acme", "workspace", "projects", "read"))  # True
```

**Rust**

```rust
use std::sync::Arc;
use gatedhouse::{Database, EntityType, GatedhouseConfig, GatedhouseFactory, PooledDatabase};

let db: Arc<dyn Database> = Arc::new(PooledDatabase::from_url(
    "host=localhost user=myuser password=mypassword dbname=mydb",
)?);
let gh = GatedhouseFactory::create(GatedhouseConfig::builder(db).build())?;

gh.permission_catalog().add_service("workspace", Some("Workspace service"))?;
gh.permission_catalog().add_resource("workspace", "projects", Some("Projects"))?;
gh.permission_catalog().add_action("workspace", "projects", "read", Some("Read projects"))?;

gh.role_manager().create_role("project-reader", "Project reader", None)?;
gh.role_manager().grant_permission(
    "project-reader", Some("workspace"), Some("projects"), Some("read"))?;

gh.membership_manager().create_membership("alice", "acme", EntityType::User)?;
gh.role_manager().assign_to_identity("alice", "acme", "project-reader")?;

println!("{}", gh.has_permission("alice", "acme", "workspace", "projects", "read")?); // true
```

A second run fails: creating an existing service, role or membership is an
error.

## Instance lifecycle

- One instance per process, shared by all threads.
- Closing it (`close()`, `with`, dropping the last `Arc`) stops its group
  source. It does not close the `Database`; whoever creates a pool closes it.
