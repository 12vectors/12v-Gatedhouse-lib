# 1. Getting started

This chapter takes you from nothing to a working permission check. It uses
the simplest connection setup (Gatedhouse runs its own small connection pool
from a URL), which is right for development and staging. For production,
[chapter 3](03-connecting.md) shows how to hand Gatedhouse your
application's pool instead.

## Requirements

- PostgreSQL 12 or later, in UTF-8 encoding (`CREATE DATABASE ... ENCODING
  'UTF8'`).
- A database user that can create a schema, for the one-time migration. The
  application itself only needs read and write access to the `gatedhouse`
  schema.

## Install

> This guide documents the release that follows 0.3.0. Use that version or
> later; the version numbers below are placeholders.

**Java** (`pom.xml`):

```xml
<dependency>
  <groupId>com.twelvevectors</groupId>
  <artifactId>gatedhouse</artifactId>
  <version>VERSION</version>
</dependency>

<!-- Only if you use Database.fromUrl (a pool run by Gatedhouse).
     Not needed when you pass your own DataSource. -->
<dependency>
  <groupId>com.zaxxer</groupId>
  <artifactId>HikariCP</artifactId>
  <version>6.2.1</version>
</dependency>
```

The PostgreSQL JDBC driver comes with the library.

**Python**:

```bash
pip install gatedhouse            # the library
pip install 'gatedhouse[pool]'    # plus psycopg_pool, only for Database.from_uri
```

**Rust** (`Cargo.toml`):

```toml
[dependencies]
# The "r2d2" feature adds connection-pool support, including
# PooledDatabase::from_url used below.
gatedhouse = { version = "VERSION", features = ["r2d2"] }
```

## Create the schema

Gatedhouse never creates or alters its schema while your application starts.
You run the migration once per database, before the first deploy and again
after upgrading to a version with a newer schema. Re-running it is safe: it
applies only what is missing, under a database lock, so concurrent runs from
several machines don't collide.

From the command line:

```bash
# Java (the jar plus the PostgreSQL driver on the classpath)
java -cp gatedhouse-VERSION.jar:postgresql-42.7.4.jar \
     com.twelvevectors.gatedhouse.cli.Migrate \
     jdbc:postgresql://localhost:5432/mydb myuser mypassword

# Python
gatedhouse-migrate "postgresql://myuser:mypassword@localhost:5432/mydb"

# Rust (from a checkout of the crate)
cargo run --bin gatedhouse-migrate -- "host=localhost user=myuser password=mypassword dbname=mydb"
```

Or from code, for example in a deploy step:

```java
GatedhouseFactory.migrate(GatedhouseConfig.builder().database(db).build());
```

```python
GatedhouseFactory.migrate(GatedhouseConfig(database=db))
```

```rust
GatedhouseFactory::migrate(&GatedhouseConfig::builder(db.clone()).build())?;
```

When the application starts, `GatedhouseFactory.create` checks the schema
version and refuses to start against a missing or outdated schema, with the
exact command to run in the error message.

## A first permission check

The program below registers a permission, defines a role that grants it,
adds a user to an organization with that role, and checks access.

**Java**

```java
import com.twelvevectors.gatedhouse.*;

try (PooledDatabase db = Database.fromUrl(
         "jdbc:postgresql://localhost:5432/mydb", "myuser", "mypassword");
     Gatedhouse gh = GatedhouseFactory.create(
         GatedhouseConfig.builder().database(db).build())) {

    // 1. What can be done in the platform
    gh.permissionCatalog().addService("workspace", "Workspace service");
    gh.permissionCatalog().addResource("workspace", "projects", "Projects");
    gh.permissionCatalog().addAction("workspace", "projects", "read", "Read projects");

    // 2. A role that grants it
    gh.roleManager().createRole("project-reader", "Project reader", null);
    gh.roleManager().grantPermission("project-reader", "workspace", "projects", "read");

    // 3. Alice joins the "acme" organization with that role
    gh.membershipManager().createMembership("alice", "acme", EntityType.USER);
    gh.roleManager().assignToIdentity("alice", "acme", "project-reader");

    // 4. Check
    boolean allowed = gh.hasPermission("alice", "acme", "workspace", "projects", "read");
    System.out.println(allowed);   // true
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

Run it twice and the second run fails: the service, role and membership
already exist, and creating them again is an error. Setup like steps 1 and 2
belongs in a deploy or admin flow; step 3 in your sign-up or invitation flow;
step 4 on every request.

## Lifecycle of a Gatedhouse instance

- Create **one** instance per process and share it. It is safe to use from
  many threads at once.
- Closing it (`close()`, a `with` block, or dropping the last `Arc` in Rust)
  stops its [group source](07-groups.md#syncing-groups-from-another-system).
  It does **not** close the database or pool you passed in: whoever creates a
  pool closes it.

## Next steps

- [Concepts](02-concepts.md): how the pieces fit before you design your roles.
- [Connecting to the database](03-connecting.md): before going to production.
