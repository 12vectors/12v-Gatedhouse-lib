# 3. Connecting to the database

Gatedhouse needs a source of database connections, called a `Database`. It
never manages connections behind your back: it borrows one per operation from
the source you give it and gives it back when the operation ends. It opens
connections of its own only when you give it a URL.

## Choosing a connection source

| Situation | Use | Gatedhouse opens connections? |
|---|---|---|
| **Production** | your application's existing pool | no |
| Another pool or custom source | a small adapter (below) | no |
| Development, staging, scripts | a URL: Gatedhouse runs its own pool | yes, from its own pool |

Using your application's pool means one pool, sized and monitored against the
database's connection limit. A second, Gatedhouse-owned pool against the same
database is fine for development, but in production it hides connections from
your capacity planning.

## Production: your application's pool

### Java

Any `javax.sql.DataSource` works: HikariCP, Agroal (Quarkus), DBCP2, Tomcat
JDBC, an application server's JNDI pool, or Spring Boot's auto-configured
pool.

```java
DataSource pool = ...;                            // your application's pool
Database db = Database.fromDataSource(pool);      // Gatedhouse never closes it
Gatedhouse gh = GatedhouseFactory.create(GatedhouseConfig.builder().database(db).build());
```

With Spring Boot:

```java
@Configuration
class GatedhouseConfiguration {
    @Bean(destroyMethod = "close")
    Gatedhouse gatedhouse(DataSource dataSource) {
        return GatedhouseFactory.create(GatedhouseConfig.builder()
            .database(Database.fromDataSource(dataSource))
            .build());
    }
}
```

Pass the **plain** pooled `DataSource`, not a transaction-aware proxy
(`TransactionAwareDataSourceProxy`). Such a proxy hands out the connection
bound to the current `@Transactional` method; Gatedhouse detects that the
connection is inside your transaction and refuses it, rather than commit your
unfinished work. A pool configured with `autoCommit=false` is fine.

For anything that isn't a `DataSource`, `Database` is a one-method interface:

```java
Database db = () -> myPool.borrowConnection();   // closed by Gatedhouse after each operation
```

### Python

Pass a `psycopg_pool.ConnectionPool`:

```python
from psycopg_pool import ConnectionPool
from gatedhouse import Database, GatedhouseConfig, GatedhouseFactory

pool = ConnectionPool("postgresql://app:secret@db/app", max_size=20, open=True)  # yours
db = Database.from_pool(pool)                                                     # never closed by Gatedhouse
gh = GatedhouseFactory.create(GatedhouseConfig(database=db))
```

- **Pre-forking servers** (gunicorn, uWSGI): open the pool *after* the workers
  fork, for example in your app factory or a `post_fork` hook, not at import
  time. Connections do not survive a fork.
- **Async frameworks** (FastAPI, Starlette, Quart): Gatedhouse is synchronous.
  Call it from a worker thread (`await asyncio.to_thread(gh.has_permission,
  ...)` or `run_in_executor`) with a **synchronous** pool. `from_pool` rejects
  an `AsyncConnectionPool` with an explanation.

For any other source, subclass `Database`. `connection()` must return a
*context manager* that yields a psycopg connection and gives it back when the
`with` block ends:

```python
import contextlib
from gatedhouse import Database

class SQLAlchemyDatabase(Database):
    """Share a SQLAlchemy engine's pool (this recipe is tested in CI)."""

    def __init__(self, engine):
        self._engine = engine            # create_engine("postgresql+psycopg://...")

    @contextlib.contextmanager
    def connection(self):
        raw = self._engine.raw_connection()   # checked out of the engine's pool
        try:
            yield raw.driver_connection       # the underlying psycopg connection
        finally:
            raw.close()                       # back to the engine's pool
```

Never return `pool.getconn()` from `connection()`: nothing would give the
connection back, and the pool runs dry after a few calls.

### Rust

With the `r2d2` feature, an `r2d2` pool *is* a `Database`:

```rust
use postgres::NoTls;
use r2d2_postgres::PostgresConnectionManager;

let manager = PostgresConnectionManager::new(conninfo.parse()?, NoTls);
let pool = r2d2::Pool::builder().max_size(20).build(manager)?;   // yours
let db: Arc<dyn Database> = Arc::new(pool.clone());
```

Any other pool works through `from_fn`: return the pool's handle (anything
that dereferences to `postgres::Client`), boxed as a `PooledClient`. Dropping
the handle returns the connection.

```rust
use gatedhouse::{from_fn, Database, PooledClient};

let db: Arc<dyn Database> = Arc::new(from_fn(move || {
    let handle = my_pool.get()?;
    Ok(Box::new(handle) as PooledClient)
}));
```

## Development and staging: a URL

Give Gatedhouse a URL and it runs a small pool of its own, backed by an
optional dependency so production deployments never download it.

| | Java | Python | Rust |
|---|---|---|---|
| Dependency | `com.zaxxer:HikariCP` | `pip install 'gatedhouse[pool]'` | feature `r2d2` |
| Create | `Database.fromUrl(url, user, password)` | `Database.from_uri(conninfo)` | `PooledDatabase::from_url(conninfo)?` |
| With settings | `Database.fromUrl(url, user, pwd, settings)` | keyword arguments | `PooledDatabase::from_url_with(conninfo, settings)?` |
| TLS | in the JDBC URL (`?sslmode=require`) | in the URL (`?sslmode=require`) | `PooledDatabase::from_url_with_tls(conninfo, tls_connector, settings)?` |
| Close | `close()` / try-with-resources | `close()` / `with` | drop the last `Arc` |
| Dependency missing | `IllegalStateException` naming HikariCP | `ImportError` naming `gatedhouse[pool]` | compile error |

Settings and their defaults:

| Setting | Default | Meaning |
|---|---|---|
| maximum size | 10 | most connections the pool opens |
| connection timeout | 10 s | longest an operation waits for a free connection before failing as *unavailable* |
| maximum lifetime | 30 min | connections older than this are replaced |
| statement timeout | 30 s | longest any statement may run before PostgreSQL cancels it (0 = no limit) |

```java
PooledDatabase db = Database.fromUrl(url, user, password,
    PooledDatabase.Settings.builder()
        .maximumPoolSize(5)
        .connectionTimeout(Duration.ofSeconds(3))
        .statementTimeout(Duration.ofSeconds(10))
        .build());
```

```python
db = Database.from_uri(conninfo, max_size=5, timeout=3.0, statement_timeout=10.0)
```

```rust
let db = PooledDatabase::from_url_with(conninfo, PoolSettings::default()
    .with_max_size(5)
    .with_connection_timeout(Duration::from_secs(3))
    .with_statement_timeout(Duration::from_secs(10)))?;
```

Behaviour worth knowing:

- **Whoever creates the pool closes it.** Closing a Gatedhouse instance does
  not close the pool, because one pool is commonly shared by `migrate` and
  several instances.
- **The pool opens lazily.** Creating it does not fail if the database is
  briefly unreachable; the first operation reports the problem.
- **Liveness checks only for idle connections.** A connection used within the
  last 0.5 s is handed out straight away; an idle one is checked first, so a
  database restart is noticed without a round trip on every operation.
- HikariCP logs through SLF4J. Without an SLF4J backend it prints a one-time
  "no providers" notice, which is harmless.

## What Gatedhouse guarantees about your connections

These hold for every connection source, in all three SDKs, and each has a
test that runs in CI against PostgreSQL:

| Guarantee | What it means for you |
|---|---|
| Every borrowed connection is returned | including when an operation fails |
| One connection per operation, never two at once | a pool of size 1 cannot deadlock |
| Gatedhouse commits its own work | a pool with autocommit off does not lose writes |
| Connections come back as they were lent | autocommit unchanged, no transaction left open |
| Your transactions are never touched | a connection inside your transaction is refused (Java `IllegalStateException`, Python `RuntimeError`); Rust's API cannot lend one out |
| "No connection" is a distinct error | *unavailable* (pool timeout, database down, connection lost) is separate from a refused statement |
| One instance serves all threads | share it; add no locks of your own |

Gatedhouse operations cannot take part in a transaction of yours: each one
commits on its own. If you create an organization's first admin in your own
transaction and then call Gatedhouse, the Gatedhouse write is committed
independently.

## Bounding query time on your own pool

Gatedhouse never changes the session settings of connections it borrows from
your pool, so it cannot set a statement timeout there. To bound its queries,
set one on the pool or the database role:

| Where | How |
|---|---|
| HikariCP | `connectionInitSql = "SET statement_timeout = 30000"` |
| psycopg_pool | `configure=lambda conn: conn.execute("SET statement_timeout = 30000")` |
| libpq / any driver | connection option `options=-c statement_timeout=30000` |
| database role | `ALTER ROLE app SET statement_timeout = '30s';` |

A statement cancelled by the timeout is reported as an *unavailable* database
error ([chapter 12](12-errors.md)).

## Sizing the pool

Each Gatedhouse operation holds a connection for one query (checks) or one
short transaction (changes). A permission check that misses the cache costs
one query. Size your pool for your own traffic plus your permission checks;
the [permission cache](09-caching.md) removes most of the latter.

## Threads and concurrent writers

Share one Gatedhouse instance across all threads. Concurrent changes, from
threads, processes or other instances of your service, are coordinated by
PostgreSQL itself: membership changes lock the membership row, role
inheritance changes take a database lock, and unique constraints reject
duplicates. Application-level locks would not help, because they cannot see
other processes.
