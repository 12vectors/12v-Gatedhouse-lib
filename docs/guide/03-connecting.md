# 3. Connecting to the database

A `Database` supplies connections. Gatedhouse borrows one per operation and
returns it when the operation ends. It opens its own connections only in URL
mode.

| Source | Use for | Gatedhouse opens connections |
|---|---|---|
| your application's pool | production | no |
| custom adapter | other pools | no |
| URL | development, staging, scripts | yes (own pool) |

## Your application's pool

**Java**: any `javax.sql.DataSource` (HikariCP, Agroal, DBCP2, Tomcat JDBC,
JNDI, Spring Boot's pool). Pass the plain pooled `DataSource`, not a
`TransactionAwareDataSourceProxy`. A pool with `autoCommit=false` is supported.

```java
Database db = Database.fromDataSource(dataSource);
Database custom = () -> myPool.borrowConnection();   // any other source; Gatedhouse closes each connection
```

```java
@Bean(destroyMethod = "close")   // Spring Boot
Gatedhouse gatedhouse(DataSource dataSource) {
    return GatedhouseFactory.create(GatedhouseConfig.builder()
        .database(Database.fromDataSource(dataSource)).build());
}
```

**Python**: a synchronous `psycopg_pool.ConnectionPool`. `from_pool` raises
`TypeError` for an `AsyncConnectionPool`; async frameworks call Gatedhouse via
`asyncio.to_thread`. With pre-forking servers (gunicorn, uWSGI), open the pool
after the fork.

```python
db = Database.from_pool(pool)
```

A custom `Database` subclass returns, from `connection()`, a context manager
that yields a psycopg connection and returns it on exit. Returning
`pool.getconn()` leaks connections. SQLAlchemy recipe (tested in CI):

```python
class SQLAlchemyDatabase(Database):
    def __init__(self, engine):
        self._engine = engine                 # create_engine("postgresql+psycopg://...")

    @contextlib.contextmanager
    def connection(self):
        raw = self._engine.raw_connection()
        try:
            yield raw.driver_connection
        finally:
            raw.close()
```

**Rust**: with feature `r2d2`, an `r2d2::Pool<PostgresConnectionManager<_>>`
is a `Database`. Any other pool: `from_fn` returning a boxed handle that
derefs to `postgres::Client`.

```rust
let db: Arc<dyn Database> = Arc::new(pool.clone());                  // r2d2
let db: Arc<dyn Database> = Arc::new(gatedhouse::from_fn(move || {
    Ok(Box::new(my_pool.get()?) as gatedhouse::PooledClient)
}));
```

## URL mode

| | Java | Python | Rust |
|---|---|---|---|
| requires | `com.zaxxer:HikariCP` | `gatedhouse[pool]` | feature `r2d2` |
| create | `Database.fromUrl(url, user, pwd[, settings])` | `Database.from_uri(conninfo, **settings)` | `PooledDatabase::from_url(conninfo)?` / `from_url_with(conninfo, settings)?` |
| TLS | JDBC URL parameters | `sslmode` in the URL | `PooledDatabase::from_url_with_tls(conninfo, connector, settings)?` |
| close | `close()` | `close()` / `with` | drop the last `Arc` |
| dependency missing | `IllegalStateException` | `ImportError` | compile error |

| Setting | Java `PooledDatabase.Settings` | Python | Rust `PoolSettings` | Default |
|---|---|---|---|---|
| max connections | `maximumPoolSize` | `max_size` | `with_max_size` | 10 |
| wait for a connection | `connectionTimeout` | `timeout` | `with_connection_timeout` | 10 s |
| connection max age | `maxLifetime` | `max_lifetime` | `with_max_lifetime` | 30 min |
| statement timeout (0 = none) | `statementTimeout` | `statement_timeout` | `with_statement_timeout` | 30 s |

- Closing a `Gatedhouse` does not close the pool.
- The pool opens lazily; an unreachable database is reported by the first
  operation.
- A connection used within the last 0.5 s is handed out without a liveness
  check; idle connections are checked.
- Without an SLF4J backend, HikariCP prints a one-time notice.

## Guarantees (all SDKs, tested in CI)

- Every borrowed connection is returned, including on errors.
- One connection per operation, never two at once (a pool of size 1 works).
- Gatedhouse commits or rolls back its own work; writes are explicit
  `READ COMMITTED` transactions.
- Connections are returned with autocommit unchanged and no open transaction.
- A connection already inside the caller's transaction is refused (Java
  `IllegalStateException`, Python `RuntimeError`); Rust's API cannot lend one.
- No connection available → database error of kind `UNAVAILABLE`.
- Gatedhouse operations never join the caller's transaction; each commits
  independently.
- One instance is safe for concurrent use. Concurrent writers (any process)
  are serialized by PostgreSQL row locks, an advisory lock for inheritance
  edits, and unique constraints.

## Statement timeout on your own pool

Gatedhouse does not change settings on borrowed connections. Set a timeout on
the pool or role:

| Where | Setting |
|---|---|
| HikariCP | `connectionInitSql = "SET statement_timeout = 30000"` |
| psycopg_pool | `configure=lambda c: c.execute("SET statement_timeout = 30000")` |
| libpq | `options=-c statement_timeout=30000` |
| role | `ALTER ROLE app SET statement_timeout = '30s'` |

## Pool sizing

A check without a cache hit uses one connection for one query; a change uses
one short transaction. Size the pool for application traffic plus permission
checks.
