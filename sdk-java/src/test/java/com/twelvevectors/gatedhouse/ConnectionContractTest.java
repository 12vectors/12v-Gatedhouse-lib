// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

/**
 * The connection contract every Gatedhouse SDK honours with a host's pool.
 * Needs a PostgreSQL database: set GATEDHOUSE_TEST_JDBC_URL to a JDBC URL that
 * carries credentials, e.g.
 * {@code jdbc:postgresql://127.0.0.1:5432/gatedhouse_test?user=gh&password=gh}.
 *
 * <ul>
 *   <li>C1 every borrowed connection is returned, on every path</li>
 *   <li>C2 one connection per operation, never two at once</li>
 *   <li>C3 our writes commit whatever autocommit setting the pool hands out</li>
 *   <li>C4 connections come back with autocommit unchanged and no transaction open</li>
 *   <li>C5 a connection inside the caller's transaction is refused, untouched</li>
 *   <li>C6 no connection available is {@code Kind.UNAVAILABLE}</li>
 *   <li>C7 one Gatedhouse instance is safe to share across threads</li>
 * </ul>
 */
@EnabledIfEnvironmentVariable(named = "GATEDHOUSE_TEST_JDBC_URL", matches = ".+")
class ConnectionContractTest {

    static final String URL = System.getenv("GATEDHOUSE_TEST_JDBC_URL");

    /** Connections exactly as a host pool configured with autoCommit=false hands them out. */
    static final Database AUTOCOMMIT_OFF = () -> {
        Connection c = DriverManager.getConnection(URL);
        c.setAutoCommit(false);
        return c;
    };

    static final Database AUTOCOMMIT_ON = () -> DriverManager.getConnection(URL);

    @BeforeAll
    static void migrate() {
        GatedhouseFactory.migrate(GatedhouseConfig.builder().database(AUTOCOMMIT_ON).build());
    }

    // ---- C3: writes are never lost ---------------------------------------

    @Test
    void writesCommitWhenThePoolHandsOutAutoCommitOff() throws Exception {
        String p = prefix();
        Gatedhouse gh = create(AUTOCOMMIT_OFF);
        gh.roleManager().createRole(p + "r", "R", null);
        gh.permissionCatalog().addService(p + "svc", null);
        gh.membershipManager().createMembership(p + "id", p + "org", EntityType.USER);
        assertTrue(rowExists("SELECT 1 FROM gatedhouse.roles WHERE key = ?", p + "r"));
        assertTrue(rowExists("SELECT 1 FROM gatedhouse.services WHERE service = ?", p + "svc"));
        assertTrue(rowExists("SELECT 1 FROM gatedhouse.memberships WHERE identity_id = ?", p + "id"));
    }

    // ---- C1, C2, C4: every operation, both autocommit modes ---------------

    @Test
    void everyOperationReturnsItsConnectionCleanAndNeverHoldsTwo() {
        for (Database base : List.of(AUTOCOMMIT_ON, AUTOCOMMIT_OFF)) {
            TrackingDatabase db = new TrackingDatabase(base);
            exerciseEveryOperation(create(db), prefix());
            db.assertAllReturnedClean();
            assertEquals(1, db.maxHeldByOneThread.get(), "an operation held two connections at once");
        }
    }

    @Test
    void migratorReturnsItsConnectionAsItFoundIt() {
        TrackingDatabase db = new TrackingDatabase(AUTOCOMMIT_OFF);
        GatedhouseFactory.migrate(GatedhouseConfig.builder().database(db).build());
        db.assertAllReturnedClean();
    }

    // ---- C2 under a real pool: size 1 must not deadlock -------------------

    @Test
    void aPoolOfOneConnectionRunsEveryOperation() {
        PooledDatabase.Settings one = PooledDatabase.Settings.builder()
            .maximumPoolSize(1).connectionTimeout(Duration.ofSeconds(2)).build();
        try (PooledDatabase pool = Database.fromUrl(URL, null, null, one)) {
            assertTimeoutPreemptively(Duration.ofSeconds(60),
                () -> exerciseEveryOperation(create(pool), prefix()));
        }
    }

    // ---- the production path: the host's own pool -------------------------

    @Test
    void hostDataSourceIsBorrowedFromAndReturnedTo() {
        for (boolean autoCommit : new boolean[] {true, false}) {
            try (HikariDataSource host = hostPool(4, autoCommit)) {
                TrackingDatabase db = new TrackingDatabase(Database.fromDataSource(host));
                exerciseEveryOperation(create(db), prefix());
                db.assertAllReturnedClean();
                assertEquals(0, host.getHikariPoolMXBean().getActiveConnections(),
                    "connections still checked out of the host pool");
            }
        }
    }

    // ---- C5: never someone else's transaction ------------------------------

    @Test
    void connectionInsideTheCallersTransactionIsRefusedAndLeftUntouched() throws Exception {
        String p = prefix();
        Gatedhouse gh = create(AUTOCOMMIT_ON);
        try (HikariDataSource host = hostPool(2, true);
             Connection callers = host.getConnection()) {
            // The caller's own unit of work, in progress (as inside @Transactional).
            callers.setAutoCommit(false);
            try (PreparedStatement ps = callers.prepareStatement(
                     "INSERT INTO gatedhouse.services (service) VALUES (?)")) {
                ps.setString(1, p + "callers");
                ps.executeUpdate();
            }
            // A transaction-aware DataSource hands back that same bound
            // connection, and closing it does not end the transaction.
            Database bound = () -> nonClosing(callers);
            Gatedhouse boundGh = new DefaultGatedhouse(GatedhouseConfig.builder().database(bound).build());

            IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> boundGh.roleManager().createRole(p + "r", "R", null));
            assertTrue(e.getMessage().contains("already inside a transaction"), e.getMessage());
            assertThrows(IllegalStateException.class, () -> boundGh.roleManager().hasRole(p + "r"));

            // Nothing of ours ran, nothing of theirs was committed or rolled back.
            assertFalse(rowExists("SELECT 1 FROM gatedhouse.roles WHERE key = ?", p + "r"));
            assertFalse(rowExists("SELECT 1 FROM gatedhouse.services WHERE service = ?", p + "callers"));
            assertEquals("OPEN", Sql.transactionState(callers));
            callers.commit();
            callers.setAutoCommit(true);
        }
        assertTrue(rowExists("SELECT 1 FROM gatedhouse.services WHERE service = ?", p + "callers"));
        assertFalse(gh.roleManager().hasRole(p + "r"));
    }

    // ---- C6: unavailable is typed, and fast ---------------------------------

    @Test
    void exhaustedPoolFailsAsUnavailableWithinItsTimeout() throws Exception {
        PooledDatabase.Settings tiny = PooledDatabase.Settings.builder()
            .maximumPoolSize(1).connectionTimeout(Duration.ofMillis(300)).build();
        try (PooledDatabase pool = Database.fromUrl(URL, null, null, tiny)) {
            Gatedhouse gh = create(pool);
            try (Connection held = pool.getConnection()) {   // the only connection
                long start = System.nanoTime();
                GatedhouseDatabaseException e = assertThrows(GatedhouseDatabaseException.class,
                    () -> gh.hasPermission("a", "b", "s", "r", "x"));
                long elapsedMs = (System.nanoTime() - start) / 1_000_000;
                assertEquals(GatedhouseDatabaseException.Kind.UNAVAILABLE, e.kind());
                assertTrue(elapsedMs < 3000, "gave up after " + elapsedMs + " ms");
            }
            assertFalse(gh.roleManager().hasRole("no-such-role"), "pool recovered");
        }
    }

    @Test
    void unreachableDatabaseFailsStartupAsUnavailable() {
        PooledDatabase.Settings quick = PooledDatabase.Settings.builder()
            .connectionTimeout(Duration.ofMillis(300)).build();
        try (PooledDatabase nowhere = Database.fromUrl(
                 "jdbc:postgresql://127.0.0.1:1/none", "u", "p", quick)) {
            GatedhouseInitializationException e = assertThrows(GatedhouseInitializationException.class,
                () -> create(nowhere));
            GatedhouseDatabaseException cause = assertInstanceOf(GatedhouseDatabaseException.class, e.getCause());
            assertEquals(GatedhouseDatabaseException.Kind.UNAVAILABLE, cause.kind());
        }
    }

    // ---- C7: shared across threads -----------------------------------------

    @Test
    void oneInstanceSharedByManyThreadsOnASmallerPool() throws Exception {
        String p = prefix();
        int threads = 16;
        int rounds = 15;
        try (HikariDataSource host = hostPool(4, false)) {
            TrackingDatabase db = new TrackingDatabase(Database.fromDataSource(host));
            Gatedhouse gh = create(db);
            gh.permissionCatalog().addService(p + "svc", null);
            gh.permissionCatalog().addResource(p + "svc", "doc", null);
            gh.permissionCatalog().addAction(p + "svc", "doc", "read", null);
            gh.roleManager().createRole(p + "reader", "Reader", null);
            gh.roleManager().grantPermission(p + "reader", p + "svc", "doc", "read");

            ExecutorService pool = Executors.newFixedThreadPool(threads);
            try {
                List<Future<?>> done = new ArrayList<>();
                for (int t = 0; t < threads; t++) {
                    String id = p + "user" + t;
                    done.add(pool.submit(() -> {
                        for (int i = 0; i < rounds; i++) {
                            String org = "org" + i;
                            gh.membershipManager().createMembership(id, org, EntityType.USER);
                            gh.roleManager().assignToIdentity(id, org, p + "reader");
                            check(gh.hasPermission(id, org, p + "svc", "doc", "read"), "granted");
                            check(gh.explainPermission(id, org, p + "svc", "doc", "read").outcome()
                                == PermissionExplanation.Outcome.ALLOWED, "explained");
                            gh.membershipManager().removeMembership(id, org);
                            check(!gh.hasPermission(id, org, p + "svc", "doc", "read"), "revoked");
                        }
                        return null;
                    }));
                }
                for (Future<?> f : done) {
                    f.get(120, TimeUnit.SECONDS);   // rethrows any failure in a worker
                }
            } finally {
                pool.shutdownNow();
            }
            db.assertAllReturnedClean();
            assertEquals(0, host.getHikariPoolMXBean().getActiveConnections());
        }
    }

    // ---- role inheritance stays acyclic ------------------------------------

    @Test
    void inheritanceCyclesAreRejected() {
        String p = prefix();
        RoleManager roles = create(AUTOCOMMIT_ON).roleManager();
        for (String r : List.of("a", "b", "c")) {
            roles.createRole(p + r, r, null);
        }
        roles.addParentRole(p + "a", p + "b");
        roles.addParentRole(p + "b", p + "c");
        IllegalArgumentException direct = assertThrows(IllegalArgumentException.class,
            () -> roles.addParentRole(p + "b", p + "a"));
        assertTrue(direct.getMessage().contains("cycle"), direct.getMessage());
        assertThrows(IllegalArgumentException.class, () -> roles.addParentRole(p + "c", p + "a"));
        assertThrows(GatedhouseDatabaseException.class, () -> roles.addParentRole(p + "a", p + "a"));
        roles.addParentRole(p + "a", p + "c");   // a shortcut is not a cycle
        assertEquals(List.of(p + "b", p + "c"), roles.getParentRoles(p + "a"));
    }

    @Test
    void concurrentOppositeEdgesCannotBothSucceed() throws Exception {
        // Also under a pool whose sessions default to SERIALIZABLE: the check
        // must not depend on the host's isolation level.
        String serializable = URL + (URL.contains("?") ? "&" : "?")
            + "options=-c%20default_transaction_isolation%3Dserializable";
        for (String url : List.of(URL, serializable)) {
            String p = prefix();
            RoleManager roles = create(() -> DriverManager.getConnection(url)).roleManager();
            ExecutorService pair = Executors.newFixedThreadPool(2);
            try {
                for (int i = 0; i < 25; i++) {
                    String a = p + "a" + i;
                    String b = p + "b" + i;
                    roles.createRole(a, a, null);
                    roles.createRole(b, b, null);
                    CountDownLatch go = new CountDownLatch(1);
                    Future<Boolean> ab = pair.submit(() -> tryEdge(roles, go, a, b));
                    Future<Boolean> ba = pair.submit(() -> tryEdge(roles, go, b, a));
                    go.countDown();
                    int succeeded = (ab.get(30, TimeUnit.SECONDS) ? 1 : 0)
                                  + (ba.get(30, TimeUnit.SECONDS) ? 1 : 0);
                    assertEquals(1, succeeded, "both or neither of " + a + "<->" + b + " succeeded");
                }
            } finally {
                pair.shutdownNow();
            }
        }
    }

    private static boolean tryEdge(RoleManager roles, CountDownLatch go, String child, String parent)
            throws InterruptedException {
        go.await();
        try {
            roles.addParentRole(child, parent);
            return true;
        } catch (IllegalArgumentException cycle) {
            return false;
        }
    }

    // ---- URL mode is opt-in --------------------------------------------------

    @Test
    void fromUrlWithoutHikariExplainsWhatToAdd() throws Exception {
        String cp = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        URL[] withoutHikari = Arrays.stream(cp.split(File.pathSeparator))
            .filter(entry -> !entry.contains("HikariCP"))
            .map(entry -> {
                try {
                    return new File(entry).toURI().toURL();
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            })
            .toArray(URL[]::new);
        try (URLClassLoader loader = new URLClassLoader(withoutHikari, ClassLoader.getPlatformClassLoader())) {
            Class<?> database = loader.loadClass(Database.class.getName());
            Method fromUrl = database.getMethod("fromUrl", String.class, String.class, String.class);
            InvocationTargetException e = assertThrows(InvocationTargetException.class,
                () -> fromUrl.invoke(null, "jdbc:postgresql://127.0.0.1/x", "u", "p"));
            IllegalStateException cause = assertInstanceOf(IllegalStateException.class, e.getCause());
            assertTrue(cause.getMessage().contains("com.zaxxer:HikariCP"), cause.getMessage());
            // The rest of the library still loads and links without HikariCP.
            assertTrue(database.getMethod("fromDataSource", javax.sql.DataSource.class) != null);
            loader.loadClass(GatedhouseFactory.class.getName()).getMethod("create",
                loader.loadClass(GatedhouseConfig.class.getName()));
        }
    }

    // ---- helpers -------------------------------------------------------------

    /** Calls every operation that touches the database, including failing ones. */
    static void exerciseEveryOperation(Gatedhouse gh, String p) {
        PermissionCatalog cat = gh.permissionCatalog();
        RoleManager roles = gh.roleManager();
        GroupManager groups = gh.groupManager();
        MembershipManager mem = gh.membershipManager();
        String svc = p + "svc";
        String org = p + "org";
        String alice = p + "alice";
        String team = p + "team";

        cat.addService(svc, "d");
        check(cat.hasService(svc) && cat.listServices().contains(svc), "service");
        cat.addResource(svc, "doc", "d");
        check(cat.hasResource(svc, "doc") && cat.listResources(svc).equals(List.of("doc")), "resource");
        cat.addAction(svc, "doc", "read", "d");
        check(cat.hasAction(svc, "doc", "read") && cat.listActions(svc, "doc").equals(List.of("read")), "action");

        roles.createRole(p + "base", "Base", null);
        roles.createRole(p + "viewer", "Viewer", "d");
        roles.grantPermission(p + "base", svc, "doc", "read");
        roles.addParentRole(p + "viewer", p + "base");
        check(roles.hasRole(p + "viewer") && roles.listRoles().contains(p + "viewer"), "role");
        check(roles.getParentRoles(p + "viewer").equals(List.of(p + "base")), "parents");

        mem.createMembership(alice, org, EntityType.USER);
        check(mem.hasMembership(alice, org), "membership");
        check(mem.getStatus(alice, org).orElseThrow() == MembershipStatus.ACTIVE, "status");
        check(mem.getEntityType(alice, org).orElseThrow() == EntityType.USER, "entity type");

        roles.assignToIdentity(alice, org, p + "viewer");
        check(roles.getIdentityRoles(alice, org).equals(List.of(p + "viewer")), "identity roles");
        groups.createGroup(team, org, "Team", null);
        check(groups.hasGroup(team, org) && groups.listGroups(org).equals(List.of(team)), "group");
        groups.addIdentityToGroup(team, org, alice);
        check(groups.getGroupMembers(team, org).equals(List.of(alice)), "members");
        check(groups.getIdentityGroups(alice, org).equals(List.of(team)), "identity groups");
        roles.assignToGroup(team, org, p + "base");
        check(roles.getGroupRoles(team, org).equals(List.of(p + "base")), "group roles");

        check(gh.hasPermission(alice, org, svc, "doc", "read"), "allowed");
        check(!gh.getEffectivePermissions(alice, org).isEmpty(), "effective");
        check(gh.explainPermission(alice, org, svc, "doc", "read").outcome()
            == PermissionExplanation.Outcome.ALLOWED, "explain");
        check(gh.getRoles(alice, org).contains(p + "viewer"), "getRoles");
        check(gh.getGroups(alice, org).contains(team), "getGroups");
        mem.setStatus(alice, org, MembershipStatus.SUSPENDED);
        check(!gh.hasPermission(alice, org, svc, "doc", "read"), "suspended");
        mem.setStatus(alice, org, MembershipStatus.ACTIVE);

        // Failing operations return their connection too.
        assertThrows(GatedhouseDatabaseException.class, () -> roles.createRole(p + "viewer", "dup", null));
        assertThrows(IllegalArgumentException.class, () -> roles.addParentRole(p + "base", p + "viewer"));
        mem.removeMembership(alice, org);
        assertThrows(IllegalStateException.class,
            () -> mem.setStatus(alice, org, MembershipStatus.SUSPENDED));

        roles.revokeFromGroup(team, org, p + "base");
        groups.removeIdentityFromGroup(team, org, alice);
        roles.revokeFromIdentity(alice, org, p + "viewer");
        groups.deleteGroup(team, org);
        roles.removeParentRole(p + "viewer", p + "base");
        roles.revokePermission(p + "base", svc, "doc", "read");
        roles.deleteRole(p + "viewer");
        roles.deleteRole(p + "base");
        cat.removeAction(svc, "doc", "read");
        cat.removeResource(svc, "doc");
        cat.removeService(svc);
    }

    static Gatedhouse create(Database db) {
        return GatedhouseFactory.create(GatedhouseConfig.builder().database(db).build());
    }

    static HikariDataSource hostPool(int size, boolean autoCommit) {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(URL);
        config.setMaximumPoolSize(size);
        config.setAutoCommit(autoCommit);
        config.setPoolName("host-under-test");
        return new HikariDataSource(config);
    }

    static String prefix() {
        return "cc_" + UUID.randomUUID().toString().substring(0, 8) + "_";
    }

    static void check(boolean condition, String what) {
        if (!condition) {
            throw new AssertionError("expected: " + what);
        }
    }

    static boolean rowExists(String sql, String param) throws SQLException {
        try (Connection c = DriverManager.getConnection(URL);
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, param);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    /** A view of a connection whose close() does nothing, like a transaction-bound one. */
    static Connection nonClosing(Connection c) {
        return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
            new Class<?>[] {Connection.class}, (proxy, method, args) -> {
                if (method.getName().equals("close")) {
                    return null;
                }
                try {
                    return method.invoke(c, args);
                } catch (InvocationTargetException e) {
                    throw e.getCause();
                }
            });
    }

    /**
     * Wraps a Database, recording every borrow and every return, and how each
     * connection looked when it came back.
     */
    static final class TrackingDatabase implements Database {
        final Database inner;
        final AtomicInteger borrowed = new AtomicInteger();
        final AtomicInteger returned = new AtomicInteger();
        final AtomicInteger maxHeldByOneThread = new AtomicInteger();
        final ThreadLocal<int[]> held = ThreadLocal.withInitial(() -> new int[1]);
        final List<String> problems = Collections.synchronizedList(new ArrayList<>());

        TrackingDatabase(Database inner) {
            this.inner = inner;
        }

        @Override
        public Connection getConnection() throws SQLException {
            Connection c = inner.getConnection();
            boolean autoCommitAtBorrow = c.getAutoCommit();
            borrowed.incrementAndGet();
            int[] mine = held.get();
            mine[0]++;
            maxHeldByOneThread.accumulateAndGet(mine[0], Math::max);
            boolean[] closed = {false};
            return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                new Class<?>[] {Connection.class}, (proxy, method, args) -> {
                    if (method.getName().equals("close")) {
                        if (!closed[0]) {
                            closed[0] = true;
                            if (c.getAutoCommit() != autoCommitAtBorrow) {
                                problems.add("returned with autocommit " + c.getAutoCommit()
                                    + ", borrowed with " + autoCommitAtBorrow);
                            }
                            String state = Sql.transactionState(c);
                            if (state != null && !state.equals("IDLE")) {
                                problems.add("returned with transaction " + state);
                            }
                            mine[0]--;
                            returned.incrementAndGet();
                            c.close();
                        }
                        return null;
                    }
                    try {
                        return method.invoke(c, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
        }

        void assertAllReturnedClean() {
            assertTrue(borrowed.get() > 0, "nothing was borrowed");
            assertEquals(borrowed.get(), returned.get(), "borrowed vs returned");
            assertEquals(List.of(), problems);
        }
    }
}
