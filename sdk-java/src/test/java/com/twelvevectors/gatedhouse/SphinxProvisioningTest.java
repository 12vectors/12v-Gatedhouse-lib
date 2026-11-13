// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@link SphinxClient#createPerson} against a stub Sphinx (wire contract APP-PROV-1). */
class SphinxProvisioningTest {

    static final String TOKEN_PATH = "/api/sphinx/v1/oauth/token";
    static final String PERSONS_PATH = "/api/sphinx/v1/persons";

    static final String CREATED = """
        {"data":{"id":"per_01J","email":"jane@cicero-client.com","email_verified":false,
         "display_name":"Jane Doe","phone":"+35799123456","phone_verified":false,
         "allow_auto_link":true,"status":"pending_verification","failed_login_attempts":0,
         "last_login_at":null,"last_login_method":null,"created_at":"2026-11-12T10:00:00Z"},
         "meta":{"password_reset_sent":true}}""";

    record Request(String method, String path, Map<String, List<String>> headers, String body) {
        String header(String name) {
            List<String> v = headers.get(name);
            return v == null ? null : v.get(0);
        }
    }

    /** A stub Sphinx: records requests; answers each path with the configured response. */
    static final class StubSphinx implements AutoCloseable {
        final HttpServer server;
        final List<Request> requests = Collections.synchronizedList(new ArrayList<>());
        final AtomicLong tokensIssued = new AtomicLong();
        volatile int tokenStatus = 200;
        volatile String tokenBody = null;   // null: a fresh token each time
        volatile int expiresIn = 3600;
        volatile long tokenDelayMillis = 0;
        volatile int personsStatus = 201;
        volatile String personsBody = CREATED;

        StubSphinx() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setExecutor(Executors.newCachedThreadPool());
            server.createContext("/", ex -> {
                String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String path = ex.getRequestURI().getPath();
                requests.add(new Request(ex.getRequestMethod(), path,
                    Map.copyOf(ex.getRequestHeaders()), body));
                int status;
                String answer;
                if (path.equals(TOKEN_PATH)) {
                    sleep(tokenDelayMillis);
                    status = tokenStatus;
                    answer = tokenBody != null ? tokenBody
                        : "{\"access_token\":\"tok-" + tokensIssued.incrementAndGet()
                          + "\",\"token_type\":\"Bearer\",\"expires_in\":" + expiresIn
                          + ",\"scope\":\"persons:create\"}";
                } else {
                    status = personsStatus;
                    answer = personsBody;
                }
                byte[] bytes = answer.getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().add("Content-Type", "application/json");
                ex.sendResponseHeaders(status, bytes.length);
                try (OutputStream out = ex.getResponseBody()) {
                    out.write(bytes);
                }
            });
            server.start();
        }

        String url() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        List<Request> to(String path) {
            synchronized (requests) {
                return requests.stream().filter(r -> r.path().equals(path)).toList();
            }
        }

        static void sleep(long millis) {
            try {
                Thread.sleep(millis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    StubSphinx sphinx;
    final AtomicLong nanos = new AtomicLong(1_000_000_000L);
    SphinxClient client;

    @BeforeEach
    void start() throws IOException {
        sphinx = new StubSphinx();
        client = new SphinxClient(sphinx.url(), "sph_app", "sps_secret",
            Duration.ofSeconds(2), nanos::get);
    }

    @AfterEach
    void stop() {
        sphinx.close();
    }

    static NewPerson jane() {
        return NewPerson.builder("jane@cicero-client.com").build();
    }

    void advance(Duration d) {
        nanos.addAndGet(d.toNanos());
    }

    SphinxException refusal(NewPerson person) {
        return assertThrows(SphinxException.class, () -> client.createPerson(person));
    }

    // ---- happy path ---------------------------------------------------------

    @Test
    void mintsAnAppTokenThenPostsThePersonAsJson() throws Exception {
        ProvisionedPerson p = client.createPerson(NewPerson.builder("jane@cicero-client.com")
            .displayName("Jane Doe").phone("+357 99 123456")
            .emailVerified(false).allowAutoLink(true).build());

        Request token = sphinx.to(TOKEN_PATH).get(0);
        assertEquals("POST", token.method());
        assertEquals("grant_type=client_credentials&client_id=sph_app&client_secret=sps_secret"
            + "&scope=persons%3Acreate", token.body());

        Request post = sphinx.to(PERSONS_PATH).get(0);
        assertEquals("POST", post.method());
        assertEquals("Bearer tok-1", post.header("Authorization"));
        assertEquals("application/json", post.header("Content-type"));
        assertEquals("application/json", post.header("Accept"));
        assertEquals(Map.of("email", "jane@cicero-client.com", "display_name", "Jane Doe",
                "phone", "+357 99 123456", "email_verified", false, "allow_auto_link", true),
            JSONObjectUtils.parse(post.body()));

        assertEquals(new ProvisionedPerson("per_01J", "jane@cicero-client.com", false,
            "Jane Doe", "+35799123456", false, true, "pending_verification",
            Instant.parse("2026-11-12T10:00:00Z"), true), p);
    }

    @Test
    void unsetOptionalFieldsAreOmittedNotNull() throws Exception {
        client.createPerson(jane());
        assertEquals(Map.of("email", "jane@cicero-client.com"),
            JSONObjectUtils.parse(sphinx.to(PERSONS_PATH).get(0).body()));
    }

    @Test
    void nullDisplayNameAndPhoneAreParsedAsNull() {
        sphinx.personsBody = CREATED.replace("\"Jane Doe\"", "null").replace("\"+35799123456\"", "null");
        ProvisionedPerson p = client.createPerson(jane());
        assertNull(p.displayName());
        assertNull(p.phone());
    }

    @Test
    void createdAtAcceptsFractionsAndOffsets() {
        sphinx.personsBody = CREATED.replace("2026-11-12T10:00:00Z", "2026-11-12T10:00:00.123456789Z");
        assertEquals(Instant.parse("2026-11-12T10:00:00.123456789Z"), client.createPerson(jane()).createdAt());
        sphinx.personsBody = CREATED.replace("2026-11-12T10:00:00Z", "2026-11-12T12:00:00+02:00");
        assertEquals(Instant.parse("2026-11-12T10:00:00Z"), client.createPerson(jane()).createdAt());
    }

    // ---- token caching ------------------------------------------------------

    @Test
    void secondCallReusesTheTokenSoMakesOneRequest() {
        client.createPerson(jane());
        int before = sphinx.requests.size();
        client.createPerson(jane());
        assertEquals(1, sphinx.requests.size() - before, "only the POST");
        assertEquals(1, sphinx.to(TOKEN_PATH).size());
        assertEquals("Bearer tok-1", sphinx.to(PERSONS_PATH).get(1).header("Authorization"));
    }

    @Test
    void tokenIsReplacedSixtySecondsBeforeItExpires() {
        client.createPerson(jane());
        advance(Duration.ofSeconds(3600 - 60).minusNanos(1));
        client.createPerson(jane());
        assertEquals(1, sphinx.to(TOKEN_PATH).size(), "still inside the usable window");
        advance(Duration.ofNanos(1));
        client.createPerson(jane());
        assertEquals(2, sphinx.to(TOKEN_PATH).size());
        assertEquals("Bearer tok-2", sphinx.to(PERSONS_PATH).get(2).header("Authorization"));
    }

    @Test
    void aTokenTooShortLivedForTheMarginIsUsedOnceNotCached() {
        sphinx.expiresIn = 60;
        client.createPerson(jane());
        client.createPerson(jane());
        assertEquals(2, sphinx.to(TOKEN_PATH).size());
    }

    @Test
    void concurrentCallersShareOneMint() throws Exception {
        sphinx.tokenDelayMillis = 300;
        int callers = 8;
        ExecutorService pool = Executors.newFixedThreadPool(callers);
        try {
            CountDownLatch go = new CountDownLatch(1);
            List<Future<ProvisionedPerson>> results = new ArrayList<>();
            for (int i = 0; i < callers; i++) {
                results.add(pool.submit(() -> {
                    go.await();
                    return client.createPerson(jane());
                }));
            }
            go.countDown();
            for (Future<ProvisionedPerson> r : results) {
                r.get(10, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(1, sphinx.to(TOKEN_PATH).size());
        assertEquals(callers, sphinx.to(PERSONS_PATH).size());
    }

    // ---- edge cases (spec table) ----------------------------------------------

    @Test
    void appNotPrivilegedIsUnauthorizedClientAndNothingIsPosted() {
        sphinx.tokenStatus = 400;
        sphinx.tokenBody = "{\"error\":\"unauthorized_client\",\"detail\":\"not privileged\"}";
        SphinxException e = refusal(jane());
        assertEquals(SphinxException.Kind.HTTP_STATUS, e.kind());
        assertEquals(400, e.statusCode().getAsInt());
        assertEquals("unauthorized_client", e.errorCode().orElseThrow());
        assertTrue(sphinx.to(PERSONS_PATH).isEmpty());
    }

    @Test
    void wrongSecretOrRevokedAppIsInvalidClient() {
        sphinx.tokenStatus = 401;
        sphinx.tokenBody = "{\"error\":\"invalid_client\",\"detail\":\"Invalid client credentials\"}";
        SphinxException e = refusal(jane());
        assertEquals(401, e.statusCode().getAsInt());
        assertEquals("invalid_client", e.errorCode().orElseThrow());
    }

    @Test
    void forbiddenKeepsTheCachedToken() {
        client.createPerson(jane());
        sphinx.personsStatus = 403;
        sphinx.personsBody = "{\"error\":\"forbidden\",\"detail\":\"domain not accepted\"}";
        SphinxException e = refusal(jane());
        assertEquals(403, e.statusCode().getAsInt());
        assertEquals("forbidden", e.errorCode().orElseThrow());
        sphinx.personsStatus = 201;
        sphinx.personsBody = CREATED;
        client.createPerson(jane());
        assertEquals(1, sphinx.to(TOKEN_PATH).size(), "403 must not drop a valid token");
    }

    @Test
    void unauthorizedDropsTheCachedTokenWithoutRetrying() {
        client.createPerson(jane());
        sphinx.personsStatus = 401;
        sphinx.personsBody = "{\"error\":\"unauthorized\",\"detail\":\"Invalid or expired token\"}";
        SphinxException e = refusal(jane());
        assertEquals(401, e.statusCode().getAsInt());
        assertEquals(2, sphinx.to(PERSONS_PATH).size(), "no automatic retry");
        assertEquals(1, sphinx.to(TOKEN_PATH).size(), "no automatic re-mint");
        sphinx.personsStatus = 201;
        sphinx.personsBody = CREATED;
        client.createPerson(jane());
        assertEquals(2, sphinx.to(TOKEN_PATH).size(), "the next call mints a fresh token");
        assertEquals("Bearer tok-2", sphinx.to(PERSONS_PATH).get(2).header("Authorization"));
    }

    @Test
    void existingEmailIsConflict() {
        sphinx.personsStatus = 409;
        sphinx.personsBody = "{\"error\":\"conflict\",\"detail\":\"A person with this email already exists\"}";
        SphinxException e = refusal(jane());
        assertEquals(409, e.statusCode().getAsInt());
        assertEquals("conflict", e.errorCode().orElseThrow());
    }

    @Test
    void invalidEmailOrPhoneIsBadRequestWithItsCode() {
        for (String code : List.of("invalid_email", "invalid_phone", "bad_request")) {
            sphinx.personsStatus = 400;
            sphinx.personsBody = "{\"error\":\"" + code + "\",\"detail\":\"x\"}";
            SphinxException e = refusal(jane());
            assertEquals(400, e.statusCode().getAsInt());
            assertEquals(code, e.errorCode().orElseThrow());
        }
    }

    @Test
    void nullOrBlankEmailIsRejectedBeforeAnyRequest() {
        assertThrows(IllegalArgumentException.class, () -> NewPerson.builder(null).build());
        assertThrows(IllegalArgumentException.class, () -> NewPerson.builder("  ").build());
        assertThrows(IllegalArgumentException.class,
            () -> new NewPerson("", null, null, null, null));
        assertThrows(NullPointerException.class, () -> client.createPerson(null));
        assertTrue(sphinx.requests.isEmpty());
    }

    @Test
    void nonJsonErrorBodyHasNoErrorCode() {
        sphinx.personsStatus = 502;
        sphinx.personsBody = "<html>Bad Gateway</html>";
        SphinxException e = refusal(jane());
        assertEquals(502, e.statusCode().getAsInt());
        assertTrue(e.errorCode().isEmpty());
    }

    @Test
    void malformedSuccessBodyIsInvalidResponse() {
        for (String body : List.of("not json", "{}", "{\"data\":{},\"meta\":{}}",
                CREATED.replace("\"2026-11-12T10:00:00Z\"", "\"yesterday\""),
                CREATED.replace("\"email_verified\":false", "\"email_verified\":\"no\""),
                CREATED.replace(",\n \"meta\":{\"password_reset_sent\":true}", ""))) {
            sphinx.personsBody = body;
            SphinxException e = refusal(jane());
            assertEquals(SphinxException.Kind.INVALID_RESPONSE, e.kind(), body);
        }
    }

    @Test
    void tokenResponseWithoutAccessTokenIsInvalidResponse() {
        sphinx.tokenBody = "{\"token_type\":\"Bearer\",\"expires_in\":3600}";
        assertEquals(SphinxException.Kind.INVALID_RESPONSE, refusal(jane()).kind());
        assertTrue(sphinx.to(PERSONS_PATH).isEmpty());
    }

    @Test
    void unresponsivePersonsEndpointTimesOut() throws IOException {
        try (ServerSocket blackHole = new ServerSocket(0)) {
            // Tokens from the stub; the person POST to a port that accepts and never answers.
            SphinxClient c = new SphinxClient("http://127.0.0.1:" + blackHole.getLocalPort(),
                "sph_app", "sps_secret", Duration.ofMillis(300));
            Thread acceptor = new Thread(() -> {
                try {
                    List<java.net.Socket> held = new ArrayList<>();
                    while (true) {
                        held.add(blackHole.accept());
                    }
                } catch (IOException closed) {
                    // closed
                }
            });
            acceptor.setDaemon(true);
            acceptor.start();
            SphinxException e = assertThrows(SphinxException.class, () -> c.createPerson(jane()));
            assertEquals(SphinxException.Kind.TIMEOUT, e.kind());
        }
    }

    @Test
    void unreachableSphinxIsTransport() throws IOException {
        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        SphinxClient c = new SphinxClient("http://127.0.0.1:" + port, "sph_app", "sps_secret",
            Duration.ofMillis(500));
        assertEquals(SphinxException.Kind.TRANSPORT,
            assertThrows(SphinxException.class, () -> c.createPerson(jane())).kind());
    }

    @Test
    void existingTokenCallsNowCarryTheErrorCodeToo() {
        sphinx.tokenStatus = 400;
        sphinx.tokenBody = "{\"error\":\"invalid_grant\",\"detail\":\"code already used\"}";
        SphinxException e = assertThrows(SphinxException.class,
            () -> client.exchangeCode("code", "http://cb"));
        assertEquals("invalid_grant", e.errorCode().orElseThrow());
        assertFalse(e.getMessage().contains("sps_secret"), "the secret is never in a message");
    }
}
