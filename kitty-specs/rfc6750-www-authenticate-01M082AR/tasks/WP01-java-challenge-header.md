---
work_package_id: WP01
title: Java servlet filter challenge header
dependencies: []
requirement_refs:
- C-001
- C-002
- C-003
- FR-001
- FR-002
- FR-003
- NFR-001
- NFR-002
tracker_refs: []
planning_base_branch: claude/library-parity-python-rust-java-30h29l
merge_target_branch: claude/library-parity-python-rust-java-30h29l
branch_strategy: Planning artifacts for this mission were generated on claude/library-parity-python-rust-java-30h29l. During /spec-kitty.implement this WP may branch from a dependency-specific base, but completed changes must merge back into claude/library-parity-python-rust-java-30h29l unless the human explicitly redirects the landing branch.
subtasks:
- T001
- T002
- T003
- T004
agent: "claude"
shell_pid: "27535"
history:
- '2026-08-17: created by /spec-kitty.tasks'
agent_profile: java-jenny
authoritative_surface: sdk-java/src/main/java/com/twelvevectors/gatedhouse/
create_intent: []
execution_mode: code_change
owned_files:
- sdk-java/src/main/java/com/twelvevectors/gatedhouse/GatedhouseApiFilter.java
- sdk-java/src/test/**
- sdk-java/pom.xml
role: implementer
tags: []
---

## ⚡ Do This First: Load Agent Profile

Before reading further, load your assigned agent profile so this work runs
under the right identity and boundaries:

```
/ad-hoc-profile-load implementer --mission rfc6750-www-authenticate-01M082AR
```

## Objective

Every 401 written by `GatedhouseApiFilter` must carry the response header
`WWW-Authenticate: Bearer` (exact name, exact value, no auth-params), per
RFC 7235 §4.1 / RFC 6750 §3, without changing the JSON body, the security
headers, or any non-401 behavior. Ship the first real unit test for the filter.

## Context

- Contract: `kitty-specs/rfc6750-www-authenticate-01M082AR/contracts/401-response.md`
  (the full 401 response with the one new header marked).
- All three 401 call sites already funnel through the private
  `sendJsonError(resp, 401, "unauthorized", ...)` helper at the bottom of
  `GatedhouseApiFilter.java` — that helper is the single choke point.
- `sendJsonError` takes a `status` parameter; today it is only ever called
  with 401, but the header MUST be conditional on `status == 401` so future
  403 reuse stays RFC-correct (constraint C-003).
- sdk-java has no test infrastructure yet: no JUnit dependency, no
  `src/test/` directory. Java verification so far has been `mvn compile` +
  the DB-backed smoke-test CLI, which never exercises the servlet filter.

### Subtask T001: Constant + conditional header in sendJsonError

In `sdk-java/src/main/java/com/twelvevectors/gatedhouse/GatedhouseApiFilter.java`:

1. Add beside the existing public constants:
   ```java
   /** RFC 6750 challenge sent on every 401 response ({@code WWW-Authenticate: Bearer}). */
   public static final String WWW_AUTHENTICATE_CHALLENGE = "Bearer";
   ```
2. In `sendJsonError`, before writing the body:
   ```java
   if (status == 401) {
       resp.setHeader("WWW-Authenticate", WWW_AUTHENTICATE_CHALLENGE);
   }
   ```
3. Update the class javadoc's one-liner ("returns a clean 401 JSON response")
   to mention the RFC 6750 challenge header.

Validation: `cd sdk-java && mvn -q compile` passes.

### Subtask T002: JUnit 5 + Surefire in pom.xml

In `sdk-java/pom.xml`:

1. Add test-scoped dependency `org.junit.jupiter:junit-jupiter:5.10.2`
   (`<scope>test</scope>`). Test scope means the published artifact and its
   POM's compile-scope dependency list are unchanged (NFR-002).
2. Add `maven-surefire-plugin` 3.2.5 to `<build><plugins>` so `mvn test`
   discovers JUnit 5 tests.
3. Do NOT touch the `central` release profile, versions, or any existing
   dependency.

Validation: `mvn -q test` runs (0 tests before T003, then green after).

### Subtask T003: GatedhouseApiFilterTest with servlet fakes

Create `sdk-java/src/test/java/com/twelvevectors/gatedhouse/GatedhouseApiFilterTest.java`
(new directory — first Java unit test in the repo; include the standard
3-line copyright header used by every source file).

Hand-roll fakes — no Mockito, no new runtime deps:

- A fake `HttpServletRequest` (extend nothing; implement via
  `jakarta.servlet.http.HttpServletRequest` is huge — instead use a tiny
  dynamic proxy: `java.lang.reflect.Proxy` handling `getHeader`,
  `setAttribute`, `getAttribute`, and defaulting everything else) — or
  equivalently a minimal anonymous implementation of only the methods the
  filter calls. The proxy route is ~20 lines; prefer it.
- A fake `HttpServletResponse` capturing `setStatus`, `setHeader` (into a
  `LinkedHashMap<String,String>`), `setContentType`, `setCharacterEncoding`,
  and `getWriter` (backed by a `StringWriter`). Same proxy technique.
- A stub `Gatedhouse` via `Proxy` whose `verifyToken` throws
  `new TokenVerificationException(...)` (check its constructor signature in
  `TokenVerificationException.java` and use whichever reason/message form
  compiles).

Test cases:

1. `missingTokenGets401WithChallenge`: no `Authorization` header →
   status 401, header map contains `WWW-Authenticate: Bearer`.
2. `invalidTokenGets401WithChallenge`: `Authorization: Bearer bad` and the
   stub throwing → status 401, same header.

### Subtask T004: Invariant assertions

In the same two tests, additionally assert (constraints C-001/C-002):

- Body written to the writer is exactly
  `{"error":"unauthorized","detail":"Missing or invalid Bearer token"}` (case 1)
  and starts with `{"error":"unauthorized","detail":"Token verification failed:`
  (case 2).
- Security headers all present with today's exact values:
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: strict-origin-when-cross-origin`.
- Content type `application/json`.

## Definition of Done

- [ ] `mvn -q test` green in `sdk-java/`
- [ ] Header emitted on both 401 causes; conditional on status 401 in code
- [ ] Body, security headers, content type asserted unchanged
- [ ] No new runtime (non-test) dependencies; release profile untouched
- [ ] Copyright header on the new test file

## Reviewer guidance

Diff should be small: ~6 lines in the filter, a test-scope pom addition, one
new test file. Reject if the header write is unconditional (not gated on 401)
or if any runtime dependency scope changed.

## Activity Log

- 2026-08-17T15:02:15Z – claude – shell_pid=22810 – Assigned agent via action command
- 2026-08-17T15:04:37Z – claude – shell_pid=22810 – Ready for review: 3/3 tests green
- 2026-08-17T15:05:02Z – claude – shell_pid=27535 – Started review via action command
- 2026-08-17T15:05:36Z – user – shell_pid=27535 – Review passed: conditional 401 challenge, test-scope-only deps, invariants asserted, 3/3 green
