# Mission Specification: RFC 6750 WWW-Authenticate Header

**Mission Slug**: `rfc6750-www-authenticate-01M082AR`
**Mission Type**: software-dev
**Created**: 2026-08-17
**Status**: Draft

## Purpose

**TL;DR**: Make 401 responses from Gatedhouse web guards standards-compliant so
any HTTP client can discover that Bearer authentication is required.

Gatedhouse's API guards across all three SDKs reject unauthenticated requests
with a 401 status and a JSON body, but the response omits the
`WWW-Authenticate` challenge header that the HTTP specification (RFC 7235) and
the Bearer token usage specification (RFC 6750) require on every 401. Generic
HTTP tooling, API gateways, and standards-compliant client libraries rely on
that header to discover which authentication scheme a protected resource
expects. This mission adds the bare `WWW-Authenticate: Bearer` challenge to
every 401 produced by the guards, in all three SDKs, without changing any other
aspect of the response.

## User Scenarios & Testing

### Primary Scenario

1. A client application calls a Gatedhouse-protected API endpoint without any
   credentials (or with an expired/invalid token).
2. The guard rejects the request with HTTP 401.
3. The 401 response now carries the header `WWW-Authenticate: Bearer` alongside
   the existing JSON error body and security headers.
4. The client (or its HTTP library) inspects the header, learns that Bearer
   authentication is expected, and can initiate the correct authentication flow
   automatically.

### Exception / Edge Scenarios

- A request that is authenticated but lacks privileges (403 Forbidden) is
  **unchanged** — RFC 6750 reserves the challenge for 401 only.
- Browser-facing pages guarded by the web (session) guard redirect to the login
  page (302) rather than returning 401 — that behavior is **unchanged**.
- WebSocket handshakes rejected by the guards close the connection as today;
  where a 401-style HTTP rejection is produced, it carries the header like any
  other 401.
- Requests that pass authentication are completely unaffected.

### Testing Expectations

- Each SDK's 401 test paths — extended where they exist, created where absent
  (the Java SDK has no test suite yet) — assert the presence and exact value
  of the new header.
- Existing assertions about the 401 JSON body and security headers continue to
  pass unmodified, proving the invariant that nothing else changed.

## Domain Language

- **Challenge header**: the `WWW-Authenticate` response header; the canonical
  term in this mission is "challenge header". The value shipped is the **bare
  scheme** form `Bearer` with no auth-params.
- **API guard**: the request interceptor protecting JSON/API endpoints
  (returns 401). Distinct from the **web guard** (browser session flow,
  redirects to login).

## Requirements

### Functional Requirements

| ID | Requirement | Status |
|----|-------------|--------|
| FR-001 | Every HTTP 401 response produced by an API guard includes the response header `WWW-Authenticate` with the exact value `Bearer`. | Confirmed |
| FR-002 | The challenge header is emitted for both causes of 401: missing/malformed credentials and failed token verification. | Confirmed |
| FR-003 | All three Gatedhouse SDKs (Java, Python, Rust) emit the identical header name and value, preserving cross-SDK contract parity. | Confirmed |
| FR-004 | In the Python SDK, both server integration styles (synchronous and asynchronous request pipelines) emit the header. | Confirmed |
| FR-005 | In the Rust SDK, the framework-agnostic guard result exposes the challenge header so host applications emit it without hand-coding the value. | Confirmed |

### Non-Functional Requirements

| ID | Requirement | Status |
|----|-------------|--------|
| NFR-001 | No measurable latency change on the request path: the header is a constant added at response-write time (zero additional allocation on the happy path, no I/O). | Confirmed |
| NFR-002 | Public API compatibility: no existing public method signature, constant, or response field is removed or altered; the change is additive and ships in a minor version. | Confirmed |

### Constraints

| ID | Constraint | Status |
|----|-----------|--------|
| C-001 | The existing 401 JSON body (`{"error": "unauthorized", "detail": ...}`) is byte-for-byte unchanged. | Confirmed |
| C-002 | The existing security headers on guard responses are unchanged. | Confirmed |
| C-003 | 403 Forbidden responses do not gain the challenge header. | Confirmed |
| C-004 | The web (session) guard's redirect-to-login behavior is unchanged. | Confirmed |
| C-005 | The header value is the bare scheme `Bearer` — no `error`, `error_description`, `realm`, or other auth-params (per user decision during discovery). | Confirmed |

## Success Criteria

- 100% of unauthenticated requests to guard-protected API endpoints receive a
  response that names the expected authentication scheme, verifiable with any
  off-the-shelf HTTP client.
- Standards-compliance check: the 401 responses satisfy RFC 7235 §4.1 ("a
  server generating a 401 response MUST send a WWW-Authenticate header field").
- Zero regressions: every pre-existing automated test in all three SDKs passes
  without modification to its assertions about bodies, statuses, redirects, or
  other headers.

## Assumptions

- The bare `Bearer` challenge (no auth-params) is sufficient; clients needing
  failure detail already receive it in the JSON body. (Confirmed by user.)
- Host applications embedding the Rust guard are responsible for copying the
  exposed header onto their framework's response object, consistent with how
  they already emit the status, body, and security headers.
- No configuration knob is needed to disable the header; it is unconditional,
  as the RFC mandates it.

## Out of Scope

- RFC 6750 auth-params (`error`, `error_description`, `scope`, `realm`).
- Any change to 403 responses, login redirects, or WebSocket close semantics.
- Documentation-site updates beyond the SDK READMEs' guard sections.
