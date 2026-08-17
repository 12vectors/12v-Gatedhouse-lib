# Research: RFC 6750 WWW-Authenticate Header

## R-1: Is the header mandatory, and on which responses?

- **Decision**: Emit on every 401 from the API guards; never on 403; never on
  the web guard's 302 login redirect.
- **Rationale**: RFC 7235 §4.1: "A server generating a 401 (Unauthorized)
  response MUST send a WWW-Authenticate header field containing at least one
  challenge." RFC 6750 §3 defines the `Bearer` scheme challenge for
  OAuth-protected resources. 403 means the identity was accepted but lacks
  privilege — no challenge is defined or useful there. A 302 is not a 401.
- **Alternatives considered**: emitting on 403 too (rejected — contradicts RFC
  semantics and constraint C-003).

## R-2: Bare challenge vs. auth-params

- **Decision**: Bare `WWW-Authenticate: Bearer` on all 401s.
- **Rationale**: User decision during specify discovery (recorded as C-005).
  RFC 6750 §3.1 states that when the request lacks credentials entirely the
  server SHOULD NOT include an error code — so the bare form is the correct
  default for the missing-token case, and acceptable for the invalid-token
  case; the JSON body already distinguishes the causes for humans and
  structured clients.
- **Alternatives considered**: `error="invalid_token"` on verification
  failures (rejected by user: more per-SDK logic for marginal client value).

## R-3: Where does the header get added in each SDK?

- **Decision**: At each SDK's single 401 choke point, conditional on status.
  - Java: `GatedhouseApiFilter.sendJsonError` adds the header when
    `status == 401` (three call sites, all 401 — but the guard keeps the
    condition so future reuse for 403 stays correct).
  - Python WSGI: `_web.py::_send_json_error` adds it when the status line is
    `"401 Unauthorized"`.
  - Python ASGI: `asgi.py::_send_json_error` adds it (bytes pair) when
    `status == 401`.
  - Rust: guards return decisions rather than writing responses, so
    `filters.rs` exposes `pub const WWW_AUTHENTICATE: (&str, &str)` and
    `FilterError::challenge_header() -> Option<(&'static str, &'static str)>`
    (Some for `Unauthorized`, None for `Forbidden`), and hosts copy it exactly
    as they already copy `SECURITY_HEADERS`.
- **Rationale**: one write point per surface keeps the invariant provable by
  inspection; mirrors how security headers are already centralized.
- **Alternatives considered**: adding the header at every call site
  (rejected — three copies per SDK invite drift).

## R-4: Public constant naming across SDKs

- **Decision**: Java `GatedhouseApiFilter.WWW_AUTHENTICATE_CHALLENGE`
  (String, value `"Bearer"`); Python `WWW_AUTHENTICATE_CHALLENGE = "Bearer"`
  exported from `gatedhouse` (used by `_web.py` and `asgi.py`); Rust
  `WWW_AUTHENTICATE` tuple constant re-exported from the crate root.
- **Rationale**: mirrors the existing per-SDK idiom for `SECURITY_HEADERS`
  (Java constant on the filter class, Python module constant, Rust
  `pub const` + lib re-export). Cross-SDK the emitted bytes are identical,
  which is the actual contract (FR-003).

## R-5: WebSocket paths

- **Decision**: Unchanged. The ASGI middleware's websocket rejection uses a
  `websocket.close` (code 1008) event, which has no HTTP headers; the Rust and
  Java surfaces have no websocket-specific 401 writer.
- **Rationale**: RFC 6750 challenges apply to HTTP responses; the spec lists
  this as an edge scenario with today's behavior preserved.
