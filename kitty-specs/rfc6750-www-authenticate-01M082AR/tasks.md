# Work Packages: RFC 6750 WWW-Authenticate Header

**Mission**: `rfc6750-www-authenticate-01M082AR`
**Input**: [spec.md](./spec.md), [plan.md](./plan.md), [research.md](./research.md), [contracts/401-response.md](./contracts/401-response.md)
**Branch contract**: planning base and merge target are both `claude/library-parity-python-rust-java-30h29l`.

## Subtask Index

| ID | Description | WP | Parallel |
|----|-------------|----|----------|
| T001 | Java: add `WWW_AUTHENTICATE_CHALLENGE` constant and emit header in `sendJsonError` when status is 401 | WP01 | [P] |
| T002 | Java: add JUnit 5 (test scope) + Surefire to `sdk-java/pom.xml` | WP01 | [P] |
| T003 | Java: create `GatedhouseApiFilterTest` with servlet fakes covering both 401 causes | WP01 | [P] |
| T004 | Java: assert body/security-header invariants unchanged in the same test | WP01 | [P] |
| T005 | Python: add `WWW_AUTHENTICATE_CHALLENGE` constant in `_web.py`, export from `gatedhouse` | WP02 | [P] |
| T006 | Python WSGI: emit header in `_web.py::_send_json_error` for 401 status lines only | WP02 | [P] |
| T007 | Python ASGI: emit header (bytes pair) in `asgi.py::_send_json_error` when status == 401 | WP02 | [P] |
| T008 | Python: extend `tests/test_web_sphinx.py` 401 tests with header assertions | WP02 | [P] |
| T009 | Python: extend `tests/test_asgi.py` 401 tests with header assertions; assert websocket close unchanged | WP02 | [P] |
| T010 | Rust: add `WWW_AUTHENTICATE` constant and `FilterError::challenge_header()` in `filters.rs` | WP03 | [P] |
| T011 | Rust: re-export `WWW_AUTHENTICATE` from `lib.rs` | WP03 | [P] |
| T012 | Rust: extend `tests/web_sphinx.rs` with challenge-header assertions (Unauthorized=Some, Forbidden=None) | WP03 | [P] |
| T013 | Docs: update README.md guard sections + Language Equivalents table for the 401 contract | WP04 | |
| T014 | Docs: update SKILLS.md web-integration sections to mention the challenge header | WP04 | |

## WP01 — Java servlet filter challenge header

- **Goal**: `GatedhouseApiFilter` 401 responses carry `WWW-Authenticate: Bearer`; first real unit test for the filter.
- **Priority**: P1 (MVP scope together with WP02/WP03)
- **Requirements**: FR-001, FR-002, FR-003, NFR-001, NFR-002, C-001, C-002, C-003
- **Independent test**: `cd sdk-java && mvn test` passes; test asserts header on both 401 causes and absence of body/security-header drift.
- **Estimated prompt size**: ~260 lines

Included subtasks:

- [x] T001 Add constant + conditional header in `sendJsonError` (WP01)
- [x] T002 Add JUnit 5 test-scope deps + Surefire to pom (WP01)
- [x] T003 Create `GatedhouseApiFilterTest` with servlet fakes (WP01)
- [x] T004 Assert 401 body and security headers unchanged (WP01)

Implementation sketch: add `public static final String WWW_AUTHENTICATE_CHALLENGE = "Bearer"`; in `sendJsonError`, `if (status == 401) resp.setHeader("WWW-Authenticate", WWW_AUTHENTICATE_CHALLENGE);`. Test uses hand-rolled `HttpServletRequest`/`HttpServletResponse` fakes (no Mockito) and a stub `Gatedhouse` whose `verifyToken` throws `TokenVerificationException`.

Dependencies: none. Parallel: safe alongside WP02/WP03 (disjoint files).
Risks: `sendJsonError` is the future 403 write path too — condition on status, not call site.

## WP02 — Python WSGI + ASGI challenge header

- **Goal**: both Python integration styles emit the header on every 401; websocket close path untouched.
- **Priority**: P1
- **Requirements**: FR-001, FR-002, FR-003, FR-004, NFR-001, NFR-002, C-001, C-002, C-003
- **Independent test**: `cd sdk-python && python -m pytest tests/test_web_sphinx.py tests/test_asgi.py` passes with new header assertions.
- **Estimated prompt size**: ~300 lines

Included subtasks:

- [x] T005 Shared constant `WWW_AUTHENTICATE_CHALLENGE = "Bearer"` in `_web.py`, exported from `gatedhouse` (WP02)
- [x] T006 WSGI `_send_json_error` emits header for `401 Unauthorized` status lines (WP02)
- [x] T007 ASGI `_send_json_error` emits `(b"www-authenticate", b"Bearer")` when status == 401 (WP02)
- [x] T008 Header assertions in `tests/test_web_sphinx.py` (WP02)
- [x] T009 Header assertions + websocket-unchanged assertion in `tests/test_asgi.py` (WP02)

Implementation sketch: constant lives beside the existing security-headers constant in `_web.py`; `asgi.py` derives its bytes form once at module level. Both helpers append conditionally on 401 so 403 reuse stays correct.

Dependencies: none. Parallel: safe alongside WP01/WP03.
Risks: WSGI headers are `(str, str)` tuples, ASGI headers are `(bytes, bytes)` — keep one canonical string constant, derive bytes locally.

## WP03 — Rust guard challenge-header exposure

- **Goal**: Rust hosts can emit the header without hand-coding it, mirroring `SECURITY_HEADERS`.
- **Priority**: P1
- **Requirements**: FR-001, FR-002, FR-003, FR-005, NFR-001, NFR-002, C-003
- **Independent test**: `cd sdk-rust && cargo test --test web_sphinx` passes with new assertions.
- **Estimated prompt size**: ~230 lines

Included subtasks:

- [ ] T010 `pub const WWW_AUTHENTICATE: (&str, &str)` + `FilterError::challenge_header()` (WP03)
- [ ] T011 Re-export from `lib.rs` filters use-block (WP03)
- [ ] T012 Tests: `Unauthorized → Some(WWW_AUTHENTICATE)`, `Forbidden → None`, exact tuple value (WP03)

Implementation sketch: `challenge_header(&self) -> Option<(&'static str, &'static str)>` matching `Unauthorized(_) => Some(WWW_AUTHENTICATE)`, `Forbidden(_) => None`; rustdoc on both explains the host copies it onto the response exactly like `SECURITY_HEADERS`.

Dependencies: none. Parallel: safe alongside WP01/WP02.
Risks: don't run rustfmt against `lib.rs` module tree (recurses over pre-existing files).

## WP04 — Documentation parity

- **Goal**: README/SKILLS accurately describe the 401 contract in all three languages.
- **Priority**: P2 (polish)
- **Requirements**: FR-003
- **Independent test**: README/SKILLS guard sections mention `WWW-Authenticate: Bearer` for each SDK; Language Equivalents table row present.
- **Estimated prompt size**: ~160 lines

Included subtasks:

- [ ] T013 README.md guard sections + Language Equivalents row (WP04)
- [ ] T014 SKILLS.md web-integration sections (WP04)

Dependencies: WP01, WP02, WP03 (documents shipped behavior).
Risks: none material.

## Parallelization

WP01, WP02, WP03 are fully parallel (three lanes, disjoint `owned_files`). WP04 runs after all three.

## MVP scope

WP01 + WP02 + WP03 deliver the RFC compliance; WP04 is documentation polish.
