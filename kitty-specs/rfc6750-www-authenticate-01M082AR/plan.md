# Implementation Plan: RFC 6750 WWW-Authenticate Header

**Branch**: `claude/library-parity-python-rust-java-30h29l` | **Date**: 2026-08-17 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `kitty-specs/rfc6750-www-authenticate-01M082AR/spec.md`

## Summary

Every HTTP 401 produced by the Gatedhouse API guards must carry the response
header `WWW-Authenticate: Bearer` (bare scheme, no auth-params), per RFC 7235
§4.1 and RFC 6750 §3, in all three SDKs. The change is a constant header added
at each SDK's existing 401 write point, exposed as a public constant beside the
existing security-headers constant so host applications and tests share one
source of truth. Bodies, security headers, 403s, login redirects, and
WebSocket close semantics are unchanged.

## Technical Context

**Language/Version**: Java 17 (sdk-java, Maven), Python 3.10+ (sdk-python), Rust 2021 edition / MSRV per Cargo.toml (sdk-rust)
**Primary Dependencies**: none added — Java uses jakarta.servlet API already present; Python stdlib only (WSGI PEP 3333 + pure ASGI); Rust `serde_json` already present
**Storage**: N/A — no database or schema involvement
**Testing**: JUnit 5 (`sdk-java/src/test`), pytest (`sdk-python/tests`, incl. `test_web.py`, `test_asgi.py`), cargo test (`sdk-rust/tests/web_sphinx.rs`)
**Target Platform**: server-side libraries (JVM, CPython, native)
**Project Type**: single repository, three parallel SDK subprojects
**Performance Goals**: zero measurable overhead — one constant header tuple appended at response-write time on the 401 (failure) path only
**Constraints**: 401 JSON body byte-identical; existing security headers unchanged; 403 responses unchanged; additive public API only (minor version bump)
**Scale/Scope**: 4 source files (~15 lines), 3 test files (~40 lines), README/SKILLS docs touch-ups

## Charter Check

Skipped — no charter exists at `.kittify/charter/charter.md` for this project.

## Project Structure

### Documentation (this mission)

```
kitty-specs/rfc6750-www-authenticate-01M082AR/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
│   └── 401-response.md  # Cross-SDK 401 response contract
└── tasks.md             # Phase 2 output (/spec-kitty.tasks — not created here)
```

`data-model.md` is intentionally omitted: the mission introduces no entities,
state, or persistence.

### Source Code (repository root)

```
sdk-java/src/main/java/com/twelvevectors/gatedhouse/
└── GatedhouseApiFilter.java      # sendJsonError(): add header when status == 401

sdk-python/gatedhouse/
├── _web.py                       # WSGI _send_json_error(): add header on "401 Unauthorized"
└── asgi.py                       # ASGI _send_json_error(): add header when status == 401

sdk-rust/src/
└── filters.rs                    # WWW_AUTHENTICATE constant + FilterError::challenge_header()

Tests:
sdk-java/src/test/java/...        # existing ApiFilter 401 tests gain header assertions
sdk-python/tests/test_web.py      # WSGI 401 header assertions
sdk-python/tests/test_asgi.py     # ASGI 401 header assertions
sdk-rust/tests/web_sphinx.rs      # challenge_header() assertions
```

**Structure Decision**: no new modules. Each SDK's guard already funnels every
401 through a single JSON-error helper (`sendJsonError` in Java,
`_send_json_error` in both Python variants) or a single error type
(`FilterError` in Rust), so the header is added at exactly one choke point per
surface.

## Complexity Tracking

No charter violations; table not applicable.

## Implementation Concern Map

> Implementation concerns are NOT work packages. `/spec-kitty.tasks` translates
> these into executable WPs.

### IC-01 — Java servlet filter challenge header

- **Purpose**: Emit `WWW-Authenticate: Bearer` from the servlet API guard's 401 path.
- **Relevant requirements**: FR-001, FR-002, C-001, C-002, C-003
- **Affected surfaces**: `sdk-java/src/main/java/com/twelvevectors/gatedhouse/GatedhouseApiFilter.java` (`sendJsonError`, called with 401 at three sites); public constant `WWW_AUTHENTICATE_CHALLENGE = "Bearer"`; existing Java filter tests.
- **Sequencing/depends-on**: none
- **Risks**: `sendJsonError` is also the 403 write path — the header must be conditional on status 401 (C-003).

### IC-02 — Python WSGI + ASGI challenge header

- **Purpose**: Emit the header from both Python server-integration styles.
- **Relevant requirements**: FR-001, FR-002, FR-004, C-001, C-002, C-003
- **Affected surfaces**: `sdk-python/gatedhouse/_web.py` (`_send_json_error`), `sdk-python/gatedhouse/asgi.py` (`_send_json_error`); shared constant; `sdk-python/tests/test_web.py`, `sdk-python/tests/test_asgi.py`.
- **Sequencing/depends-on**: none
- **Risks**: ASGI headers are byte pairs, WSGI headers are str tuples — the constant needs one canonical form per module; WebSocket rejection path (close code 1008) is not an HTTP 401 and must stay untouched (spec edge scenario).

### IC-03 — Rust framework-agnostic guard exposure

- **Purpose**: Let Rust hosts emit the header without hand-coding it, mirroring how `SECURITY_HEADERS` is exposed.
- **Relevant requirements**: FR-001, FR-002, FR-005, C-003
- **Affected surfaces**: `sdk-rust/src/filters.rs` — new public constant `WWW_AUTHENTICATE: (&str, &str) = ("WWW-Authenticate", "Bearer")` and a `FilterError::challenge_header()` accessor returning `Some(WWW_AUTHENTICATE)` for `Unauthorized`, `None` for `Forbidden`; re-export in `sdk-rust/src/lib.rs`; `sdk-rust/tests/web_sphinx.rs`.
- **Sequencing/depends-on**: none
- **Risks**: Rust guards don't write responses themselves — the contract must make it unmistakable that the host copies the header, matching the existing pattern for status/body/security headers.

### IC-04 — Documentation parity

- **Purpose**: Keep README/SKILLS guard sections accurate about the 401 contract.
- **Relevant requirements**: FR-003
- **Affected surfaces**: `README.md`, `SKILLS.md` (guard/web sections; Language Equivalents table row for 401 responses).
- **Sequencing/depends-on**: IC-01, IC-02, IC-03 (documents what shipped)
- **Risks**: none material.
