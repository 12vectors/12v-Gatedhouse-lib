# Mission Review Report: rfc6750-www-authenticate-01M082AR

**Reviewer**: claude (post-merge mission review, spec-kitty-mission-review skill)
**Date**: 2026-08-17
**Mission**: `rfc6750-www-authenticate-01M082AR` — RFC 6750 WWW-Authenticate Header (mission #1)
**Baseline commit**: `bdf0927` (pre-mission tip; also checkpoint branch `checkpoint/pre-spec-kitty`)
**HEAD at review**: post-merge tip on `claude/library-parity-python-rust-java-30h29l`
**WPs reviewed**: WP01–WP04 (all `done`; zero rejection cycles; no arbiter overrides; no self-approval events)

---

## Gate Results

This repository is not the Spec Kitty codebase, so the four hard gates map onto
this project's own contract layers where equivalents exist.

### Gate 1 — Contract tests (equivalent: per-SDK test suites)
- Commands: `mvn test` (sdk-java), `python3 -m pytest tests/test_web_sphinx.py tests/test_asgi.py` (sdk-python), `cargo test --test web_sphinx` (sdk-rust)
- Exit codes: 0 / 0 / 0 — Java 3/3, Python 27/27, Rust 5/5 at the merged tip
- Result: **PASS**
- Notes: the cross-SDK wire contract is additionally pinned by `contracts/401-response.md` and by exact-value assertions in all three suites.

### Gate 2 — Architectural tests
- Result: **N/A** — no `tests/architectural/` layer exists in this repo. Nearest equivalent: WP ownership boundaries (disjoint `owned_files`) verified against the diff; no file was touched by more than one WP.

### Gate 3 — Cross-repo E2E
- Result: **N/A** — no companion e2e repo exists. Nearest prior equivalent: the three SDKs' DB-backed smoke suites (80 checks each) exist but were not re-run for this mission since it touches no database code path; the guards' HTTP behavior is covered by the suites in Gate 1.

### Gate 4 — Issue Matrix
- Result: **N/A** — no `issue-matrix.md`; no in-mission issues were tracked. The acceptance matrix (`acceptance-matrix.json`) stands in: 5 criteria `pass`, 5 negative invariants `confirmed_absent` via executable checks, overall verdict `pass`.

---

## FR Coverage Matrix

| FR ID | Description (brief) | WP Owner | Test File(s) | Test Adequacy | Finding |
|-------|---------------------|----------|--------------|---------------|---------|
| FR-001 | 401s carry `WWW-Authenticate: Bearer` | WP01–03 | `GatedhouseApiFilterTest.java`, `test_web_sphinx.py`, `test_asgi.py`, `web_sphinx.rs` | ADEQUATE | — |
| FR-002 | Both 401 causes emit the challenge | WP01–03 | same (missing-token + invalid-token cases per SDK) | ADEQUATE | — |
| FR-003 | Identical header name/value across SDKs | WP01–04 | exact-value assertions in all three suites | ADEQUATE | — |
| FR-004 | Python WSGI and ASGI both emit | WP02 | `test_web_sphinx.py`, `test_asgi.py` | ADEQUATE | — |
| FR-005 | Rust exposes challenge for hosts | WP03 | `web_sphinx.rs` (crate-root import proves re-export) | ADEQUATE | [RISK-2] |

**Deletion test (mental mutation)**: every FR's tests assert the header/accessor
directly; removing any implementation line fails its tests. No synthetic-fixture
false positives: all tests drive the production middleware/filter/guard objects.

**NFR-001 (zero latency)**: verified structurally — in all four emission points the
header append sits inside the failure-only JSON-error helpers; no authenticated-path
code changed. The Java success-path test additionally asserts no challenge and no body.

**NFR-002 (additive API)**: verified — new symbols only (`WWW_AUTHENTICATE_CHALLENGE` ×2,
`WWW_AUTHENTICATE`, `challenge_header()`); JUnit 5 is test-scoped; no published
artifact's dependency tree changed.

**Constraints C-001..C-005**: all carry negative assertions (exact body, exact security
headers, no challenge on 403/302, exact websocket close sequence, bare `Bearer`).

---

## Drift Findings

None. No non-goal invasion (no auth-params code exists — verified by grep-absence
invariant), no locked-decision violations, no punted FRs, no NFR misses. The diff
contains nothing outside the four WPs' declared ownership plus mission artifacts.

---

## Risk Findings

### RISK-1: Pre-existing — Java 401 body built by string concatenation without JSON escaping

**Type**: ERROR-PATH (pre-existing, adjacent to this mission's surface)
**Severity**: LOW (today), latent MEDIUM
**Location**: `sdk-java/src/main/java/com/twelvevectors/gatedhouse/GatedhouseApiFilter.java`, `sendJsonError`
**Trigger condition**: a `TokenVerificationException` message containing `"` or `\`
reaches `detail` — the body `{"error":"...","detail":"..."}` becomes malformed JSON.

**Analysis**: NOT introduced by this mission (the mission deliberately left the body
byte-identical per C-001), but the new exact-body test now pins the current
concatenation behavior, which makes the escaping gap visible. Current exception
messages are library-controlled constants, so no input reaches the body unescaped
today — hence LOW. The Python (json.dumps) and Rust (serde_json) SDKs escape
correctly, so this is also a latent tri-SDK parity gap under the charter if a
message ever carries dynamic content. Recommend a follow-up mission: escape `detail`
in `sendJsonError` (a behavior-preserving change for all current messages).

### RISK-2: Rust challenge emission is host-mediated (documentation-enforced)

**Type**: CROSS-WP-INTEGRATION (inherent design, acknowledged by spec)
**Severity**: LOW
**Location**: `sdk-rust/src/filters.rs` (`challenge_header()` contract)
**Trigger condition**: a Rust host wires `FilterError` into its framework but
forgets to copy `challenge_header()` onto the 401 response.

**Analysis**: identical in kind to the pre-existing `SECURITY_HEADERS` host-copy
contract; the spec (FR-005, Assumptions) accepts this. Rustdoc on the module,
constant, and accessor all state the obligation. No stronger enforcement is
possible without shipping framework-specific middleware — noted as accepted.

---

## Silent Failure Candidates

None introduced. No new `except`/`catch`/`match` arms; no default-value returns.
The only new conditional is `status == 401` (or `startswith("401")`), whose
false branch is the pre-existing unmodified behavior.

## Security Notes

| Finding | Location | Risk class | Recommendation |
|---------|----------|------------|----------------|
| Header value is a compile-time constant; no user input flows into the header — no injection surface | all four emission points | — | none |
| Pre-existing JSON-escaping gap (RISK-1) | `GatedhouseApiFilter.sendJsonError` | RESPONSE-MALFORMATION | follow-up mission to escape `detail` |

No new subprocess, filesystem, network, or credential operations were introduced.

---

## Final Verdict

**PASS WITH NOTES**

### Verdict rationale

All five FRs are adequately covered with production-path tests in all three SDKs;
both NFRs and all five constraints are verified (constraints by executable negative
invariants in the acceptance matrix); no drift from spec, no locked-decision
violations, no dead code (every new symbol has live usage), no new silent-failure
or security surfaces. The two findings are a pre-existing latent defect adjacent
to the mission (RISK-1) and an accepted design property (RISK-2) — neither blocks
release.

### Open items (non-blocking)

1. **Follow-up mission candidate**: JSON-escape `detail` in Java `sendJsonError`
   (RISK-1) — brings Java to parity with Python/Rust JSON serialization.
2. Consider a `data-model.md` stub policy for missions with no entities, to
   silence the recurring optional-artifact warning.

## Retrospective Reminder

`retrospective.yaml` was auto-authored at merge terminus
(`kitty-specs/rfc6750-www-authenticate-01M082AR/retrospective.yaml`,
created_by spec-kitty-generator, schema v1) — verified present. Next:
`spec-kitty retrospect summary` for the cross-mission view, and
`spec-kitty agent retrospect synthesize --mission rfc6750-www-authenticate-01M082AR`
(dry-run) to inspect any staged proposals.
