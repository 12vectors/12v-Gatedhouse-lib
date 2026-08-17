---
work_package_id: WP03
title: Rust guard challenge-header exposure
dependencies: []
requirement_refs:
- C-003
- FR-001
- FR-002
- FR-003
- FR-005
- NFR-001
- NFR-002
tracker_refs: []
planning_base_branch: claude/library-parity-python-rust-java-30h29l
merge_target_branch: claude/library-parity-python-rust-java-30h29l
branch_strategy: Planning artifacts for this mission were generated on claude/library-parity-python-rust-java-30h29l. During /spec-kitty.implement this WP may branch from a dependency-specific base, but completed changes must merge back into claude/library-parity-python-rust-java-30h29l unless the human explicitly redirects the landing branch.
subtasks:
- T010
- T011
- T012
agent: claude
history:
- '2026-08-17: created by /spec-kitty.tasks'
agent_profile: implementer-ivan
authoritative_surface: sdk-rust/src/
create_intent: []
execution_mode: code_change
owned_files:
- sdk-rust/src/filters.rs
- sdk-rust/src/lib.rs
- sdk-rust/tests/web_sphinx.rs
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

Rust hosts embedding the framework-agnostic guards must be able to emit
`WWW-Authenticate: Bearer` on 401 responses without hand-coding the value,
exactly the way they already copy `SECURITY_HEADERS`. The guards return
decisions rather than writing responses, so the deliverable is a constant
plus an accessor on `FilterError`.

## Context

- Contract: `kitty-specs/rfc6750-www-authenticate-01M082AR/contracts/401-response.md`, rule 5.
- `sdk-rust/src/filters.rs` defines `SECURITY_HEADERS`, `FilterError`
  (`Unauthorized` → 401, `Forbidden` → 403), and `to_json_body()`.
- Known pitfall recorded in the plan: do NOT run rustfmt against `lib.rs`
  (it recurses over the whole module tree and reformats pre-existing files).

### Subtask T010: Constant + accessor in filters.rs

1. Beside `SECURITY_HEADERS`:
   ```rust
   /// RFC 6750 challenge header the host must add to every 401 response,
   /// alongside [`SECURITY_HEADERS`] (RFC 7235 §4.1 makes it mandatory).
   pub const WWW_AUTHENTICATE: (&str, &str) = ("WWW-Authenticate", "Bearer");
   ```
2. On `impl FilterError`, beside `status()`:
   ```rust
   /// The `WWW-Authenticate` challenge the host must emit with this error:
   /// `Some` for 401 (RFC 6750 bare Bearer challenge), `None` for 403.
   pub fn challenge_header(&self) -> Option<(&'static str, &'static str)> {
       match self {
           FilterError::Unauthorized(_) => Some(WWW_AUTHENTICATE),
           FilterError::Forbidden(_) => None,
       }
   }
   ```
3. Extend the module-level doc comment's wiring sentence so it reads that
   hosts add `SECURITY_HEADERS` to every response *and the header from
   [`FilterError::challenge_header`] to error responses*.

### Subtask T011: Crate-root re-export

In `sdk-rust/src/lib.rs`, add `WWW_AUTHENTICATE` to the existing
`pub use filters::{...}` list (alphabetical position consistent with the
current ordering). Do not reformat anything else.

### Subtask T012: Tests

In `sdk-rust/tests/web_sphinx.rs` add assertions (either extending an
existing filter test or a new `#[test]`):

```rust
assert_eq!(WWW_AUTHENTICATE, ("WWW-Authenticate", "Bearer"));
let unauthorized = FilterError::Unauthorized("x".into());
assert_eq!(unauthorized.challenge_header(), Some(("WWW-Authenticate", "Bearer")));
let forbidden = FilterError::Forbidden("x".into());
assert_eq!(forbidden.challenge_header(), None);
```

Also keep/verify an assertion that `unauthorized.status() == 401` so the
challenge stays tied to the 401 mapping.

## Definition of Done

- [ ] `cd sdk-rust && cargo test --test web_sphinx` green
- [ ] `cargo build` warning-free for the new items (rustdoc included)
- [ ] `WWW_AUTHENTICATE` importable from crate root (`use gatedhouse::WWW_AUTHENTICATE;` in the test proves it)
- [ ] `Forbidden.challenge_header()` is `None`
- [ ] No rustfmt sweep of pre-existing code

## Reviewer guidance

API-shape review: tuple constant matches the `SECURITY_HEADERS` idiom;
accessor returns `Option` so hosts can't accidentally attach the challenge
to 403. Reject string-typed or always-Some designs.
