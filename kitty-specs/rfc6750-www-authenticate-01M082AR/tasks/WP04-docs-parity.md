---
work_package_id: WP04
title: Documentation parity
dependencies:
- WP01
- WP02
- WP03
requirement_refs:
- FR-003
tracker_refs: []
planning_base_branch: claude/library-parity-python-rust-java-30h29l
merge_target_branch: claude/library-parity-python-rust-java-30h29l
branch_strategy: lane worktree from planning base; merge back to target
subtasks:
- T013
- T014
agent: claude
history:
- '2026-08-17: created by /spec-kitty.tasks'
agent_profile: curator-carla
authoritative_surface: README.md
create_intent: []
execution_mode: code_change
owned_files:
- README.md
- SKILLS.md
role: implementer
tags: []
---

## ⚡ Do This First: Load Agent Profile

Before reading further, load your assigned agent profile so this work runs
under the right identity and boundaries:

```
/ad-hoc-profile-load curator --mission rfc6750-www-authenticate-01M082AR
```

## Objective

README.md and SKILLS.md must describe the 401 contract accurately for all
three SDKs now that the guards emit `WWW-Authenticate: Bearer`.

## Context

- Contract: `kitty-specs/rfc6750-www-authenticate-01M082AR/contracts/401-response.md`.
- Runs after WP01–WP03 so it documents shipped behavior, not intent.
- Both files have per-language "Web & Sphinx" (README) / web-integration
  (SKILLS) sections plus a Language Equivalents table.

### Subtask T013: README.md

1. In each language's web/guard section, where the 401 JSON response is
   described, add one sentence: the response also carries the RFC 6750
   challenge header `WWW-Authenticate: Bearer` (Rust: via
   `FilterError::challenge_header()` for the host to copy).
2. In the Language Equivalents web-integration table, add a row:
   `401 challenge header` → Java `GatedhouseApiFilter.WWW_AUTHENTICATE_CHALLENGE` /
   Python `gatedhouse.WWW_AUTHENTICATE_CHALLENGE` / Rust `gatedhouse::WWW_AUTHENTICATE` +
   `FilterError::challenge_header()`.

### Subtask T014: SKILLS.md

Mirror the same one-sentence addition in the web-integration guidance for
each SDK, keeping SKILLS.md's terser style. Mention that 403 responses and
login redirects do NOT carry the header.

## Definition of Done

- [ ] Both files mention the header for all three SDKs with the exact value `Bearer`
- [ ] Language Equivalents row present and symbol names correct against the merged code
- [ ] Explicit note that 403/redirects are challenge-free
- [ ] No other doc content reflowed

## Reviewer guidance

Cross-check every symbol name against the actual WP01–WP03 diffs — docs that
name non-existent constants are worse than no docs.
