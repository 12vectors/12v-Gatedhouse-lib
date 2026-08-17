---
work_package_id: WP02
title: Python WSGI + ASGI challenge header
dependencies: []
requirement_refs:
- C-001
- C-002
- C-003
- FR-001
- FR-002
- FR-003
- FR-004
- NFR-001
- NFR-002
tracker_refs: []
planning_base_branch: claude/library-parity-python-rust-java-30h29l
merge_target_branch: claude/library-parity-python-rust-java-30h29l
branch_strategy: Planning artifacts for this mission were generated on claude/library-parity-python-rust-java-30h29l. During /spec-kitty.implement this WP may branch from a dependency-specific base, but completed changes must merge back into claude/library-parity-python-rust-java-30h29l unless the human explicitly redirects the landing branch.
subtasks:
- T005
- T006
- T007
- T008
- T009
agent: "claude"
shell_pid: "29244"
history:
- '2026-08-17: created by /spec-kitty.tasks'
agent_profile: python-pedro
authoritative_surface: sdk-python/gatedhouse/
create_intent: []
execution_mode: code_change
owned_files:
- sdk-python/gatedhouse/_web.py
- sdk-python/gatedhouse/asgi.py
- sdk-python/gatedhouse/__init__.py
- sdk-python/tests/test_web_sphinx.py
- sdk-python/tests/test_asgi.py
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

Both Python integration styles — the WSGI middleware in
`sdk-python/gatedhouse/_web.py` and the ASGI middleware in
`sdk-python/gatedhouse/asgi.py` — must emit `WWW-Authenticate: Bearer` on
every 401 JSON response, with bodies, security headers, redirects, and the
ASGI websocket close path all byte-identical to today.

## Context

- Contract: `kitty-specs/rfc6750-www-authenticate-01M082AR/contracts/401-response.md`.
- Each module funnels every 401 through its own `_send_json_error` helper —
  two choke points total.
- WSGI headers are `(str, str)` tuples added to the `start_response` header
  list; ASGI headers are `(bytes, bytes)` pairs in the `http.response.start`
  message. Keep ONE canonical string constant; derive the bytes form once at
  module level in `asgi.py`.
- The ASGI websocket rejection path (`_reject_websocket`, close code 1008)
  is not an HTTP response and MUST stay untouched.

### Subtask T005: Shared public constant

1. In `_web.py`, beside the existing security-headers constant:
   ```python
   #: RFC 6750 challenge sent on every 401 response.
   WWW_AUTHENTICATE_CHALLENGE = "Bearer"
   ```
2. Export it from the package: add to `gatedhouse/__init__.py` imports and
   `__all__`, next to the other web exports.

### Subtask T006: WSGI emission

In `_web.py::_send_json_error`, append the header only for 401:

```python
if status.startswith("401"):
    headers.append(("WWW-Authenticate", WWW_AUTHENTICATE_CHALLENGE))
```

(Adapt to the helper's actual local variable names; the condition keys off
the WSGI status line `"401 Unauthorized"`. Do not add it to
`_with_security_headers`, which also serves 403/302 paths.)

### Subtask T007: ASGI emission

In `asgi.py`:

1. Module-level, beside `_SECURITY_HEADERS`:
   ```python
   from ._web import WWW_AUTHENTICATE_CHALLENGE

   _WWW_AUTHENTICATE = (b"www-authenticate", WWW_AUTHENTICATE_CHALLENGE.encode("latin-1"))
   ```
2. In `asgi.py::_send_json_error`, add `_WWW_AUTHENTICATE` to the headers
   list only when `status == 401`.

### Subtask T008: WSGI tests

In `sdk-python/tests/test_web_sphinx.py`, extend the existing API-filter 401
tests (missing token and invalid token) to assert the header:

```python
assert ("WWW-Authenticate", "Bearer") in captured_headers
```

Also assert on the 302 login-redirect test that no `WWW-Authenticate` header
is present (C-003/C-004 analog for the web filter path).

### Subtask T009: ASGI tests

In `sdk-python/tests/test_asgi.py`:

1. Extend the existing 401 tests (missing token, invalid token) to assert
   `(b"www-authenticate", b"Bearer")` is in the response-start headers.
2. Assert the websocket rejection test's message sequence is still exactly
   `[{"type": "websocket.close", "code": 1008}]` — no headers appeared.

## Definition of Done

- [ ] `cd sdk-python && python -m pytest tests/test_web_sphinx.py tests/test_asgi.py` green
- [ ] Header on both 401 causes in both WSGI and ASGI
- [ ] 302 redirect and websocket close paths asserted unchanged
- [ ] Constant exported from `gatedhouse` package `__all__`
- [ ] No changes outside owned files

## Reviewer guidance

Watch the str/bytes split: WSGI must send `("WWW-Authenticate", "Bearer")`
str tuple, ASGI must send lowercase `b"www-authenticate"` bytes pair. Reject
if the header leaks onto 403 or redirect paths.

## Activity Log

- 2026-08-17T15:06:04Z – claude – shell_pid=29244 – Assigned agent via action command
