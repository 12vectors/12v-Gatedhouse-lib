# Contract: API-guard 401 response (all SDKs)

The complete, cross-SDK contract for an unauthenticated request rejected by a
Gatedhouse API guard. Items marked **(new)** are added by this mission; all
others are pre-existing and MUST NOT change.

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
WWW-Authenticate: Bearer            (new)
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin

{"error": "unauthorized", "detail": "<cause-specific message>"}
```

Rules:

1. `WWW-Authenticate: Bearer` — exact header name, exact value, no
   auth-params — on **every** guard-produced 401, whether the cause is a
   missing/malformed `Authorization` header or a failed token verification.
2. 403 responses carry **no** `WWW-Authenticate` header.
3. The web (session) guard's 302 login redirect carries **no**
   `WWW-Authenticate` header.
4. ASGI websocket rejections remain a `websocket.close` with code 1008 — no
   HTTP headers exist on that path.
5. Rust: `GatedhouseApiFilter::authenticate` returns
   `Err(FilterError::Unauthorized(_))`; the host emits status 401, the JSON
   body from `to_json_body()`, `SECURITY_HEADERS`, and **(new)** the header
   from `FilterError::challenge_header()` when it is `Some`.
