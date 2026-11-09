# 11. Web integration

Gatedhouse ships two request guards and an OAuth client, in every SDK:

| Component | Protects | On a missing or bad token |
|---|---|---|
| **API filter** | REST endpoints; reads `Authorization: Bearer <token>` | `401` JSON |
| **Web filter** | browser pages; reads the token from the user's session | redirect to the login page |
| **Sphinx client** | calls the Sphinx SSO OAuth 2.0 endpoints | typed errors |

Both filters verify the token with your [token verifier](10-authentication.md),
attach a `GatedContext` to the request, and add security headers
(`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: strict-origin-when-cross-origin`) to every response. They
**authenticate**; your code still **authorizes** with `hasPermission`.

## Responses

The filters behave identically in every SDK, down to the bytes of the body:

| Situation | API filter | Web filter |
|---|---|---|
| no token / not `Bearer` | `401`, `{"error":"unauthorized","reason":"missing_token","detail":"Missing or invalid Bearer token"}` | redirect to login |
| token rejected | `401`, `{"error":"unauthorized","reason":"expired","detail":"Token verification failed"}` (reason varies) | token removed from the session, redirect to login |
| identity provider unreachable | `503`, `Retry-After: 30`, `{"error":"unavailable","reason":"jwks_unavailable","detail":"Token verification is temporarily unavailable"}` | same `503`; **the session is kept** |
| valid token | request continues with the context attached | same |
| your code throws the filter's `ForbiddenException` | `403`, `{"error":"forbidden","detail":"<message>"}` | (not translated) |
| your code throws the filter's `UnauthorizedException` | `401` with the challenge | (not translated) |
| your code throws anything else | passes through untouched (your 500 / 503 handling applies) | passes through untouched |

- Every `401` carries `WWW-Authenticate: Bearer` (RFC 6750). `403`, `503` and
  redirects don't.
- The `reason` is a stable code; the verifier's internal message (which can
  contain your identity provider's URL) is never sent.
- The scheme is matched case-insensitively: `bearer abc` works.
- An identity-provider outage is a `503` because the client's token is not
  at fault: retrying later will work, and users stay signed in.

## Java (Jakarta Servlet)

Register the filters on the paths they protect. Programmatically, for example
with Spring Boot:

```java
@Bean
FilterRegistrationBean<GatedhouseApiFilter> apiFilter(Gatedhouse gh) {
    var reg = new FilterRegistrationBean<>(new GatedhouseApiFilter(gh));
    reg.addUrlPatterns("/api/*");
    return reg;
}

@Bean
FilterRegistrationBean<GatedhouseWebFilter> webFilter(Gatedhouse gh) {
    var reg = new FilterRegistrationBean<>(
        new GatedhouseWebFilter(gh, "/auth/login", "access_token"));
    reg.addUrlPatterns("/dashboard/*");
    return reg;
}
```

Or in `web.xml` (see [`sdk-java/sample-web.xml`](../../sdk-java/sample-web.xml)).
Declared filters find the `Gatedhouse` instance in the servlet context
attribute `com.twelvevectors.gatedhouse.Gatedhouse` (change it with the
`gatedhouseAttr` init parameter); the web filter also reads `loginPath` and
`sessionTokenAttr` init parameters.

In your servlets or controllers:

```java
GatedContext ctx = GatedhouseApiFilter.getContext(request);      // UnauthorizedException if absent
GatedhouseApiFilter.requireScope(request, "invoices:write");      // ForbiddenException → 403
if (!gh.hasPermission(ctx.personId(), orgId, "billing", "invoices", "refund")) {
    response.sendError(403);
    return;
}
```

`requireAdmin(request)` and `requireHuman(request)` work the same way. The
web filter attaches the context under the same attribute
(`GatedhouseWebFilter.CONTEXT_ATTR`).

The login path may be absolute (`https://sso.example.com/login`) or relative
to the application's context path (`/auth/login`).

## Python (WSGI)

```python
from gatedhouse import GatedhouseApiFilter, GatedhouseWebFilter

# Flask
app.wsgi_app = GatedhouseApiFilter(app.wsgi_app, gh)

@app.post("/api/invoices/<invoice_id>/refund")
def refund(invoice_id):
    ctx = GatedhouseApiFilter.get_context(request.environ)
    GatedhouseApiFilter.require_scope(request.environ, "invoices:write")
    if not gh.has_permission(ctx.person_id, org_id, "billing", "invoices", "refund"):
        abort(403)
    ...
```

The web filter reads the token from a session mapping your session
middleware places in the WSGI environ (key `gatedhouse.session` by default,
token attribute `access_token`):

```python
app.wsgi_app = GatedhouseWebFilter(app.wsgi_app, gh,
                                   login_path="/auth/login",
                                   session_token_attr="access_token",
                                   session_environ_key="gatedhouse.session")
```

The redirect is relative to `SCRIPT_NAME` unless the login path is absolute.

## Python (ASGI: FastAPI, Starlette, Litestar, Quart)

The ASGI versions live in `gatedhouse.asgi`, with the same names and
behaviour. They verify tokens in a worker thread so a key fetch never blocks
the event loop.

```python
import asyncio

from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware
from gatedhouse.asgi import GatedhouseApiFilter, GatedhouseWebFilter

api = FastAPI()
api.add_middleware(GatedhouseApiFilter, gatedhouse=gh)

@api.get("/api/invoices")
async def invoices(request: Request):
    ctx = request.state.gatedhouse_context          # or GatedhouseApiFilter.get_context(request.scope)
    allowed = await asyncio.to_thread(gh.has_permission, ctx.person_id, org_id,
                                      "billing", "invoices", "read")
    ...

pages = FastAPI()
pages.add_middleware(GatedhouseWebFilter, gatedhouse=gh, login_path="/auth/login")
pages.add_middleware(SessionMiddleware, secret_key=...)   # added last = runs first
```

- The web filter reads `scope["session"]`, so the session middleware must
  run before it.
- `hasPermission` is synchronous: call it with `asyncio.to_thread` (or
  `run_in_executor`) in async endpoints.
- **WebSockets** are guarded too: a missing or invalid token closes the
  handshake with code `1008`, an identity-provider outage with `1013` (try
  again later).
- `ForbiddenException` / `UnauthorizedException` raised by your endpoint
  become `403` / `401` if the response has not started yet.

## Rust

Rust has no standard middleware interface, so the filters are plain
functions that return either the verified context or the response to send.
Wire them into your framework in a few lines. A sketch for axum 0.7 (adapt to your framework):

```rust
use axum::{extract::{Request, State}, http::{HeaderValue, StatusCode}, middleware::Next,
           response::{IntoResponse, Response}};
use gatedhouse::{GatedhouseApiFilter, SECURITY_HEADERS};

async fn guard(State(filter): State<Arc<GatedhouseApiFilter>>, mut req: Request, next: Next) -> Response {
    let header = req.headers().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_owned);
    // verify_token may fetch keys: keep it off the async runtime's threads
    let result = tokio::task::spawn_blocking({
        let filter = filter.clone();
        move || filter.authenticate(header.as_deref())
    }).await.expect("verification task");

    let mut response = match result {
        Ok(ctx) => {
            req.extensions_mut().insert(ctx);
            next.run(req).await
        }
        Err(err) => {
            let mut r = (StatusCode::from_u16(err.status()).unwrap(), err.to_json_body()).into_response();
            r.headers_mut().insert("content-type", HeaderValue::from_static("application/json"));
            if let Some((name, value)) = err.challenge_header() {
                r.headers_mut().insert(name, HeaderValue::from_static(value));
            }
            if let Some(seconds) = err.retry_after() {
                r.headers_mut().insert("retry-after", seconds.into());
            }
            r
        }
    };
    for &(name, value) in SECURITY_HEADERS {
        response.headers_mut().entry(name).or_insert(HeaderValue::from_static(value));
    }
    response
}
```

| Function | Returns |
|---|---|
| `GatedhouseApiFilter::authenticate(header)` | `Ok(GatedContext)` or `Err(FilterError)` with `status()`, `to_json_body()`, `challenge_header()`, `retry_after()`, `reason()` |
| `GatedhouseApiFilter::require_admin / require_human / require_scope(&ctx, ..)` | `Err(FilterError::Forbidden(..))` when not allowed |
| `GatedhouseWebFilter::check(session_token, context_path)` | `Authenticated(ctx)`, `RedirectToLogin { location, clear_session_token }` (remove the token when asked), or `Unavailable` (send 503 with `Retry-After`, keep the session) |
| `bearer_token(header)` | the token from an `Authorization` header, scheme case-insensitive |

## The Sphinx OAuth client

`SphinxClient` covers the Sphinx SSO OAuth 2.0 endpoints: signing users in,
service-to-service tokens, delegation and introspection.

```java
SphinxClient sphinx = new SphinxClient("https://sso.example.com", clientId, clientSecret);
// or with an explicit timeout: new SphinxClient(url, id, secret, Duration.ofSeconds(5))

String loginUrl = sphinx.loginUrl("my-app");                         // send the browser here
TokenResponse t = sphinx.exchangeCode(code, "https://app.example.com/auth/callback");
TokenResponse svc = sphinx.clientCredentials("invoices:read");       // service-to-service
TokenResponse delegated = sphinx.tokenExchange(subjectToken, actorToken, delegationId, scope);
TokenResponse refreshed = sphinx.refreshToken(t.refreshToken());
Map<String, Object> info = sphinx.introspect(t.accessToken());
String federated = sphinx.federatedLoginUrl(ssoConnectionId, "my-app");
```

```python
sphinx = SphinxClient("https://sso.example.com", client_id, client_secret, timeout=10.0)
tokens = sphinx.exchange_code(code, "https://app.example.com/auth/callback")
```

```rust
let sphinx = SphinxClient::new("https://sso.example.com", client_id, client_secret)
    .with_timeout(Duration::from_secs(10));
let tokens = sphinx.exchange_code(&code, "https://app.example.com/auth/callback")?;
```

A `TokenResponse` has `accessToken`, `refreshToken`, `tokenType`,
`expiresIn` (seconds), `scope` and `issuedTokenType`.

A typical sign-in callback stores the access token where the web filter
looks for it:

```java
TokenResponse t = sphinx.exchangeCode(request.getParameter("code"), redirectUri);
request.getSession(true).setAttribute("access_token", t.accessToken());
response.sendRedirect("/dashboard");
```

### Timeouts and errors

- Every call is bounded: no single network wait (connecting, or waiting for
  data) exceeds the timeout, **10 seconds** by default.
- Failures raise `SphinxException` (Java), `SphinxError` (Python) or return
  `SphinxError` (Rust), with a **kind**:

| Kind | Meaning | What to do |
|---|---|---|
| `TIMEOUT` | the provider did not answer in time | retry later (except code exchange, below) |
| `TRANSPORT` | could not connect, or the connection failed | retry later |
| `HTTP_STATUS` | the provider refused the request; `statusCode` has the HTTP status | don't retry; e.g. an invalid or already-used code |
| `INVALID_RESPONSE` | the answer was not the expected JSON | report; retrying rarely helps |

- The client **never retries**. Do not blindly retry `exchangeCode` after a
  timeout: authorization codes are single-use, and the provider may already
  have consumed it. Send the user through sign-in again instead.
- `introspect` returns the provider's JSON even for non-200 answers, because
  introspection reports inactive tokens in the body.
