# 11. Web integration

| Component | Input | Purpose |
|---|---|---|
| API filter | `Authorization: Bearer <token>` | guard REST endpoints |
| Web filter | token in the user's session (`access_token`) | guard pages |
| `SphinxClient` | | Sphinx SSO OAuth 2.0 calls |

Filters verify the token ([ch. 10](10-authentication.md)), attach a
`GatedContext` to the request, and add `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`.
Authorization (`hasPermission`) remains the application's job.

## Responses (identical in all SDKs)

| Situation | API filter | Web filter |
|---|---|---|
| no token / scheme not Bearer (case-insensitive) | 401 `{"error":"unauthorized","reason":"missing_token","detail":"Missing or invalid Bearer token"}` | redirect to login |
| token rejected | 401 `{"error":"unauthorized","reason":"<code>","detail":"Token verification failed"}` | remove token from session, redirect |
| `JWKS_UNAVAILABLE` | 503, `Retry-After: 30`, `{"error":"unavailable","reason":"jwks_unavailable","detail":"Token verification is temporarily unavailable"}` | same 503; session kept |
| app throws filter's `ForbiddenException` | 403 `{"error":"forbidden","detail":"<message>"}` | not translated |
| app throws filter's `UnauthorizedException` | 401 | not translated |
| app throws anything else | propagates | propagates |

401 responses carry `WWW-Authenticate: Bearer`; 403, 503 and redirects do
not. Login path: absolute URL, or relative to the context path / `SCRIPT_NAME`
/ `root_path`.

## Java (Jakarta Servlet)

```java
var api = new FilterRegistrationBean<>(new GatedhouseApiFilter(gh));          // Spring Boot
api.addUrlPatterns("/api/*");
var web = new FilterRegistrationBean<>(new GatedhouseWebFilter(gh, "/auth/login", "access_token"));
web.addUrlPatterns("/dashboard/*");
```

Declared filters (`web.xml`, see `sdk-java/sample-web.xml`) read the instance
from servlet context attribute `com.twelvevectors.gatedhouse.Gatedhouse`
(init param `gatedhouseAttr`); the web filter also reads `loginPath` and
`sessionTokenAttr`.

In handlers: `GatedhouseApiFilter.getContext(req)` (throws
`UnauthorizedException` if absent), `requireAdmin(req)`, `requireHuman(req)`,
`requireScope(req, scope)` (throw `ForbiddenException`).

## Python

WSGI (`gatedhouse.GatedhouseApiFilter`, `gatedhouse.GatedhouseWebFilter`):

```python
app.wsgi_app = GatedhouseApiFilter(app.wsgi_app, gh)                  # Flask
ctx = GatedhouseApiFilter.get_context(request.environ)
app.wsgi_app = GatedhouseWebFilter(app.wsgi_app, gh, login_path="/auth/login",
                                   session_token_attr="access_token",
                                   session_environ_key="gatedhouse.session")
```

The WSGI web filter reads a session mapping from `environ[session_environ_key]`,
which the host's session middleware must provide.

ASGI (`gatedhouse.asgi`, same names); verification runs in a worker thread:

```python
app.add_middleware(GatedhouseApiFilter, gatedhouse=gh)                # FastAPI / Starlette
# context: request.state.gatedhouse_context, or GatedhouseApiFilter.get_context(scope)
app.add_middleware(GatedhouseWebFilter, gatedhouse=gh, login_path="/auth/login")
app.add_middleware(SessionMiddleware, secret_key=...)                 # added last = runs first
```

- The ASGI web filter reads `scope["session"]`.
- WebSockets: missing/invalid token → close 1008; `JWKS_UNAVAILABLE` → close
  1013.
- `ForbiddenException` / `UnauthorizedException` are translated only before
  the response starts.
- `hasPermission` is synchronous; call it via `asyncio.to_thread` in async
  handlers.

## Rust

Framework-agnostic functions:

| Item | Result |
|---|---|
| `GatedhouseApiFilter::authenticate(Option<&str>)` | `Ok(GatedContext)` or `Err(FilterError)` |
| `FilterError` | variants `Unauthorized { reason, detail }`, `Forbidden(String)`, `Unavailable`; `status()`, `to_json_body()`, `challenge_header()`, `retry_after()`, `reason()`, `detail()` |
| `GatedhouseApiFilter::require_admin / require_human / require_scope(&ctx, ..)` | `Err(FilterError::Forbidden(..))` when not allowed |
| `GatedhouseWebFilter::check(token, context_path)` | `Authenticated(ctx)`, `RedirectToLogin { location, clear_session_token }`, `Unavailable` |
| `bearer_token(&str)` | token from an `Authorization` value |
| `SECURITY_HEADERS`, `WWW_AUTHENTICATE`, `RETRY_AFTER_SECONDS` | constants |

`authenticate` may fetch the JWKS (blocking); in async runtimes use
`spawn_blocking`. axum 0.7 sketch (not compiled in CI):

```rust
async fn guard(State(f): State<Arc<GatedhouseApiFilter>>, mut req: Request, next: Next) -> Response {
    let header = req.headers().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_owned);
    let result = tokio::task::spawn_blocking({ let f = f.clone(); move || f.authenticate(header.as_deref()) })
        .await.expect("verification task");
    let mut response = match result {
        Ok(ctx) => { req.extensions_mut().insert(ctx); next.run(req).await }
        Err(e) => {
            let mut r = (StatusCode::from_u16(e.status()).unwrap(), e.to_json_body()).into_response();
            r.headers_mut().insert("content-type", HeaderValue::from_static("application/json"));
            if let Some((k, v)) = e.challenge_header() { r.headers_mut().insert(k, HeaderValue::from_static(v)); }
            if let Some(s) = e.retry_after() { r.headers_mut().insert("retry-after", s.into()); }
            r
        }
    };
    for &(k, v) in SECURITY_HEADERS { response.headers_mut().entry(k).or_insert(HeaderValue::from_static(v)); }
    response
}
```

## SphinxClient

| Java | Purpose |
|---|---|
| `new SphinxClient(baseUrl, clientId, secret[, timeout])` | Python `SphinxClient(url, id, secret, timeout=10.0)`; Rust `SphinxClient::new(..).with_timeout(d)`; default 10 s per network wait |
| `loginUrl(app)`, `federatedLoginUrl(connectionId, app)` | redirect URLs |
| `exchangeCode(code, redirectUri)` | authorization code → tokens |
| `clientCredentials(scope)` | service token |
| `tokenExchange(subjectToken, actorToken, delegationId, scope)` | delegation |
| `refreshToken(refreshToken)` | refresh |
| `introspect(token)` | token status map; body parsed for any HTTP status |

`TokenResponse`: `accessToken`, `refreshToken`, `tokenType`, `expiresIn`
(seconds), `scope`, `issuedTokenType`.

Errors: `SphinxException` (Java) / `SphinxError` (Python, Rust) with `kind`:

| Kind | Meaning | Retry |
|---|---|---|
| `TIMEOUT` | no answer within the timeout | later, except `exchangeCode` |
| `TRANSPORT` | connection failed | later |
| `HTTP_STATUS` | refused; `statusCode` set | no |
| `INVALID_RESPONSE` | not the expected JSON (often a proxy) | no |

The client never retries. Authorization codes are single-use: after a failed
`exchangeCode`, restart sign-in.

Sign-in callback, storing the token where the web filter reads it:

```java
TokenResponse t = sphinx.exchangeCode(req.getParameter("code"), redirectUri);
req.getSession(true).setAttribute("access_token", t.accessToken());
```
