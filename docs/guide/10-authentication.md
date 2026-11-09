# 10. Authentication

Gatedhouse's core never asks *who* is calling: you pass an identity you
already trust. If your users sign in through an identity provider that
issues JSON Web Tokens (JWTs), such as Sphinx SSO, Gatedhouse can verify
those tokens for you and give you the trusted identity. This is optional;
skip this chapter if your application authenticates users some other way.

## Configuring token verification

You need three values from your identity provider:

| Setting | What it is | Example |
|---|---|---|
| JWKS URI | where the provider publishes its public signing keys | `https://sso.example.com/api/sphinx/v1/.well-known/jwks.json` |
| Issuer | the `iss` the provider puts in its tokens | `https://sso.example.com` |
| Audience | the `aud` your application's tokens carry | `my-platform` |

```java
GatedhouseConfig config = GatedhouseConfig.builder()
    .database(db)
    .tokenVerifier(TokenVerifierConfig.builder()
        .jwksUri(URI.create("https://sso.example.com/api/sphinx/v1/.well-known/jwks.json"))
        .issuer("https://sso.example.com")
        .audience("my-platform")
        .jwksTimeout(Duration.ofSeconds(5))      // optional; 5 s is the default
        .build())
    .build();
```

```python
config = GatedhouseConfig(
    database=db,
    token_verifier=TokenVerifierConfig(
        "https://sso.example.com/api/sphinx/v1/.well-known/jwks.json",
        "https://sso.example.com",
        "my-platform",
        jwks_timeout=5.0,          # optional
    ),
)
```

```rust
let config = GatedhouseConfig::builder(db)
    .token_verifier(TokenVerifierConfig::new(
        "https://sso.example.com/api/sphinx/v1/.well-known/jwks.json",
        "https://sso.example.com",
        "my-platform",
    ).with_jwks_timeout(Duration::from_secs(5)))
    .build();
```

## Verifying a token

```java
try {
    AuthenticatedSubject who = gh.verifyToken(bearerToken);
    boolean ok = gh.hasPermission(who.id(), orgId, "billing", "invoices", "read");
} catch (TokenVerificationException e) {
    switch (e.reason()) { ... }
}
```

```python
try:
    who = gh.verify_token(bearer_token)
    ok = gh.has_permission(who.id, org_id, "billing", "invoices", "read")
except TokenVerificationException as e:
    ...  # e.reason
```

```rust
match gh.verify_token(&bearer_token) {
    Ok(who) => { gh.has_permission(&who.id, org_id, "billing", "invoices", "read")?; }
    Err(e) => { /* e.reason, e.message */ }
}
```

A token is accepted only if **all** of these hold:

- it is signed with **RS256** (no other algorithm is accepted, so a token
  cannot pick a weaker one);
- its header names a key (`kid`) the provider currently publishes, and the
  signature verifies with that key;
- `iss` equals the configured issuer and `aud` contains the configured
  audience;
- it has not expired (`exp`) and is already valid (`nbf`, if present), with
  no clock-skew allowance in any SDK.

The result is an `AuthenticatedSubject`:

| Field | From the token | Notes |
|---|---|---|
| `id` | `sub` | the identity to pass to `hasPermission` |
| `issuer` | `iss` | |
| `audience` | `aud` | first entry if it is a list |
| `issuedAt` / `issued_at` | `iat` | optional |
| `expiresAt` / `expires_at` | `exp` | |
| `tokenType` / `token_type` | `type` | e.g. `access`, `delegation`; optional |
| `claims` | everything else | read custom claims such as `org_id` or `scope` here |

## Why verification failed

Every failure carries one of nine reasons, the same in every SDK:

| Reason | Meaning | Suggested response |
|---|---|---|
| `EXPIRED` | `exp` has passed | refresh the token, or send the user to sign in |
| `NOT_YET_VALID` | `nbf` is in the future | reject; check server clocks |
| `INVALID_SIGNATURE` | signature does not verify | reject; log as a security event |
| `INVALID_ISSUER` | wrong `iss` | reject; token from another system |
| `INVALID_AUDIENCE` | wrong `aud` | reject; token meant for another application |
| `MALFORMED` | not a well-formed JWT, or no `kid` | reject |
| `UNKNOWN_KEY` | the `kid` is not among the provider's keys | reject; treat as forged |
| `JWKS_UNAVAILABLE` | the provider's keys could not be fetched | **our** problem, not the caller's: answer 503 and let them retry |
| `OTHER` | anything else | reject; inspect the message |

Rust names them `TokenVerificationReason::Expired` and so on, and each has a
stable lower-case code (`reason.code()`, e.g. `"expired"`); Python's enum
values are those codes. The bundled [web filters](11-web.md) send that code
to clients.

The exception message has details useful in your logs (for a JWKS failure,
the provider URL and network error). **Don't send messages to clients**;
send the reason.

## How signing keys are fetched and cached

Gatedhouse downloads the provider's key set (JWKS) when it first needs it,
then manages it with the same policy in every SDK:

- **Keys are trusted for 5 minutes**, then refetched. A key the provider
  has removed (rotated out, or revoked after a leak) stops validating
  within 5 minutes.
- **At most one fetch every 30 seconds**, whether triggered by an unknown
  `kid` or by an earlier failed fetch. Forged tokens with made-up key IDs
  therefore cannot flood your provider with requests, and an outage doesn't
  add a slow network call to every request.
- **One fetch at a time.** Concurrent requests wait for that fetch and reuse
  its result; checks of tokens with known keys are not blocked by it.
- Each fetch is bounded by the JWKS timeout (default 5 s).

Consequences: after your provider rotates to a new key, tokens signed with it
validate as soon as the next fetch is allowed (immediately, unless a fetch
happened in the last 30 seconds). While the provider is unreachable, tokens
signed with keys fetched in the last 5 minutes keep working; after that,
verification fails with `JWKS_UNAVAILABLE`.

## The verified context

`GatedContext` turns a verified subject into a typed view of the claims
Sphinx puts in its tokens:

```java
GatedContext ctx = GatedContext.fromSubject(who);
ctx.personId();      // sub
ctx.email();         ctx.role();         ctx.identityType();   // "human" or "agent"
ctx.authMethod();    ctx.mfaVerified();  ctx.emailVerified();
ctx.clientId();      ctx.scope();        ctx.delegationId();   ctx.actorClaims();
ctx.isAdmin();       // role == "admin"
ctx.isHuman();       // identityType == "human"
ctx.isDelegated();   // a delegation_id is present
ctx.hasScope("invoices:write");
```

Python and Rust have the same fields in snake_case (`person_id`,
`identity_type`, `actor_claims`, `raw_claims`) and the same helpers
(`is_admin()`, `has_scope(...)`).

> `isAdmin()` reads the **token's** `role` claim, which your identity
> provider controls. It is not a Gatedhouse role. Use it for coarse gates
> (an internal admin console); use `hasPermission` for authorization
> decisions in your product.

## Connecting authentication to authorization

A typical request:

1. Verify the token, getting `who.id`.
2. Determine the org the request acts on (path, header, or a claim such as
   `org_id`), and check the resource belongs to it.
3. `hasPermission(who.id, org, service, resource, action)`.

The [web filters](11-web.md) do step 1 for you and attach the context to the
request.

## A verify-only instance

A service that only needs to verify tokens, with no database, can use:

```java
Gatedhouse verifier = GatedhouseFactory.createJustTokenVerifier(tokenVerifierConfig);
```

```python
verifier = GatedhouseFactory.create_just_token_verifier(token_verifier_config)
```

```rust
let verifier = GatedhouseFactory::create_just_token_verifier(token_verifier_config);
```

Every database method on it fails immediately (Java
`UnsupportedOperationException`, Python `NotImplementedError`, Rust panic).

## Without a verifier

Calling `verifyToken` on an instance created without a token verifier is a
configuration error: Java throws `IllegalStateException` and Python raises
`RuntimeError`. Rust returns a `TokenVerificationError` with reason `OTHER`.
