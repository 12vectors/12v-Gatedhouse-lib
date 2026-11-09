# 10. Authentication

Optional. Verifies JWTs issued by an identity provider (Sphinx SSO
compatible) against its JWKS.

## Configuration

| Setting | Required | Default | Sphinx value |
|---|---|---|---|
| JWKS URI | yes | | `https://<sphinx-host>/api/sphinx/v1/auth/jwks` |
| issuer (`iss`) | yes | | literal `sphinx` (the `OIDC_ISSUER` URL is only for OIDC id_tokens) |
| audience (`aud`) | yes | | the app's `client_id` registered in Sphinx |
| JWKS fetch timeout | no | 5 s | |

```java
.tokenVerifier(TokenVerifierConfig.builder()
    .jwksUri(URI.create("https://sso.example.com/api/sphinx/v1/auth/jwks"))
    .issuer("sphinx").audience("my-app-client-id")
    .jwksTimeout(Duration.ofSeconds(5)).build())
```
```python
GatedhouseConfig(database=db, token_verifier=TokenVerifierConfig(jwks_uri, issuer, audience, jwks_timeout=5.0))
```
```rust
GatedhouseConfig::builder(db).token_verifier(
    TokenVerifierConfig::new(jwks_uri, issuer, audience).with_jwks_timeout(Duration::from_secs(5)))
```

## Verification

`verifyToken(jwt)` returns an `AuthenticatedSubject` or fails with
`TokenVerificationException` (Java, Python) / `TokenVerificationError` (Rust).

Accepted only if: algorithm RS256; header `kid` present in the JWKS and the
signature verifies; `iss` equals the issuer; `aud` contains the audience;
`exp` not passed; `nbf` (if present) reached. No clock-skew leeway.

| `AuthenticatedSubject` | Claim |
|---|---|
| `id` | `sub` (pass to `hasPermission`) |
| `issuer`, `audience` | `iss`, `aud` (first if a list) |
| `issuedAt`, `expiresAt` | `iat` (optional), `exp` |
| `tokenType` | `type` (optional) |
| `claims` | all non-standard claims |

| Reason | Cause | Response |
|---|---|---|
| `EXPIRED` | `exp` passed | 401; refresh or re-login |
| `NOT_YET_VALID` | `nbf` in the future | 401 |
| `INVALID_SIGNATURE` | signature fails | 401; security event |
| `INVALID_ISSUER` | wrong `iss` | 401 |
| `INVALID_AUDIENCE` | wrong `aud` | 401 |
| `MALFORMED` | not a JWT, or no `kid` | 401 |
| `UNKNOWN_KEY` | `kid` not in JWKS | 401; treat as forged |
| `JWKS_UNAVAILABLE` | JWKS not fetchable | **503** |
| `OTHER` | anything else | 401 |

Stable codes: the lower-case names (`"expired"`); Rust `reason.code()`,
Python enum values. Messages contain internal detail (IdP URL, network
errors): log them, do not return them to clients.

## JWKS caching (all SDKs)

| Rule | Value |
|---|---|
| key lifetime | 5 min, then refetched (removed keys stop validating) |
| minimum interval between fetches (unknown `kid` or failed fetch) | 30 s |
| concurrency | one fetch at a time; others reuse its result; known keys not blocked |
| fetch timeout | JWKS timeout (default 5 s) |

During an IdP outage, keys fetched within the last 5 minutes keep working;
afterwards verification fails with `JWKS_UNAVAILABLE`. For persistent
`JWKS_UNAVAILABLE`, check that the JWKS URL is reachable from the host.

## GatedContext

`GatedContext.fromSubject(subject)` maps Sphinx claims: `personId` (`sub`),
`email`, `role`, `identityType` (`person_type`, default `human`), `authMethod`,
`mfaVerified`, `emailVerified`, `clientId`, `scope`, `delegationId`,
`actorClaims` (`act`), `rawClaims`. Helpers: `isAdmin()` (`role == "admin"`),
`isHuman()`, `isDelegated()`, `hasScope(s)` (space-separated `scope`). Python
and Rust use snake_case. `role` is the token's claim set by the IdP, not a
Gatedhouse role.

## Verify-only instance

`GatedhouseFactory.createJustTokenVerifier(config)` needs no database; its
database methods fail (Java `UnsupportedOperationException`, Python
`NotImplementedError`, Rust panic).

Without a configured verifier, `verifyToken` fails: Java
`IllegalStateException`, Python `RuntimeError`, Rust
`TokenVerificationError` with reason `OTHER`.
