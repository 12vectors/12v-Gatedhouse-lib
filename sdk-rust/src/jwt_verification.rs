// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Internal `jsonwebtoken`-backed verifier used by
//! `Gatedhouse::verify_token`. Not part of the public API.
//!
//! Mirrors the Java `JwtVerification` package-private helper.
//!
//! Thread-safe. The JWKS caching policy matches the Java (Nimbus) and Python
//! SDKs: keys live [`JWKS_CACHE_TTL`]; a refetch happens at most once per
//! [`JWKS_MIN_REFRESH_INTERVAL`], by one thread, outside the state lock.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;

use crate::error::{TokenVerificationError, TokenVerificationReason};
use crate::token_verifier::TokenVerifierConfig;
use crate::types::AuthenticatedSubject;

const STANDARD_CLAIMS: &[&str] = &["sub", "iss", "aud", "iat", "exp", "nbf", "type"];

/// How long fetched signing keys are trusted before they are refetched, so a
/// key the identity provider has removed stops validating (the Java SDK's
/// Nimbus default).
pub(crate) const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);
/// Least time between two fetches of the JWKS, whether triggered by an
/// unknown `kid` or by a failed fetch, so forged tokens cannot flood the
/// identity provider and an outage does not add a fetch to every request.
pub(crate) const JWKS_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) struct JwtVerification {
    jwks_uri: String,
    /// Bounds connecting and each read with `TokenVerifierConfig::jwks_timeout`.
    agent: ureq::Agent,
    /// Built once: RS256 only, issuer and audience pinned.
    validation: Validation,
    cache_ttl: Duration,
    min_refresh_interval: Duration,
    /// Read on every verification; written only after a fetch completes.
    state: RwLock<JwksState>,
    /// Serializes fetching, so one thread fetches and the others reuse its
    /// outcome. Never held while `state` is locked for writing.
    fetch_lock: Mutex<()>,
}

#[derive(Default)]
struct JwksState {
    /// Parsed once per fetch, not per verification.
    keys: HashMap<String, Arc<DecodingKey>>,
    fetched_at: Option<Instant>,
    attempted_at: Option<Instant>,
    /// Set while the most recent fetch failed.
    last_error: Option<String>,
}

impl JwtVerification {
    pub(crate) fn new(config: &TokenVerifierConfig) -> Self {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&[&config.audience]);
        // jsonwebtoken validates exp/nbf by default, but with 60 s of leeway;
        // the Java and Python SDKs apply none, so neither does this one.
        validation.leeway = 0;
        Self {
            jwks_uri: config.jwks_uri.clone(),
            agent: crate::sphinx_client::agent_with_timeout(config.jwks_timeout),
            validation,
            cache_ttl: JWKS_CACHE_TTL,
            min_refresh_interval: JWKS_MIN_REFRESH_INTERVAL,
            state: RwLock::new(JwksState::default()),
            fetch_lock: Mutex::new(()),
        }
    }

    pub(crate) fn verify(&self, token: &str) -> Result<AuthenticatedSubject, TokenVerificationError> {
        // 1. Parse header to extract the `kid`.
        let header = decode_header(token).map_err(|e| {
            TokenVerificationError::new(
                TokenVerificationReason::Malformed,
                format!("JWT header parse failed: {e}"),
            )
        })?;
        let kid = header.kid.ok_or_else(|| {
            TokenVerificationError::new(
                TokenVerificationReason::Malformed,
                "JWT header has no kid",
            )
        })?;

        // 2. Locate the matching key.
        let key = self.key_for(&kid)?;

        // 3. Validate signature + standard claims.
        let token_data = decode::<HashMap<String, Value>>(token, &key, &self.validation)
            .map_err(map_jwt_error)?;

        // 4. Build AuthenticatedSubject.
        Self::build_subject(token_data.claims)
    }

    fn key_for(&self, kid: &str) -> Result<Arc<DecodingKey>, TokenVerificationError> {
        if let Some(key) = self.fresh(kid, Instant::now()) {
            return Ok(key);
        }
        let _fetching = self.fetch_lock.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        if let Some(key) = self.fresh(kid, now) {
            return Ok(key); // another thread just fetched
        }
        let recently = self
            .read_state()
            .attempted_at
            .is_some_and(|t| now.duration_since(t) < self.min_refresh_interval);
        if !recently {
            // The network wait happens here, holding only `fetch_lock`:
            // verifications of known keys continue meanwhile.
            let fetched = fetch_jwks(&self.agent, &self.jwks_uri);
            let mut state = self.state.write().unwrap_or_else(|p| p.into_inner());
            state.attempted_at = Some(now);
            match fetched {
                Ok(set) => {
                    state.keys = signing_keys(&set);
                    state.fetched_at = Some(now);
                    state.last_error = None;
                }
                Err(e) => state.last_error = Some(e.message),
            }
        }
        let state = self.read_state();
        if let Some(error) = &state.last_error {
            return Err(TokenVerificationError::new(
                TokenVerificationReason::JwksUnavailable,
                format!("JWKS could not be fetched: {error}"),
            ));
        }
        state.keys.get(kid).cloned().ok_or_else(|| {
            TokenVerificationError::new(
                TokenVerificationReason::UnknownKey,
                format!("kid {kid:?} not present in JWKS"),
            )
        })
    }

    fn fresh(&self, kid: &str, now: Instant) -> Option<Arc<DecodingKey>> {
        let state = self.read_state();
        let fetched_at = state.fetched_at?;
        if now.duration_since(fetched_at) >= self.cache_ttl {
            return None;
        }
        state.keys.get(kid).cloned()
    }

    fn read_state(&self) -> std::sync::RwLockReadGuard<'_, JwksState> {
        self.state.read().unwrap_or_else(|p| p.into_inner())
    }

    fn build_subject(
        claims: HashMap<String, Value>,
    ) -> Result<AuthenticatedSubject, TokenVerificationError> {
        let id = string_claim(&claims, "sub")?;
        let issuer = string_claim(&claims, "iss")?;
        let audience = match claims.get("aud") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(arr)) => arr
                .first()
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| {
                    TokenVerificationError::new(
                        TokenVerificationReason::Malformed,
                        "aud claim is an empty array",
                    )
                })?,
            _ => {
                return Err(TokenVerificationError::new(
                    TokenVerificationReason::Malformed,
                    "aud claim missing or wrong type",
                ));
            }
        };

        let expires_at = ts_claim(&claims, "exp")?;
        let issued_at = match claims.get("iat") {
            Some(Value::Number(n)) => n.as_i64().map(seconds_to_systemtime),
            _ => None,
        };
        let token_type = match claims.get("type") {
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        };

        let standard: HashSet<&str> = STANDARD_CLAIMS.iter().copied().collect();
        let custom: HashMap<String, Value> = claims
            .into_iter()
            .filter(|(k, _)| !standard.contains(k.as_str()))
            .collect();

        Ok(AuthenticatedSubject {
            id,
            issuer,
            audience,
            issued_at,
            expires_at,
            token_type,
            claims: custom,
        })
    }
}

fn fetch_jwks(agent: &ureq::Agent, uri: &str) -> Result<JwkSet, TokenVerificationError> {
    let response = agent.get(uri).call().map_err(|e| {
        TokenVerificationError::new(
            TokenVerificationReason::JwksUnavailable,
            format!("JWKS endpoint unreachable ({uri}): {e}"),
        )
    })?;
    response.into_json::<JwkSet>().map_err(|e| {
        TokenVerificationError::new(
            TokenVerificationReason::JwksUnavailable,
            format!("JWKS payload could not be parsed: {e}"),
        )
    })
}

/// Signing keys by `kid`, parsed once. Keys without a `kid`, marked for
/// encryption, or not convertible to a decoding key are skipped.
fn signing_keys(set: &JwkSet) -> HashMap<String, Arc<DecodingKey>> {
    use jsonwebtoken::jwk::PublicKeyUse;
    set.keys
        .iter()
        .filter(|jwk| !matches!(jwk.common.public_key_use, Some(PublicKeyUse::Encryption)))
        .filter_map(|jwk| {
            let kid = jwk.common.key_id.clone()?;
            let key = DecodingKey::from_jwk(jwk).ok()?;
            Some((kid, Arc::new(key)))
        })
        .collect()
}

fn map_jwt_error(e: jsonwebtoken::errors::Error) -> TokenVerificationError {
    use jsonwebtoken::errors::ErrorKind as K;
    let reason = match e.kind() {
        K::ExpiredSignature => TokenVerificationReason::Expired,
        K::ImmatureSignature => TokenVerificationReason::NotYetValid,
        K::InvalidIssuer => TokenVerificationReason::InvalidIssuer,
        K::InvalidAudience => TokenVerificationReason::InvalidAudience,
        K::InvalidSignature => TokenVerificationReason::InvalidSignature,
        K::InvalidToken
        | K::InvalidAlgorithm
        | K::InvalidAlgorithmName
        | K::Base64(_)
        | K::Json(_)
        | K::Utf8(_) => TokenVerificationReason::Malformed,
        _ => TokenVerificationReason::Other,
    };
    TokenVerificationError::new(reason, e.to_string())
}

fn string_claim(
    claims: &HashMap<String, Value>,
    name: &str,
) -> Result<String, TokenVerificationError> {
    match claims.get(name) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(TokenVerificationError::new(
            TokenVerificationReason::Malformed,
            format!("{name} claim missing or not a string"),
        )),
    }
}

fn ts_claim(
    claims: &HashMap<String, Value>,
    name: &str,
) -> Result<SystemTime, TokenVerificationError> {
    match claims.get(name) {
        Some(Value::Number(n)) => n.as_i64().map(seconds_to_systemtime).ok_or_else(|| {
            TokenVerificationError::new(
                TokenVerificationReason::Malformed,
                format!("{name} claim is not a valid integer timestamp"),
            )
        }),
        _ => Err(TokenVerificationError::new(
            TokenVerificationReason::Malformed,
            format!("{name} claim missing"),
        )),
    }
}

fn seconds_to_systemtime(secs: i64) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs((-secs) as u64)
    }
}

#[cfg(test)]
mod tests {
    //! JWKS fetch limits, against a counting local identity provider. The
    //! key in tests/data is a throwaway generated for these tests only.

    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    const TEST_KEY_PEM: &str = include_str!("../tests/data/jwks_test_key.pem");
    const TEST_KEY_N: &str = "kUpDB-I85yV8Y192kcYPbiB94O0EgVBdy0y2HzLgwBAOikoc9Tc26sSwPA6DIdyr0Ni_HQ-eEPAfioMRQIn2t87ZpTdE3KvzrjM68kI3Z1h8emtX4oqz9X76ZpDqBZaC76vzJELeMzt1wbxffFnc3HvMnr_3uy02cO2206N3F5N-IxqzX9QhQ_ffZR0U9infPs7sY52QQPsDrmYadk4hii3yDhWA0KmLLJ4DULYOnyUH2BX4s0FWG-aEfX12Y6KtmFMABsMTVjVXXqDwK4q5BZ7fOkwReh84iDWIejaSQuhavYCg66MjqgZavs157k3zXFx8Noxi2qWbJAySuKxZtw";

    struct Idp {
        uri: String,
        requests: Arc<AtomicUsize>,
        response: Arc<Mutex<(u16, String)>>,
    }

    fn jwks(kid: &str) -> String {
        format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","use":"sig","alg":"RS256","n":"{TEST_KEY_N}","e":"AQAB"}}]}}"#
        )
    }

    fn idp() -> Idp {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let uri = format!("http://{}/jwks.json", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let response = Arc::new(Mutex::new((200, jwks("k1"))));
        let (count, body) = (requests.clone(), response.clone());
        thread::spawn(move || {
            for mut conn in listener.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let _ = conn.read(&mut buf);
                count.fetch_add(1, Ordering::SeqCst);
                let (status, body) = body.lock().unwrap().clone();
                let _ = write!(
                    conn,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        Idp { uri, requests, response }
    }

    fn verifier(idp: &Idp) -> JwtVerification {
        JwtVerification::new(&TokenVerifierConfig::new(&idp.uri, "iss", "aud"))
    }

    fn token(kid: &str) -> String {
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let exp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 600;
        let claims = serde_json::json!({"sub": "u", "iss": "iss", "aud": "aud", "exp": exp});
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).unwrap();
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }

    fn reason(result: Result<AuthenticatedSubject, TokenVerificationError>) -> TokenVerificationReason {
        result.expect_err("verification should fail").reason
    }

    #[test]
    fn valid_tokens_share_one_fetch() {
        let idp = idp();
        let v = verifier(&idp);
        for _ in 0..50 {
            assert_eq!("u", v.verify(&token("k1")).unwrap().id);
        }
        assert_eq!(1, idp.requests.load(Ordering::SeqCst));
    }

    #[test]
    fn forged_kids_cannot_flood_the_identity_provider() {
        let idp = idp();
        let v = verifier(&idp);
        v.verify(&token("k1")).unwrap();
        for i in 0..50 {
            assert_eq!(TokenVerificationReason::UnknownKey, reason(v.verify(&token(&format!("forged-{i}")))));
        }
        assert_eq!(1, idp.requests.load(Ordering::SeqCst));
    }

    #[test]
    fn failed_fetches_are_rate_limited_too() {
        let idp = idp();
        *idp.response.lock().unwrap() = (500, "boom".into());
        let v = verifier(&idp);
        for _ in 0..20 {
            assert_eq!(TokenVerificationReason::JwksUnavailable, reason(v.verify(&token("k1"))));
        }
        assert_eq!(1, idp.requests.load(Ordering::SeqCst));
    }

    #[test]
    fn keys_expire_so_removed_keys_stop_validating() {
        let idp = idp();
        let mut v = verifier(&idp);
        v.cache_ttl = Duration::from_millis(200);
        v.min_refresh_interval = Duration::from_millis(100);
        v.verify(&token("k1")).unwrap();
        *idp.response.lock().unwrap() = (200, jwks("k2")); // the IdP rotates k1 out
        thread::sleep(Duration::from_millis(300));
        assert_eq!(TokenVerificationReason::UnknownKey, reason(v.verify(&token("k1"))));
        assert_eq!(2, idp.requests.load(Ordering::SeqCst));
    }

    #[test]
    fn expired_tokens_are_rejected_without_leeway() {
        let idp = idp();
        let v = verifier(&idp);
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some("k1".into());
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let claims = serde_json::json!({"sub": "u", "iss": "iss", "aud": "aud", "exp": now - 5});
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).unwrap();
        let expired = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        assert_eq!(TokenVerificationReason::Expired, reason(v.verify(&expired)));
    }

    #[test]
    fn defaults_match_the_other_sdks() {
        assert_eq!(Duration::from_secs(300), JWKS_CACHE_TTL);
        assert_eq!(Duration::from_secs(30), JWKS_MIN_REFRESH_INTERVAL);
    }
}
