//! Internal `jsonwebtoken`-backed verifier used by
//! `Gatedhouse::verify_token`. Not part of the public API.
//!
//! Mirrors the Java `JwtVerification` package-private helper.
//!
//! Thread-safe: the JWKS cache is behind a `Mutex` so concurrent
//! callers serialize only when the cache is empty or being refreshed.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;

use crate::error::{TokenVerificationError, TokenVerificationReason};
use crate::token_verifier::TokenVerifierConfig;
use crate::types::AuthenticatedSubject;

const STANDARD_CLAIMS: &[&str] = &["sub", "iss", "aud", "iat", "exp", "nbf", "type"];

/// Re-fetch JWKS on miss but no more often than this interval, to avoid
/// hammering the issuer if every request carries an unknown `kid`.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

pub(crate) struct JwtVerification {
    jwks_uri: String,
    issuer: String,
    audience: String,
    cache: Mutex<JwksCacheState>,
}

struct JwksCacheState {
    jwks: Option<JwkSet>,
    last_refresh: Option<Instant>,
}

impl JwtVerification {
    pub(crate) fn new(config: &TokenVerifierConfig) -> Self {
        Self {
            jwks_uri: config.jwks_uri.clone(),
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            cache: Mutex::new(JwksCacheState {
                jwks: None,
                last_refresh: None,
            }),
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

        // 2. Locate the matching JWK; refresh JWKS on miss.
        let jwk = self.find_key(&kid)?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|e| {
            TokenVerificationError::new(
                TokenVerificationReason::Other,
                format!("JWK could not be converted to DecodingKey: {e}"),
            )
        })?;

        // 3. Validate signature + standard claims.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        // jsonwebtoken validates exp/nbf by default.

        let token_data = decode::<HashMap<String, Value>>(token, &key, &validation)
            .map_err(map_jwt_error)?;

        // 4. Build AuthenticatedSubject.
        Self::build_subject(token_data.claims)
    }

    fn find_key(&self, kid: &str) -> Result<Jwk, TokenVerificationError> {
        // Fast path: cached JwkSet has the kid.
        {
            let state = self.cache.lock().expect("jwks lock poisoned");
            if let Some(jwks) = &state.jwks {
                if let Some(jwk) = jwks.find(kid).cloned() {
                    return Ok(jwk);
                }
            }
        }

        // Slow path: refresh, but rate-limit so a flood of unknown-kid
        // tokens doesn't hammer the issuer.
        let mut state = self.cache.lock().expect("jwks lock poisoned");
        let now = Instant::now();
        let recently_refreshed = state
            .last_refresh
            .map(|t| now.duration_since(t) < MIN_REFRESH_INTERVAL)
            .unwrap_or(false);

        if state.jwks.is_none() || !recently_refreshed {
            let fresh = fetch_jwks(&self.jwks_uri)?;
            state.jwks = Some(fresh);
            state.last_refresh = Some(now);
        }

        let jwks = state
            .jwks
            .as_ref()
            .expect("JWKS just refreshed but is None");
        if let Some(jwk) = jwks.find(kid).cloned() {
            Ok(jwk)
        } else {
            Err(TokenVerificationError::new(
                TokenVerificationReason::UnknownKey,
                format!("kid {kid:?} not present in JWKS"),
            ))
        }
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

fn fetch_jwks(uri: &str) -> Result<JwkSet, TokenVerificationError> {
    let response = ureq::get(uri).call().map_err(|e| {
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
