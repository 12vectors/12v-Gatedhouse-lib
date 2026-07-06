//! Login-CSRF-safe hosted-login flow for Sphinx (mirrors Java `LoginFlow`).
//!
//! Binds the authorization code to the browser that started the flow using
//! **PKCE** (not `state`). Framework-agnostic: returns cookie *values* for the
//! host to set/read with its own web framework. Set the `gh_login` cookie
//! `HttpOnly`, `Secure`, `SameSite=Lax`, `Max-Age = COOKIE_MAX_AGE_SECONDS`; on
//! `complete_login` clear it and rotate the session id on elevation.

use ring::rand::{SecureRandom, SystemRandom};
use ring::{digest, hmac};

use crate::error::{LoginCsrfError, LoginError};
use crate::secure_urls;
use crate::sphinx_client::{form_component, SphinxClient, TokenResponse};

/// Cookie the host sets on `begin_login` and reads on `complete_login`.
pub const COOKIE_NAME: &str = "gh_login";
/// Cookie the host reads for the deep-link return target (set by the web filter).
pub const RETURN_COOKIE_NAME: &str = "gh_return";
/// Suggested `Max-Age` (seconds) for the `gh_login` cookie.
pub const COOKIE_MAX_AGE_SECONDS: u64 = 600;

pub struct LoginFlow {
    authorize_url: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    signing_key: Vec<u8>,
    client: SphinxClient,
}

impl LoginFlow {
    pub fn new(
        sphinx_base_url: impl Into<String>,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        signing_key: &[u8],
        client: SphinxClient,
    ) -> Self {
        let mut base = sphinx_base_url.into();
        if base.ends_with('/') {
            base.pop();
        }
        secure_urls::require_https_or_loopback(&base, "Sphinx base URL");
        Self {
            authorize_url: format!("{base}/oauth/authorize"),
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            scope: scope.into(),
            signing_key: signing_key.to_vec(),
            client,
        }
    }

    /// Start a login: returns `(authorize_url, cookie_value)`. Redirect the
    /// browser to `authorize_url` and set the `gh_login` cookie to
    /// `cookie_value` (HttpOnly/Secure/SameSite=Lax).
    pub fn begin_login(&self) -> (String, String) {
        let mut buf = [0u8; 64];
        SystemRandom::new()
            .fill(&mut buf)
            .expect("CSPRNG failure generating PKCE verifier");
        let verifier = b64url(&buf);
        let challenge = self.challenge_for(&verifier);
        let query = [
            ("response_type", "code"),
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("scope", self.scope.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ]
        .iter()
        .map(|&(k, v)| format!("{k}={}", form_component(v)))
        .collect::<Vec<_>>()
        .join("&");
        // No state parameter — PKCE is the CSRF binding.
        (format!("{}?{}", self.authorize_url, query), self.sign(&verifier))
    }

    /// Require this browser's verifier cookie, then redeem the code with it.
    /// The host should clear the `gh_login` cookie and rotate the session id
    /// (anti-fixation) after a successful call.
    pub fn complete_login(
        &self,
        gh_login_cookie: Option<&str>,
        code: Option<&str>,
    ) -> Result<TokenResponse, LoginError> {
        let verifier = self.verify_cookie_value(gh_login_cookie).ok_or_else(|| {
            LoginError::Csrf(LoginCsrfError {
                message: "no login in progress for this browser".into(),
            })
        })?;
        let code = match code {
            Some(c) if !c.trim().is_empty() => c,
            _ => {
                return Err(LoginError::Csrf(LoginCsrfError {
                    message: "callback is missing the authorization code".into(),
                }))
            }
        };
        self.client
            .exchange_code(code, &self.redirect_uri, Some(&verifier))
            .map_err(LoginError::Exchange)
    }

    /// Return an open-redirect-safe same-origin path from the `gh_return`
    /// cookie, or `default_home`. The host should also clear the cookie.
    pub fn consume_return_to(&self, gh_return_cookie: Option<&str>, default_home: &str) -> String {
        Self::sanitize_return_to(gh_return_cookie).unwrap_or_else(|| default_home.to_string())
    }

    // ---- PKCE + signed cookie ("verifier.hmac") ---------------------------

    /// RFC 7636 S256: `BASE64URL(SHA256(ASCII(verifier)))`.
    pub fn challenge_for(&self, verifier: &str) -> String {
        b64url(digest::digest(&digest::SHA256, verifier.as_bytes()).as_ref())
    }

    pub fn sign(&self, verifier: &str) -> String {
        format!("{verifier}.{}", b64url(self.hmac(verifier).as_ref()))
    }

    /// Return the verifier if the signed cookie is authentic, else `None`.
    pub fn verify_cookie_value(&self, raw: Option<&str>) -> Option<String> {
        let raw = raw?;
        let dot = raw.rfind('.')?;
        if dot == 0 {
            return None;
        }
        let verifier = &raw[..dot];
        let mac = &raw[dot + 1..];
        let expected = b64url(self.hmac(verifier).as_ref());
        if constant_time_eq(mac.as_bytes(), expected.as_bytes()) {
            Some(verifier.to_string())
        } else {
            None
        }
    }

    fn hmac(&self, verifier: &str) -> hmac::Tag {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.signing_key);
        hmac::sign(&key, verifier.as_bytes())
    }

    /// Return `raw` if it is a safe same-origin relative path, else `None`.
    pub fn sanitize_return_to(raw: Option<&str>) -> Option<String> {
        let raw = raw?;
        let bytes = raw.as_bytes();
        // Must be an absolute-path reference: exactly one leading '/'.
        if bytes.first() != Some(&b'/') {
            return None;
        }
        if bytes.len() >= 2 && (bytes[1] == b'/' || bytes[1] == b'\\') {
            return None; // //host or /\host
        }
        for &b in bytes {
            if b <= 0x20 || b == 0x7f || b == b'\\' {
                return None;
            }
        }
        if raw.contains("://") {
            return None;
        }
        Some(raw.to_string())
    }
}

/// Constant-time equality for the (fixed-length) MAC comparison — no early-out
/// on content, so a forged cookie can't be discovered byte-by-byte by timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// URL-safe base64 without padding (RFC 4648 §5).
fn b64url(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(A[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(A[(n & 63) as usize] as char);
        }
    }
    out
}
