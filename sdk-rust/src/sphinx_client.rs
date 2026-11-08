// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! HTTP client wrapper to orchestrate Sphinx SSO OAuth 2.0 endpoints.
//!
//! Uses `ureq` (already a dependency for JWKS fetching), mirroring the
//! Java `SphinxClient` which uses `java.net.http.HttpClient`.
//!
//! Every call is bounded: no network wait (connecting, or waiting for data)
//! exceeds [`SphinxClient::timeout`], which defaults to
//! [`SphinxClient::DEFAULT_TIMEOUT`]. Failures are reported as
//! [`SphinxError`], whose [`kind`](SphinxError::kind) tells a timeout or an
//! unreachable IdP apart from a refused request. The client never retries.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::time::Duration;

use serde_json::{Map, Value};

/// How a Sphinx call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SphinxErrorKind {
    /// A network wait (connecting, or waiting for data) exceeded the client's timeout.
    Timeout,
    /// The endpoint could not be reached, or the connection failed, other
    /// than by timing out.
    Transport,
    /// The endpoint answered with an unsuccessful HTTP status; see
    /// [`SphinxError::status_code`].
    HttpStatus,
    /// The endpoint answered, but the body was not the expected JSON object.
    InvalidResponse,
}

/// A [`SphinxClient`] call failed. [`kind`](Self::kind) says how, so a host
/// can tell "the IdP is unavailable, try again" (`Timeout`, `Transport`)
/// apart from "the request was refused" (`HttpStatus`, e.g. an invalid or
/// already-used authorization code).
///
/// The library never retries. In particular, do not blindly retry
/// [`SphinxClient::exchange_code`] after a timeout: authorization codes are
/// single-use, and the IdP may already have consumed the code.
#[derive(Debug)]
pub struct SphinxError {
    pub kind: SphinxErrorKind,
    /// The HTTP status for [`SphinxErrorKind::HttpStatus`]; `None` otherwise.
    pub status_code: Option<u16>,
    pub message: String,
}

impl SphinxError {
    fn new(kind: SphinxErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            status_code: None,
            message: message.into(),
        }
    }
}

impl fmt::Display for SphinxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SphinxError {}

/// Parsed body of a successful Sphinx token-endpoint response.
#[derive(Debug, Clone)]
pub struct TokenResponse {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: i64,
    pub scope: Option<String>,
    pub issued_token_type: Option<String>,
}

/// HTTP client wrapper to orchestrate Sphinx SSO OAuth 2.0 endpoints.
/// Create one and reuse it.
pub struct SphinxClient {
    base_url: String,
    client_id: String,
    client_secret: String,
    timeout: Duration,
    agent: ureq::Agent,
}

impl SphinxClient {
    /// The timeout used when none is given: 10 seconds.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

    /// A client with [`DEFAULT_TIMEOUT`](Self::DEFAULT_TIMEOUT); use
    /// [`with_timeout`](Self::with_timeout) to change it.
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        let mut base_url = base_url.into();
        if base_url.ends_with('/') {
            base_url.pop();
        }
        Self {
            base_url,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            timeout: Self::DEFAULT_TIMEOUT,
            agent: agent_with_timeout(Self::DEFAULT_TIMEOUT),
        }
    }

    /// Sets the longest any single network wait may take.
    ///
    /// # Panics
    ///
    /// If `timeout` is zero.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        assert!(!timeout.is_zero(), "SphinxClient timeout must be positive");
        self.timeout = timeout;
        self.agent = agent_with_timeout(timeout);
        self
    }

    /// The longest any single network wait may take.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Exchanges an authorization code for tokens.
    pub fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<TokenResponse, SphinxError> {
        self.post_token(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ])
    }

    /// Requests tokens via client credentials grant.
    pub fn client_credentials(&self, scope: Option<&str>) -> Result<TokenResponse, SphinxError> {
        let mut form = vec![
            ("grant_type", "client_credentials"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
        ];
        if let Some(scope) = scope {
            form.push(("scope", scope));
        }
        self.post_token(&form)
    }

    /// Performs an OAuth 2.0 Token Exchange.
    pub fn token_exchange(
        &self,
        subject_token: &str,
        actor_token: &str,
        delegation_id: &str,
        scope: Option<&str>,
    ) -> Result<TokenResponse, SphinxError> {
        let mut form = vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", subject_token),
            ("actor_token", actor_token),
            ("delegation_id", delegation_id),
        ];
        if let Some(scope) = scope {
            form.push(("scope", scope));
        }
        self.post_token(&form)
    }

    /// Refreshes an access token using a refresh token.
    pub fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse, SphinxError> {
        self.post_token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ])
    }

    /// Introspects an access token.
    pub fn introspect(&self, token: &str) -> Result<Map<String, Value>, SphinxError> {
        // The introspection endpoint conveys inactive or invalid tokens in
        // the body, so the body is parsed whatever the status.
        let (_, body) = self.post_form(
            "/api/sphinx/v1/oauth/introspect",
            &[("token", token)],
            "Introspection",
        )?;
        parse_object(&body, "Introspection")
    }

    /// Builds a redirect URL to the standard Sphinx login page.
    pub fn login_url(&self, app_shortcode: &str) -> String {
        format!("{}/login?app={}", self.base_url, form_encode(app_shortcode))
    }

    /// Builds a redirect URL to a federated Sphinx login provider.
    pub fn federated_login_url(
        &self,
        sso_connection_id: &str,
        app_shortcode: Option<&str>,
    ) -> String {
        let mut url = format!(
            "{}/api/sphinx/v1/auth/federated/{}",
            self.base_url,
            form_encode(sso_connection_id)
        );
        if let Some(app) = app_shortcode {
            url.push_str("?app=");
            url.push_str(&form_encode(app));
        }
        url
    }

    fn post_token(&self, form: &[(&str, &str)]) -> Result<TokenResponse, SphinxError> {
        let (status, body) = self.post_form("/api/sphinx/v1/oauth/token", form, "Token request")?;
        if status != 200 {
            return Err(SphinxError {
                kind: SphinxErrorKind::HttpStatus,
                status_code: Some(status),
                message: format!("Token request failed ({status}): {body}"),
            });
        }
        let json = parse_object(&body, "Token request")?;
        let str_field = |name: &str| json.get(name).and_then(Value::as_str).map(str::to_string);
        Ok(TokenResponse {
            access_token: str_field("access_token"),
            refresh_token: str_field("refresh_token"),
            token_type: str_field("token_type"),
            expires_in: json.get("expires_in").and_then(Value::as_i64).unwrap_or(0),
            scope: str_field("scope"),
            issued_token_type: str_field("issued_token_type"),
        })
    }

    /// POSTs a form; returns `(status, body)` for any HTTP answer, and a
    /// [`SphinxError`] when there is none.
    fn post_form(
        &self,
        path: &str,
        form: &[(&str, &str)],
        op: &str,
    ) -> Result<(u16, String), SphinxError> {
        let url = format!("{}{}", self.base_url, path);
        let response = match self.agent.post(&url).send_form(form) {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r, // an HTTP answer, just not 2xx
            Err(ureq::Error::Transport(t)) => {
                return Err(if is_timeout(&t) {
                    self.timed_out(op)
                } else {
                    SphinxError::new(SphinxErrorKind::Transport, format!("{op} failed: {t}"))
                })
            }
        };
        let status = response.status();
        match response.into_string() {
            Ok(body) => Ok((status, body)),
            Err(e) if is_timeout_io(&e) => Err(self.timed_out(op)),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => Err(SphinxError::new(
                SphinxErrorKind::InvalidResponse,
                format!("{op} returned a response that could not be read: {e}"),
            )),
            Err(e) => Err(SphinxError::new(
                SphinxErrorKind::Transport,
                format!("{op} failed reading the response: {e}"),
            )),
        }
    }

    fn timed_out(&self, op: &str) -> SphinxError {
        SphinxError::new(
            SphinxErrorKind::Timeout,
            format!("{op} timed out (timeout {} ms)", self.timeout.as_millis()),
        )
    }
}

/// An agent bounding connecting, each read and each write.
pub(crate) fn agent_with_timeout(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .build()
}

/// True if the transport error was caused by a timeout anywhere in its
/// source chain.
fn is_timeout(error: &ureq::Transport) -> bool {
    let mut source: Option<&(dyn StdError + 'static)> = error.source();
    while let Some(e) = source {
        if let Some(io) = e.downcast_ref::<io::Error>() {
            if is_timeout_io(io) {
                return true;
            }
        }
        source = e.source();
    }
    false
}

/// Read timeouts surface as `TimedOut` on most platforms and `WouldBlock`
/// on some.
fn is_timeout_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn parse_object(body: &str, op: &str) -> Result<Map<String, Value>, SphinxError> {
    let json: Value = serde_json::from_str(body).map_err(|e| {
        SphinxError::new(
            SphinxErrorKind::InvalidResponse,
            format!("{op} returned a response that is not JSON: {e}"),
        )
    })?;
    match json {
        Value::Object(map) => Ok(map),
        _ => Err(SphinxError::new(
            SphinxErrorKind::InvalidResponse,
            format!("{op} returned JSON that is not an object"),
        )),
    }
}

/// `application/x-www-form-urlencoded` encoding, matching Java's
/// `URLEncoder.encode` (space becomes `+`; `-_.*` stay literal).
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
