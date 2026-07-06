//! Client for Sphinx SSO's OAuth 2.0 endpoints (mirrors Java `SphinxClient`).

use std::time::Duration;

use serde_json::Value;

use crate::error::SphinxError;
use crate::secure_urls;

/// Bounds connection setup so an unreachable Sphinx can't hang caller threads.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bound on a single token/introspection round-trip.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Parsed OAuth token-endpoint response.
#[derive(Debug, Clone)]
pub struct TokenResponse {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: i64,
    pub scope: Option<String>,
    pub issued_token_type: Option<String>,
}

/// Thin wrapper over the Sphinx OAuth 2.0 token/introspection endpoints.
///
/// Prefer [`crate::LoginFlow`] for the browser login flow; use `SphinxClient`
/// directly for machine-to-machine grants.
pub struct SphinxClient {
    base_url: String,
    client_id: String,
    client_secret: String,
    agent: ureq::Agent,
}

impl SphinxClient {
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        let mut base = base_url.into();
        if base.ends_with('/') {
            base.pop();
        }
        // This client transmits the client_secret and receives tokens — refuse
        // a non-TLS base URL (review M5).
        secure_urls::require_https_or_loopback(&base, "Sphinx baseUrl");
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build();
        Self {
            base_url: base,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            agent,
        }
    }

    // ---- grants -----------------------------------------------------------

    pub fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse, SphinxError> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
        ];
        if let Some(v) = code_verifier {
            form.push(("code_verifier", v));
        }
        self.post_token(&form)
    }

    pub fn client_credentials(&self, scope: Option<&str>) -> Result<TokenResponse, SphinxError> {
        let mut form = vec![
            ("grant_type", "client_credentials"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
        ];
        if let Some(s) = scope {
            form.push(("scope", s));
        }
        self.post_token(&form)
    }

    pub fn token_exchange(
        &self,
        subject_token: &str,
        actor_token: &str,
        delegation_id: &str,
        scope: Option<&str>,
    ) -> Result<TokenResponse, SphinxError> {
        let mut form = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", subject_token),
            ("actor_token", actor_token),
            ("delegation_id", delegation_id),
        ];
        if let Some(s) = scope {
            form.push(("scope", s));
        }
        self.post_token(&form)
    }

    pub fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse, SphinxError> {
        let form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
        ];
        self.post_token(&form)
    }

    /// Introspect an access token. Fails closed on a non-200 so an error / proxy
    /// body is never handed back as if it were a valid result (review L1).
    pub fn introspect(&self, token: &str) -> Result<Value, SphinxError> {
        let url = format!("{}/api/sphinx/v1/oauth/token/introspect", self.base_url);
        let (status, body) = self.send_form(&url, &[("token", token)])?;
        if status != 200 {
            return Err(SphinxError::Status {
                status,
                oauth_error: oauth_error(&body),
            });
        }
        serde_json::from_str(&body).map_err(|e| SphinxError::Parse(e.to_string()))
    }

    // ---- redirect URL builders -------------------------------------------

    pub fn login_url(&self, app_shortcode: &str) -> String {
        format!("{}/login?app={}", self.base_url, form_component(app_shortcode))
    }

    pub fn federated_login_url(
        &self,
        sso_connection_id: &str,
        app_shortcode: Option<&str>,
    ) -> String {
        let mut url = format!(
            "{}/api/sphinx/v1/auth/federated/{}",
            self.base_url,
            form_component(sso_connection_id)
        );
        if let Some(app) = app_shortcode {
            url.push_str(&format!("?app={}", form_component(app)));
        }
        url
    }

    // ---- internals --------------------------------------------------------

    fn post_token(&self, form: &[(&str, &str)]) -> Result<TokenResponse, SphinxError> {
        let url = format!("{}/api/sphinx/v1/oauth/token", self.base_url);
        let (status, body) = self.send_form(&url, form)?;
        if status != 200 {
            // Surface only the standardized OAuth error code, never the raw body
            // — it may carry tokens or internal diagnostics (review L9).
            return Err(SphinxError::Status {
                status,
                oauth_error: oauth_error(&body),
            });
        }
        let v: Value = serde_json::from_str(&body).map_err(|e| SphinxError::Parse(e.to_string()))?;
        Ok(TokenResponse {
            access_token: str_field(&v, "access_token"),
            refresh_token: str_field(&v, "refresh_token"),
            token_type: str_field(&v, "token_type"),
            expires_in: v.get("expires_in").and_then(Value::as_i64).unwrap_or(0),
            scope: str_field(&v, "scope"),
            issued_token_type: str_field(&v, "issued_token_type"),
        })
    }

    fn send_form(&self, url: &str, form: &[(&str, &str)]) -> Result<(u16, String), SphinxError> {
        match self.agent.post(url).send_form(form) {
            Ok(resp) => {
                let status = resp.status();
                let body = resp
                    .into_string()
                    .map_err(|e| SphinxError::Http(e.to_string()))?;
                Ok((status, body))
            }
            // ureq surfaces non-2xx as Error::Status; keep the status + body so
            // the caller can map it (mirrors Java reading statusCode()/body()).
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Ok((code, body))
            }
            Err(ureq::Error::Transport(t)) => Err(SphinxError::Http(t.to_string())),
        }
    }
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

/// Extract only the short, standardized OAuth `error` code (never tokens).
fn oauth_error(body: &str) -> String {
    match serde_json::from_str::<Value>(body) {
        Ok(v) => match v.get("error").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => "unknown_error".to_string(),
        },
        Err(_) => "unparseable_error".to_string(),
    }
}

/// Percent-encode a query/form component (application/x-www-form-urlencoded).
/// Shared with `LoginFlow`'s authorize-URL builder.
pub(crate) fn form_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            other => {
                out.push('%');
                out.push_str(&format!("{other:02X}"));
            }
        }
    }
    out
}
