//! HTTP client wrapper to orchestrate Sphinx SSO OAuth 2.0 endpoints.
//!
//! Uses `ureq` (already a dependency for JWKS fetching), mirroring the
//! Java `SphinxClient` which uses `java.net.http.HttpClient`.

use std::fmt;

use serde_json::{Map, Value};

/// Failure talking to a Sphinx OAuth endpoint (transport error or
/// non-200 token response).
#[derive(Debug)]
pub struct SphinxError {
    pub message: String,
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
pub struct SphinxClient {
    base_url: String,
    client_id: String,
    client_secret: String,
}

impl SphinxClient {
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
        }
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
        let url = format!("{}/api/sphinx/v1/oauth/introspect", self.base_url);
        // The introspection endpoint conveys inactive/invalid tokens in
        // the body; parse it regardless of status.
        let response = match ureq::post(&url).send_form(&[("token", token)]) {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => {
                return Err(SphinxError {
                    message: format!("Introspection failed: {e}"),
                })
            }
        };
        let json: Value = response.into_json().map_err(|e| SphinxError {
            message: format!("Introspection failed: {e}"),
        })?;
        json.as_object().cloned().ok_or_else(|| SphinxError {
            message: "Introspection failed: response is not a JSON object".to_string(),
        })
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
        let url = format!("{}/api/sphinx/v1/oauth/token", self.base_url);
        let response = match ureq::post(&url).send_form(form) {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                return Err(SphinxError {
                    message: format!("Token request failed ({code}): {body}"),
                });
            }
            Err(e) => {
                return Err(SphinxError {
                    message: format!("Token request failed: {e}"),
                })
            }
        };
        let json: Value = response.into_json().map_err(|e| SphinxError {
            message: format!("Token request failed: {e}"),
        })?;
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
