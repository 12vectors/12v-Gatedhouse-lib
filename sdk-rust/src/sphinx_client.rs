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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    /// The call was rejected before any request, e.g. a blank email for
    /// [`SphinxClient::create_person`].
    InvalidArgument,
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
    /// Sphinx's machine-readable error code (the `error` field of its JSON
    /// error body, e.g. `"conflict"`) for [`SphinxErrorKind::HttpStatus`];
    /// `None` when the body carried none.
    pub error_code: Option<String>,
    pub message: String,
}

impl SphinxError {
    fn new(kind: SphinxErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            status_code: None,
            error_code: None,
            message: message.into(),
        }
    }

    /// An `HttpStatus` error for an unsuccessful answer, with Sphinx's error code.
    fn refused(op: &str, status: u16, body: &str) -> Self {
        let error_code = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string));
        Self {
            kind: SphinxErrorKind::HttpStatus,
            status_code: Some(status),
            error_code,
            message: format!("{op} failed ({status}): {body}"),
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

/// A person to create with [`SphinxClient::create_person`]. Only `email` is
/// required; an unset optional field is left out of the request, so Sphinx
/// applies its default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPerson {
    /// The person's identifier in Sphinx; must not be blank.
    pub email: String,
    pub display_name: Option<String>,
    /// E.164 (`+35799123456`); spaces and dashes are allowed. Stored unverified.
    pub phone: Option<String>,
    /// Sphinx default `false`; `true` means the app vouches for the address
    /// and the account is active at once.
    pub email_verified: Option<bool>,
    /// Sphinx default `true`; `false` means a federated sign-in with the same
    /// email is never linked without the user's confirmation.
    pub allow_auto_link: Option<bool>,
}

impl NewPerson {
    pub fn new(email: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            display_name: None,
            phone: None,
            email_verified: None,
            allow_auto_link: None,
        }
    }

    pub fn display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    pub fn phone(mut self, phone: impl Into<String>) -> Self {
        self.phone = Some(phone.into());
        self
    }

    pub fn email_verified(mut self, email_verified: bool) -> Self {
        self.email_verified = Some(email_verified);
        self
    }

    pub fn allow_auto_link(mut self, allow_auto_link: bool) -> Self {
        self.allow_auto_link = Some(allow_auto_link);
        self
    }

    /// The JSON request body: snake_case keys, unset fields omitted.
    fn to_json(&self) -> Value {
        let mut json = Map::new();
        json.insert("email".into(), self.email.clone().into());
        if let Some(v) = &self.display_name {
            json.insert("display_name".into(), v.clone().into());
        }
        if let Some(v) = &self.phone {
            json.insert("phone".into(), v.clone().into());
        }
        if let Some(v) = self.email_verified {
            json.insert("email_verified".into(), v.into());
        }
        if let Some(v) = self.allow_auto_link {
            json.insert("allow_auto_link".into(), v.into());
        }
        Value::Object(json)
    }
}

/// A person created by [`SphinxClient::create_person`], as Sphinx reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedPerson {
    /// Sphinx's person id (`per_…`).
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub display_name: Option<String>,
    /// Normalised E.164.
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub allow_auto_link: bool,
    /// E.g. `pending_verification` until the person sets a password, or `active`.
    pub status: String,
    pub created_at: SystemTime,
    /// Whether Sphinx emailed the set-password link; if not, the person can
    /// use "Forgot password".
    pub password_reset_sent: bool,
}

/// A cached app token. Compared by identity (`Arc::ptr_eq`) when dropped.
struct AppToken {
    value: String,
    expires_at: Instant,
}

/// HTTP client wrapper to orchestrate Sphinx SSO OAuth 2.0 endpoints.
/// Create one and reuse it; it is `Send + Sync`.
pub struct SphinxClient {
    base_url: String,
    client_id: String,
    client_secret: String,
    timeout: Duration,
    agent: ureq::Agent,
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
    /// Held while minting, so concurrent callers share one mint.
    mint_lock: Mutex<()>,
    app_token: Mutex<Option<Arc<AppToken>>>,
}

impl SphinxClient {
    /// The timeout used when none is given: 10 seconds.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

    /// The scope of the app token [`create_person`](Self::create_person) uses.
    pub const PROVISIONING_SCOPE: &'static str = "persons:create";

    /// A cached app token is replaced this long before it expires.
    pub const TOKEN_EXPIRY_MARGIN: Duration = Duration::from_secs(60);

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
            clock: Box::new(Instant::now),
            mint_lock: Mutex::new(()),
            app_token: Mutex::new(None),
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

    /// Creates a person in Sphinx on behalf of this app. The app must be
    /// marked "Can provision users" by a Sphinx admin.
    ///
    /// Mints an app token ([`client_credentials`](Self::client_credentials)
    /// with scope [`PROVISIONING_SCOPE`](Self::PROVISIONING_SCOPE)) and caches
    /// it in this client until [`TOKEN_EXPIRY_MARGIN`](Self::TOKEN_EXPIRY_MARGIN)
    /// before it expires, so later calls make one request. Thread-safe;
    /// concurrent callers share one mint. A 401 from Sphinx drops the cached
    /// token (the next call mints a new one); a 403 keeps it. Never retries.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` for a blank email, before any request. `HttpStatus`
    /// when the token request or the creation is refused, with `error_code`
    /// e.g. `unauthorized_client` (app not privileged), `conflict` (email
    /// exists), `forbidden` (domain not accepted, or an admin domain),
    /// `invalid_email`, `invalid_phone`. `Timeout` / `Transport`, or
    /// `InvalidResponse`: after either, the person may exist, and a repeated
    /// call then answers `conflict`.
    pub fn create_person(&self, person: &NewPerson) -> Result<ProvisionedPerson, SphinxError> {
        if person.email.trim().is_empty() {
            return Err(SphinxError::new(
                SphinxErrorKind::InvalidArgument,
                "email is required",
            ));
        }
        let token = self.app_token()?;
        let url = format!("{}/api/sphinx/v1/persons", self.base_url);
        let request = self
            .agent
            .post(&url)
            .set("Authorization", &format!("Bearer {}", token.value))
            .set("Content-Type", "application/json")
            .set("Accept", "application/json");
        let (status, body) =
            self.read(request.send_string(&person.to_json().to_string()), "Person creation")?;
        if status == 401 {
            self.drop_app_token(&token);
        }
        if status != 201 {
            return Err(SphinxError::refused("Person creation", status, &body));
        }
        parse_provisioned_person(&parse_object(&body, "Person creation")?)
    }

    /// The cached app token, or a new one. At most one mint at a time.
    fn app_token(&self) -> Result<Arc<AppToken>, SphinxError> {
        if let Some(token) = self.fresh_app_token() {
            return Ok(token);
        }
        let _minting = self.mint_lock.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(token) = self.fresh_app_token() {
            return Ok(token); // another thread minted it while we waited
        }
        let now = (self.clock)();
        let minted = self.client_credentials(Some(Self::PROVISIONING_SCOPE))?;
        let value = minted.access_token.filter(|t| !t.is_empty()).ok_or_else(|| {
            SphinxError::new(
                SphinxErrorKind::InvalidResponse,
                "Token request returned no access_token",
            )
        })?;
        let usable = minted.expires_in - Self::TOKEN_EXPIRY_MARGIN.as_secs() as i64;
        let token = Arc::new(AppToken {
            value,
            expires_at: now + Duration::from_secs(usable.max(0) as u64),
        });
        // A token too short-lived to outlast the margin is used once, not cached.
        *self.app_token.lock().unwrap_or_else(|p| p.into_inner()) =
            (usable > 0).then(|| token.clone());
        Ok(token)
    }

    fn fresh_app_token(&self) -> Option<Arc<AppToken>> {
        let cached = self.app_token.lock().unwrap_or_else(|p| p.into_inner());
        cached
            .as_ref()
            .filter(|t| (self.clock)() < t.expires_at)
            .cloned()
    }

    /// Forgets `rejected` unless another thread has replaced it already.
    fn drop_app_token(&self, rejected: &Arc<AppToken>) {
        let mut cached = self.app_token.lock().unwrap_or_else(|p| p.into_inner());
        if cached.as_ref().is_some_and(|t| Arc::ptr_eq(t, rejected)) {
            *cached = None;
        }
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
            return Err(SphinxError::refused("Token request", status, &body));
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

    /// POSTs a form; see [`read`](Self::read).
    fn post_form(
        &self,
        path: &str,
        form: &[(&str, &str)],
        op: &str,
    ) -> Result<(u16, String), SphinxError> {
        let url = format!("{}{}", self.base_url, path);
        self.read(self.agent.post(&url).send_form(form), op)
    }

    /// Returns `(status, body)` for any HTTP answer, and a [`SphinxError`]
    /// when there is none.
    fn read(
        &self,
        sent: Result<ureq::Response, ureq::Error>,
        op: &str,
    ) -> Result<(u16, String), SphinxError> {
        let response = match sent {
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

fn parse_provisioned_person(json: &Map<String, Value>) -> Result<ProvisionedPerson, SphinxError> {
    let invalid = |what: &str| {
        SphinxError::new(
            SphinxErrorKind::InvalidResponse,
            format!("Person creation returned {what}"),
        )
    };
    let (Some(Value::Object(data)), Some(Value::Object(meta))) = (json.get("data"), json.get("meta"))
    else {
        return Err(invalid("no data or meta object"));
    };
    let string = |name: &str| match data.get(name) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(invalid(&format!("no string {name}"))),
    };
    let nullable = |name: &str| match data.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        _ => Err(invalid(&format!("a non-string {name}"))),
    };
    let boolean = |map: &Map<String, Value>, name: &str| match map.get(name) {
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(invalid(&format!("no boolean {name}"))),
    };
    Ok(ProvisionedPerson {
        id: string("id")?,
        email: string("email")?,
        email_verified: boolean(data, "email_verified")?,
        display_name: nullable("display_name")?,
        phone: nullable("phone")?,
        phone_verified: boolean(data, "phone_verified")?,
        allow_auto_link: boolean(data, "allow_auto_link")?,
        status: string("status")?,
        created_at: parse_rfc3339(&string("created_at")?)
            .ok_or_else(|| invalid("an invalid created_at"))?,
        password_reset_sent: boolean(meta, "password_reset_sent")?,
    })
}

/// Parses an RFC 3339 instant as Java's `Instant.parse` accepts it: 0-9
/// fractional digits, then `Z` or `±HH:MM`. `None` if it is not one.
fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    fn digits(s: &str, from: usize, to: usize) -> Option<i64> {
        let part = s.get(from..to)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    }
    let b = text.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (digits(text, 0, 4)?, digits(text, 5, 7)?, digits(text, 8, 10)?);
    let (hour, minute, second) = (digits(text, 11, 13)?, digits(text, 14, 16)?, digits(text, 17, 19)?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&month)
        || !(1..=month_days[month as usize - 1]).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let mut rest = &text[19..];
    let mut nanos = 0u32;
    if let Some(fraction) = rest.strip_prefix('.') {
        let n = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 || n > 9 {
            return None;
        }
        nanos = format!("{:0<9}", &fraction[..n]).parse().ok()?;
        rest = &fraction[n..];
    }
    let offset = match rest.as_bytes() {
        [b'Z'] => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let (h, m) = (digits(rest, 1, 3)?, digits(rest, 4, 6)?);
            if h > 18 || m > 59 {
                return None;
            }
            (h * 3600 + m * 60) * if *sign == b'-' { -1 } else { 1 }
        }
        _ => return None,
    };
    // Days since 1970-01-01 (H. Hinnant's days_from_civil).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset;
    let whole = if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))?
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))?
    };
    whole.checked_add(Duration::from_nanos(u64::from(nanos)))
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

#[cfg(test)]
mod tests {
    //! `create_person` against a stub Sphinx (wire contract APP-PROV-1).
    //! Mirrors the Java `SphinxProvisioningTest`.

    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    const TOKEN_PATH: &str = "/api/sphinx/v1/oauth/token";
    const PERSONS_PATH: &str = "/api/sphinx/v1/persons";
    const CREATED: &str = r#"{"data":{"id":"per_01J","email":"jane@cicero-client.com","email_verified":false,"display_name":"Jane Doe","phone":"+35799123456","phone_verified":false,"allow_auto_link":true,"status":"pending_verification","failed_login_attempts":0,"last_login_at":null,"last_login_method":null,"created_at":"2026-11-12T10:00:00Z"},"meta":{"password_reset_sent":true}}"#;

    #[derive(Clone, Debug)]
    struct Request {
        path: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl Request {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    struct Config {
        token_status: u16,
        token_body: Option<String>, // None: a fresh token each time
        expires_in: i64,
        token_delay: Duration,
        persons_status: u16,
        persons_body: String,
    }

    struct Stub {
        url: String,
        requests: Arc<Mutex<Vec<Request>>>,
        config: Arc<Mutex<Config>>,
    }

    impl Stub {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let config = Arc::new(Mutex::new(Config {
                token_status: 200,
                token_body: None,
                expires_in: 3600,
                token_delay: Duration::ZERO,
                persons_status: 201,
                persons_body: CREATED.to_string(),
            }));
            let tokens = Arc::new(AtomicU64::new(0));
            let (reqs, cfg) = (requests.clone(), config.clone());
            thread::spawn(move || {
                for conn in listener.incoming().flatten() {
                    let (reqs, cfg, tokens) = (reqs.clone(), cfg.clone(), tokens.clone());
                    thread::spawn(move || {
                        let mut reader = BufReader::new(conn.try_clone().unwrap());
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                        let mut headers = Vec::new();
                        loop {
                            let mut h = String::new();
                            reader.read_line(&mut h).unwrap();
                            let h = h.trim_end();
                            if h.is_empty() {
                                break;
                            }
                            let (k, v) = h.split_once(':').unwrap();
                            headers.push((k.trim().to_string(), v.trim().to_string()));
                        }
                        let len = headers
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                            .map_or(0, |(_, v)| v.parse().unwrap());
                        let mut body = vec![0; len];
                        reader.read_exact(&mut body).unwrap();
                        reqs.lock().unwrap().push(Request {
                            path: path.clone(),
                            headers,
                            body: String::from_utf8(body).unwrap(),
                        });
                        let (status, answer) = if path == TOKEN_PATH {
                            let (delay, status, body, expires_in) = {
                                let c = cfg.lock().unwrap();
                                (c.token_delay, c.token_status, c.token_body.clone(), c.expires_in)
                            };
                            thread::sleep(delay);
                            let n = tokens.fetch_add(1, Ordering::SeqCst) + 1;
                            (status, body.unwrap_or_else(|| format!(
                                r#"{{"access_token":"tok-{n}","token_type":"Bearer","expires_in":{expires_in},"scope":"persons:create"}}"#
                            )))
                        } else {
                            let c = cfg.lock().unwrap();
                            (c.persons_status, c.persons_body.clone())
                        };
                        let mut conn = conn;
                        let _ = write!(
                            conn,
                            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                            answer.len()
                        );
                    });
                }
            });
            Stub { url, requests, config }
        }

        fn to(&self, path: &str) -> Vec<Request> {
            self.requests.lock().unwrap().iter().filter(|r| r.path == path).cloned().collect()
        }

        fn set(&self, edit: impl FnOnce(&mut Config)) {
            edit(&mut self.config.lock().unwrap());
        }
    }

    /// A client whose clock is `start + offset`; returns the offset to advance it.
    fn client(stub: &Stub) -> (SphinxClient, Arc<Mutex<Duration>>) {
        let offset = Arc::new(Mutex::new(Duration::ZERO));
        let start = Instant::now();
        let mut client = SphinxClient::new(&stub.url, "sph_app", "sps_secret")
            .with_timeout(Duration::from_secs(2));
        let o = offset.clone();
        client.clock = Box::new(move || start + *o.lock().unwrap());
        (client, offset)
    }

    fn jane() -> NewPerson {
        NewPerson::new("jane@cicero-client.com")
    }

    fn json(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    // ---- happy path ---------------------------------------------------------

    #[test]
    fn mints_an_app_token_then_posts_the_person_as_json() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        let p = client
            .create_person(
                &jane()
                    .display_name("Jane Doe")
                    .phone("+357 99 123456")
                    .email_verified(false)
                    .allow_auto_link(true),
            )
            .unwrap();
        assert_eq!(
            "grant_type=client_credentials&client_id=sph_app&client_secret=sps_secret&scope=persons%3Acreate",
            stub.to(TOKEN_PATH)[0].body
        );
        let post = &stub.to(PERSONS_PATH)[0];
        assert_eq!(Some("Bearer tok-1"), post.header("Authorization"));
        assert_eq!(Some("application/json"), post.header("Content-Type"));
        assert_eq!(Some("application/json"), post.header("Accept"));
        assert_eq!(
            json(r#"{"email":"jane@cicero-client.com","display_name":"Jane Doe","phone":"+357 99 123456","email_verified":false,"allow_auto_link":true}"#),
            json(&post.body)
        );
        assert_eq!(
            ProvisionedPerson {
                id: "per_01J".into(),
                email: "jane@cicero-client.com".into(),
                email_verified: false,
                display_name: Some("Jane Doe".into()),
                phone: Some("+35799123456".into()),
                phone_verified: false,
                allow_auto_link: true,
                status: "pending_verification".into(),
                created_at: UNIX_EPOCH + Duration::from_secs(1_794_477_600),
                password_reset_sent: true,
            },
            p
        );
    }

    #[test]
    fn unset_optional_fields_are_omitted_not_null() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        client.create_person(&jane()).unwrap();
        assert_eq!(json(r#"{"email":"jane@cicero-client.com"}"#), json(&stub.to(PERSONS_PATH)[0].body));
    }

    #[test]
    fn null_display_name_and_phone_are_none() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        stub.set(|c| {
            c.persons_body = CREATED.replace(r#""Jane Doe""#, "null").replace(r#""+35799123456""#, "null")
        });
        let p = client.create_person(&jane()).unwrap();
        assert_eq!((None, None), (p.display_name, p.phone));
    }

    #[test]
    fn rfc3339_parsing_matches_java_instant_parse() {
        let at = |s: i64| {
            if s >= 0 {
                UNIX_EPOCH + Duration::from_secs(s as u64)
            } else {
                UNIX_EPOCH - Duration::from_secs(s.unsigned_abs())
            }
        };
        for (text, secs) in [
            ("2026-11-12T10:00:00Z", 1_794_477_600),
            ("1970-01-01T00:00:00Z", 0),
            ("2000-02-29T23:59:59Z", 951_868_799),
            ("1969-12-31T23:59:59Z", -1),
            ("2026-11-12T12:00:00+02:00", 1_794_477_600),
            ("2026-11-12T05:30:00-04:30", 1_794_477_600),
        ] {
            assert_eq!(Some(at(secs)), parse_rfc3339(text), "{text}");
        }
        assert_eq!(
            Some(at(1_794_477_600) + Duration::from_nanos(123_456_789)),
            parse_rfc3339("2026-11-12T10:00:00.123456789Z")
        );
        assert_eq!(
            Some(at(1_794_477_600) + Duration::from_millis(100)),
            parse_rfc3339("2026-11-12T10:00:00.1Z")
        );
        for bad in [
            "", "yesterday", "2026-11-12", "2026-11-12T10:00:00", "2026-11-12 10:00:00Z",
            "2026-13-01T00:00:00Z", "2026-02-29T00:00:00Z", "2026-11-31T00:00:00Z",
            "2026-11-12T24:00:00Z", "2026-11-12T10:60:00Z", "2026-11-12T10:00:60Z",
            "2026-11-12T10:00:00.Z", "2026-11-12T10:00:00.1234567890Z", "2026-11-12T10:00:00+0200",
            "2026-11-12T10:00:00+19:00", "+026-11-12T10:00:00Z", "2026-11-12T10:00:00Zjunk",
            "２０２６-11-12T10:00:00Z",
        ] {
            assert_eq!(None, parse_rfc3339(bad), "{bad}");
        }
    }

    // ---- token caching ------------------------------------------------------

    #[test]
    fn second_call_reuses_the_token_so_makes_one_request() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        client.create_person(&jane()).unwrap();
        client.create_person(&jane()).unwrap();
        assert_eq!(1, stub.to(TOKEN_PATH).len());
        assert_eq!(2, stub.to(PERSONS_PATH).len());
    }

    #[test]
    fn token_is_replaced_sixty_seconds_before_it_expires() {
        let stub = Stub::start();
        let (client, offset) = client(&stub);
        client.create_person(&jane()).unwrap();
        *offset.lock().unwrap() = Duration::from_secs(3600 - 60) - Duration::from_nanos(1);
        client.create_person(&jane()).unwrap();
        assert_eq!(1, stub.to(TOKEN_PATH).len(), "still inside the usable window");
        *offset.lock().unwrap() = Duration::from_secs(3600 - 60);
        client.create_person(&jane()).unwrap();
        assert_eq!(2, stub.to(TOKEN_PATH).len());
        assert_eq!(Some("Bearer tok-2"), stub.to(PERSONS_PATH)[2].header("Authorization"));
    }

    #[test]
    fn a_token_too_short_lived_for_the_margin_is_used_once() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        stub.set(|c| c.expires_in = 60);
        client.create_person(&jane()).unwrap();
        client.create_person(&jane()).unwrap();
        assert_eq!(2, stub.to(TOKEN_PATH).len());
    }

    #[test]
    fn concurrent_callers_share_one_mint() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        stub.set(|c| c.token_delay = Duration::from_millis(300));
        let client = Arc::new(client);
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (client, barrier) = (client.clone(), barrier.clone());
                thread::spawn(move || {
                    barrier.wait();
                    client.create_person(&jane()).unwrap()
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(1, stub.to(TOKEN_PATH).len());
        assert_eq!(8, stub.to(PERSONS_PATH).len());
    }

    // ---- edge cases (spec table) ----------------------------------------------

    fn refusal(client: &SphinxClient) -> SphinxError {
        client.create_person(&jane()).expect_err("should be refused")
    }

    #[test]
    fn app_not_privileged_is_unauthorized_client_and_nothing_is_posted() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        stub.set(|c| {
            c.token_status = 400;
            c.token_body = Some(r#"{"error":"unauthorized_client","detail":"not privileged"}"#.into());
        });
        let e = refusal(&client);
        assert_eq!(
            (SphinxErrorKind::HttpStatus, Some(400), Some("unauthorized_client")),
            (e.kind, e.status_code, e.error_code.as_deref())
        );
        assert!(stub.to(PERSONS_PATH).is_empty());
    }

    #[test]
    fn wrong_secret_or_revoked_app_is_invalid_client() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        stub.set(|c| {
            c.token_status = 401;
            c.token_body = Some(r#"{"error":"invalid_client","detail":"Invalid client credentials"}"#.into());
        });
        let e = refusal(&client);
        assert_eq!((Some(401), Some("invalid_client")), (e.status_code, e.error_code.as_deref()));
    }

    #[test]
    fn forbidden_keeps_the_cached_token() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        client.create_person(&jane()).unwrap();
        stub.set(|c| {
            c.persons_status = 403;
            c.persons_body = r#"{"error":"forbidden","detail":"domain not accepted"}"#.into();
        });
        let e = refusal(&client);
        assert_eq!((Some(403), Some("forbidden")), (e.status_code, e.error_code.as_deref()));
        stub.set(|c| {
            c.persons_status = 201;
            c.persons_body = CREATED.into();
        });
        client.create_person(&jane()).unwrap();
        assert_eq!(1, stub.to(TOKEN_PATH).len(), "403 must not drop a valid token");
    }

    #[test]
    fn unauthorized_drops_the_cached_token_without_retrying() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        client.create_person(&jane()).unwrap();
        stub.set(|c| {
            c.persons_status = 401;
            c.persons_body = r#"{"error":"unauthorized","detail":"Invalid or expired token"}"#.into();
        });
        assert_eq!(Some(401), refusal(&client).status_code);
        assert_eq!(2, stub.to(PERSONS_PATH).len(), "no automatic retry");
        assert_eq!(1, stub.to(TOKEN_PATH).len(), "no automatic re-mint");
        stub.set(|c| {
            c.persons_status = 201;
            c.persons_body = CREATED.into();
        });
        client.create_person(&jane()).unwrap();
        assert_eq!(2, stub.to(TOKEN_PATH).len(), "the next call mints a fresh token");
        assert_eq!(Some("Bearer tok-2"), stub.to(PERSONS_PATH)[2].header("Authorization"));
    }

    #[test]
    fn existing_email_is_conflict_and_bad_input_keeps_its_code() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        for (status, code) in [
            (409, "conflict"),
            (400, "invalid_email"),
            (400, "invalid_phone"),
            (400, "bad_request"),
        ] {
            stub.set(|c| {
                c.persons_status = status;
                c.persons_body = format!(r#"{{"error":"{code}","detail":"x"}}"#);
            });
            let e = refusal(&client);
            assert_eq!((Some(status), Some(code)), (e.status_code, e.error_code.as_deref()));
        }
    }

    #[test]
    fn blank_email_is_rejected_before_any_request() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        for email in ["", "   "] {
            let e = client.create_person(&NewPerson::new(email)).unwrap_err();
            assert_eq!(SphinxErrorKind::InvalidArgument, e.kind);
        }
        assert!(stub.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn non_json_error_body_has_no_error_code() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        stub.set(|c| {
            c.persons_status = 502;
            c.persons_body = "<html>Bad Gateway</html>".into();
        });
        let e = refusal(&client);
        assert_eq!((Some(502), None), (e.status_code, e.error_code));
    }

    #[test]
    fn malformed_success_body_is_invalid_response() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        for body in [
            "not json".to_string(),
            "{}".into(),
            r#"{"data":{},"meta":{}}"#.into(),
            CREATED.replace("2026-11-12T10:00:00Z", "yesterday"),
            CREATED.replace(r#""email_verified":false"#, r#""email_verified":"no""#),
            CREATED.replace(r#","meta":{"password_reset_sent":true}"#, ""),
        ] {
            stub.set(|c| c.persons_body = body.clone());
            assert_eq!(SphinxErrorKind::InvalidResponse, refusal(&client).kind, "{body}");
        }
    }

    #[test]
    fn token_response_without_access_token_is_invalid_response() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        stub.set(|c| c.token_body = Some(r#"{"token_type":"Bearer","expires_in":3600}"#.into()));
        assert_eq!(SphinxErrorKind::InvalidResponse, refusal(&client).kind);
        assert!(stub.to(PERSONS_PATH).is_empty());
    }

    #[test]
    fn unresponsive_sphinx_times_out_and_unreachable_is_transport() {
        let black_hole = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", black_hole.local_addr().unwrap());
        thread::spawn(move || {
            let mut held = Vec::new();
            for conn in black_hole.incoming().flatten() {
                held.push(conn); // keep it open, say nothing
            }
        });
        let client = SphinxClient::new(url, "sph_app", "sps_secret")
            .with_timeout(Duration::from_millis(300));
        assert_eq!(SphinxErrorKind::Timeout, client.create_person(&jane()).unwrap_err().kind);

        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let client = SphinxClient::new(format!("http://127.0.0.1:{port}"), "sph_app", "sps_secret")
            .with_timeout(Duration::from_millis(500));
        assert_eq!(SphinxErrorKind::Transport, client.create_person(&jane()).unwrap_err().kind);
    }

    #[test]
    fn existing_token_calls_now_carry_the_error_code_too() {
        let stub = Stub::start();
        let (client, _) = client(&stub);
        stub.set(|c| {
            c.token_status = 400;
            c.token_body = Some(r#"{"error":"invalid_grant","detail":"code already used"}"#.into());
        });
        let e = client.exchange_code("code", "http://cb").unwrap_err();
        assert_eq!(Some("invalid_grant"), e.error_code.as_deref());
        assert!(!e.message.contains("sps_secret"), "the secret is never in a message");
    }

    #[test]
    fn client_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SphinxClient>();
    }
}
