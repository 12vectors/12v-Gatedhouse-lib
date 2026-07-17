// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Framework-agnostic web security guards mirroring the Java servlet
//! filters (`GatedhouseApiFilter`, `GatedhouseWebFilter`).
//!
//! Rust has no servlet-like standard interface, so these expose the same
//! decision logic as plain calls: feed in the request's `Authorization`
//! header (API) or session token (web) and get back either a verified
//! [`GatedContext`] or the exact response the Java filters would write
//! (401 JSON body / login redirect). Wire them into axum/actix/hyper
//! middleware in a few lines, adding [`SECURITY_HEADERS`] to every
//! response as the Java filters do.

use std::fmt;
use std::sync::Arc;

use crate::gated_context::GatedContext;
use crate::gatedhouse::Gatedhouse;

/// Headers the Java filters set on every response.
pub const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
];

/// Default login redirect path for [`GatedhouseWebFilter`].
pub const DEFAULT_LOGIN_PATH: &str = "/auth/login";
/// Default session attribute the web filter reads the token from.
pub const DEFAULT_SESSION_TOKEN_ATTR: &str = "access_token";

/// Authorization failure, carrying what the Java filters would have
/// written to the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterError {
    /// Maps to HTTP 401 (Java: 401 JSON body / `UnauthorizedException`).
    Unauthorized(String),
    /// Maps to HTTP 403 (Java: `ForbiddenException`).
    Forbidden(String),
}

impl FilterError {
    pub fn status(&self) -> u16 {
        match self {
            FilterError::Unauthorized(_) => 401,
            FilterError::Forbidden(_) => 403,
        }
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            FilterError::Unauthorized(_) => "unauthorized",
            FilterError::Forbidden(_) => "forbidden",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            FilterError::Unauthorized(d) | FilterError::Forbidden(d) => d,
        }
    }

    /// The `{"error":...,"detail":...}` body the Java API filter writes.
    pub fn to_json_body(&self) -> String {
        serde_json::json!({
            "error": self.error_code(),
            "detail": self.detail(),
        })
        .to_string()
    }
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}): {}",
            self.error_code(),
            self.status(),
            self.detail()
        )
    }
}

impl std::error::Error for FilterError {}

/// API security guard enforcing `Authorization: Bearer` token
/// validation. On failure, the returned [`FilterError`] carries a clean
/// 401 JSON response.
pub struct GatedhouseApiFilter {
    gatedhouse: Arc<dyn Gatedhouse>,
}

impl GatedhouseApiFilter {
    pub fn new(gatedhouse: Arc<dyn Gatedhouse>) -> Self {
        Self { gatedhouse }
    }

    /// Validate the raw `Authorization` header value and return the
    /// verified context to attach to the request.
    pub fn authenticate(
        &self,
        authorization_header: Option<&str>,
    ) -> Result<GatedContext, FilterError> {
        let token = authorization_header
            .and_then(|h| h.strip_prefix("Bearer "))
            .ok_or_else(|| {
                FilterError::Unauthorized("Missing or invalid Bearer token".to_string())
            })?;
        match self.gatedhouse.verify_token(token.trim()) {
            Ok(subject) => Ok(GatedContext::from_subject(&subject)),
            Err(e) => Err(FilterError::Unauthorized(format!(
                "Token verification failed: {}",
                e.message
            ))),
        }
    }

    /// Asserts that the authenticated context has admin privileges.
    pub fn require_admin(ctx: &GatedContext) -> Result<(), FilterError> {
        if ctx.is_admin() {
            Ok(())
        } else {
            Err(FilterError::Forbidden("Admin access required".to_string()))
        }
    }

    /// Asserts that the authenticated identity is a human user.
    pub fn require_human(ctx: &GatedContext) -> Result<(), FilterError> {
        if ctx.is_human() {
            Ok(())
        } else {
            Err(FilterError::Forbidden(
                "Human identity required".to_string(),
            ))
        }
    }

    /// Asserts that the authenticated context carries a specific scope.
    pub fn require_scope(ctx: &GatedContext, scope: &str) -> Result<(), FilterError> {
        if ctx.has_scope(scope) {
            Ok(())
        } else {
            Err(FilterError::Forbidden(format!("Scope '{scope}' required")))
        }
    }
}

/// Result of a [`GatedhouseWebFilter`] check.
#[derive(Debug)]
pub enum WebFilterOutcome {
    /// Token verified — attach the context to the request and continue.
    /// Boxed to keep the enum small next to the redirect variant.
    Authenticated(Box<GatedContext>),
    /// Send an HTTP 302 to `location`. When `clear_session_token` is
    /// true the token was present but invalid or expired — remove it
    /// from the session before redirecting.
    RedirectToLogin {
        location: String,
        clear_session_token: bool,
    },
}

/// Web security guard for browser-facing pages using session-based
/// token verification. On failure, yields a redirect to a configurable
/// login path (absolute or relative).
pub struct GatedhouseWebFilter {
    gatedhouse: Arc<dyn Gatedhouse>,
    login_path: String,
    session_token_attr: String,
}

impl GatedhouseWebFilter {
    /// Construct with the default login path and session attribute.
    pub fn new(gatedhouse: Arc<dyn Gatedhouse>) -> Self {
        Self::with_config(gatedhouse, DEFAULT_LOGIN_PATH, DEFAULT_SESSION_TOKEN_ATTR)
    }

    pub fn with_config(
        gatedhouse: Arc<dyn Gatedhouse>,
        login_path: impl Into<String>,
        session_token_attr: impl Into<String>,
    ) -> Self {
        Self {
            gatedhouse,
            login_path: login_path.into(),
            session_token_attr: session_token_attr.into(),
        }
    }

    /// Session attribute the host should read the token from before
    /// calling [`check`](Self::check) (and remove when the outcome asks
    /// for it).
    pub fn session_token_attr(&self) -> &str {
        &self.session_token_attr
    }

    /// Decide what to do with a request. `session_token` is the value of
    /// the configured session attribute (if any); `context_path` is the
    /// application mount prefix prepended to relative login paths (the
    /// servlet context-path analog — pass `""` when mounted at root).
    pub fn check(&self, session_token: Option<&str>, context_path: &str) -> WebFilterOutcome {
        let token = session_token.map(str::trim).filter(|t| !t.is_empty());
        let Some(token) = token else {
            return self.login_redirect(context_path, false);
        };
        match self.gatedhouse.verify_token(token) {
            Ok(subject) => {
                WebFilterOutcome::Authenticated(Box::new(GatedContext::from_subject(&subject)))
            }
            // Token is invalid or expired — have the host remove it from
            // the session and redirect.
            Err(_) => self.login_redirect(context_path, true),
        }
    }

    fn login_redirect(&self, context_path: &str, clear_session_token: bool) -> WebFilterOutcome {
        let location = if self.login_path.starts_with("http://")
            || self.login_path.starts_with("https://")
            || self.login_path.starts_with("//")
        {
            self.login_path.clone()
        } else {
            format!("{context_path}{}", self.login_path)
        };
        WebFilterOutcome::RedirectToLogin {
            location,
            clear_session_token,
        }
    }
}
