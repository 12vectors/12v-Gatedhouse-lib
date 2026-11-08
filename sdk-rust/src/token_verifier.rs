// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Configuration for the optional JWT verification helper.

use std::time::Duration;

/// Settings for `Gatedhouse::verify_token`.
///
/// For a Sphinx deployment, `jwks_uri` is typically
/// `https://<sphinx-host>/api/sphinx/v1/.well-known/jwks.json`,
/// `issuer` matches Sphinx's `JWT_ISSUER`, and `audience` matches its
/// `JWT_AUDIENCE`.
///
/// Fetching the JWKS is bounded by `jwks_timeout` (default
/// [`DEFAULT_JWKS_TIMEOUT`](Self::DEFAULT_JWKS_TIMEOUT)): no network wait
/// while fetching exceeds it. A fetch that fails or times out surfaces as a
/// `TokenVerificationError` with reason `JwksUnavailable`.
#[derive(Debug, Clone)]
pub struct TokenVerifierConfig {
    pub jwks_uri: String,
    pub issuer: String,
    pub audience: String,
    /// The longest any single network wait may take while fetching the JWKS.
    pub jwks_timeout: Duration,
}

impl TokenVerifierConfig {
    pub fn new(
        jwks_uri: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            jwks_uri: jwks_uri.into(),
            issuer: issuer.into(),
            audience: audience.into(),
            jwks_timeout: Self::DEFAULT_JWKS_TIMEOUT,
        }
    }

    /// The JWKS fetch timeout used when none is given: 5 seconds.
    pub const DEFAULT_JWKS_TIMEOUT: Duration = Duration::from_secs(5);

    /// Sets the longest any single network wait may take while fetching the
    /// JWKS.
    ///
    /// # Panics
    ///
    /// If `timeout` is zero.
    pub fn with_jwks_timeout(mut self, timeout: Duration) -> Self {
        assert!(!timeout.is_zero(), "jwks_timeout must be positive");
        self.jwks_timeout = timeout;
        self
    }
}
