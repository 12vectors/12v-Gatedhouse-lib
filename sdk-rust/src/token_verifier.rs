//! Configuration for the optional JWT verification helper.

/// Settings for `Gatedhouse::verify_token`.
///
/// For a Sphinx deployment, `jwks_uri` is typically
/// `https://<sphinx-host>/api/sphinx/v1/.well-known/jwks.json`,
/// `issuer` matches Sphinx's `JWT_ISSUER`, and `audience` matches its
/// `JWT_AUDIENCE`.
#[derive(Debug, Clone)]
pub struct TokenVerifierConfig {
    pub jwks_uri: String,
    pub issuer: String,
    pub audience: String,
}

impl TokenVerifierConfig {
    pub fn new(
        jwks_uri: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        let jwks_uri = jwks_uri.into();
        // All signature trust roots in the keys fetched from jwks_uri — refuse a
        // non-TLS endpoint (loopback exempt for dev/test). (review M4)
        crate::secure_urls::require_https_or_loopback(&jwks_uri, "jwks_uri");
        Self {
            jwks_uri,
            issuer: issuer.into(),
            audience: audience.into(),
        }
    }
}
