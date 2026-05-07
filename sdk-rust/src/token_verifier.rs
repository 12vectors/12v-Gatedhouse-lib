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
        Self {
            jwks_uri: jwks_uri.into(),
            issuer: issuer.into(),
            audience: audience.into(),
        }
    }
}
