//! JWT verification using jsonwebtoken crate.

use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::types::{AuthMethod, Identity, IdentityType};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    identity_type: Option<String>,
    #[serde(default)]
    auth_method: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    mfa_verified: Option<bool>,
}

pub struct JwtVerifier {
    jwks_url: String,
}

impl JwtVerifier {
    pub fn new(jwks_url: &str) -> Self {
        Self {
            jwks_url: jwks_url.to_string(),
        }
    }

    /// Verify a JWT token and extract the Identity.
    /// In production, this fetches JWKS keys from the URL.
    /// For now, it provides the structure — full JWKS integration
    /// requires fetching keys at runtime.
    pub fn verify_with_key(&self, token: &str, key: &DecodingKey) -> Option<Identity> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;

        match decode::<Claims>(token, key, &validation) {
            Ok(token_data) => Some(Self::extract_identity(token_data.claims)),
            Err(e) => {
                error!("JWT verification failed: {}", e);
                None
            }
        }
    }

    fn extract_identity(claims: Claims) -> Identity {
        let identity_type = match claims.identity_type.as_deref() {
            Some("agent") => IdentityType::Agent,
            Some("machine") => IdentityType::Machine,
            _ => IdentityType::Human,
        };

        let auth_method = match claims.auth_method.as_deref() {
            Some("sso") => AuthMethod::Sso,
            Some("passkey") => AuthMethod::Passkey,
            Some("client_credentials") => AuthMethod::ClientCredentials,
            Some("api_key") => AuthMethod::ApiKey,
            Some("workload") => AuthMethod::Workload,
            Some("token_exchange") => AuthMethod::TokenExchange,
            _ => AuthMethod::Password,
        };

        Identity {
            id: claims.sub,
            identity_type,
            auth_method,
            email: claims.email,
            name: claims.name,
            mfa_verified: claims.mfa_verified,
        }
    }

    pub fn jwks_url(&self) -> &str {
        &self.jwks_url
    }
}
