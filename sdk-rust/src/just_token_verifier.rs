//! Database-free `Gatedhouse` implementation that only verifies tokens.
//!
//! Mirrors the Java package-private `JustTokenVerifierGatedhouse`;
//! construct via [`GatedhouseFactory::create_just_token_verifier`].
//!
//! Every database-backed method panics, mirroring Java's unchecked
//! `UnsupportedOperationException`.
//!
//! [`GatedhouseFactory::create_just_token_verifier`]:
//! crate::factory::GatedhouseFactory::create_just_token_verifier

use crate::error::{GatedhouseError, TokenVerificationError};
use crate::gatedhouse::Gatedhouse;
use crate::group_manager::GroupManager;
use crate::jwt_verification::JwtVerification;
use crate::membership_manager::MembershipManager;
use crate::permission_catalog::PermissionCatalog;
use crate::role_manager::RoleManager;
use crate::token_verifier::TokenVerifierConfig;
use crate::types::{AuthenticatedSubject, EffectivePermission};

const UNSUPPORTED: &str = "Database operations not supported on token-verifier-only instance";

pub(crate) struct JustTokenVerifierGatedhouse {
    jwt: JwtVerification,
}

impl JustTokenVerifierGatedhouse {
    pub(crate) fn new(config: &TokenVerifierConfig) -> Self {
        Self {
            jwt: JwtVerification::new(config),
        }
    }
}

impl Gatedhouse for JustTokenVerifierGatedhouse {
    fn permission_catalog(&self) -> &dyn PermissionCatalog {
        panic!("{UNSUPPORTED}")
    }

    fn role_manager(&self) -> &dyn RoleManager {
        panic!("{UNSUPPORTED}")
    }

    fn membership_manager(&self) -> &dyn MembershipManager {
        panic!("{UNSUPPORTED}")
    }

    fn group_manager(&self) -> &dyn GroupManager {
        panic!("{UNSUPPORTED}")
    }

    fn has_permission(
        &self,
        _identity_id: &str,
        _org_id: &str,
        _service: &str,
        _resource: &str,
        _action: &str,
    ) -> Result<bool, GatedhouseError> {
        panic!("{UNSUPPORTED}")
    }

    fn get_effective_permissions(
        &self,
        _identity_id: &str,
        _org_id: &str,
    ) -> Result<Vec<EffectivePermission>, GatedhouseError> {
        panic!("{UNSUPPORTED}")
    }

    fn get_roles(&self, _identity_id: &str, _org_id: &str) -> Result<Vec<String>, GatedhouseError> {
        panic!("{UNSUPPORTED}")
    }

    fn get_groups(
        &self,
        _identity_id: &str,
        _org_id: &str,
    ) -> Result<Vec<String>, GatedhouseError> {
        panic!("{UNSUPPORTED}")
    }

    fn verify_token(
        &self,
        jwt_token: &str,
    ) -> Result<AuthenticatedSubject, TokenVerificationError> {
        self.jwt.verify(jwt_token)
    }

    // Cache control is a no-op: there is no cache.

    fn invalidate_cache(&self, _identity_id: &str, _org_id: &str) {}

    fn invalidate_all_cache(&self) {}

    fn set_cache_bypass(&self, _bypass: bool) {}

    fn is_cache_bypassed(&self) -> bool {
        false
    }
}
