//! Gatedhouse — embedded authorization library, Rust SDK.
//!
//! Mirrors the Java reference implementation. Top-level entry point is
//! [`GatedhouseFactory::create`]; everything else hangs off the
//! [`Gatedhouse`] trait.

pub mod config;
pub mod database;
pub mod enums;
pub mod error;
pub mod factory;
pub mod gatedhouse;
pub mod group_manager;
pub mod group_source;
pub mod login_flow;
pub mod membership_manager;
pub mod permission_cache;
pub mod permission_catalog;
pub mod role_manager;
pub mod sphinx_client;
pub mod token_verifier;
pub mod types;

mod jwt_verification;
mod migrator;
mod schema_check;
mod secure_urls;

// Re-exports — what hosts typically import.
pub use config::{GatedhouseConfig, GatedhouseConfigBuilder};
pub use database::{ConninfoDatabase, Database};
pub use enums::{EntityType, MembershipStatus};
pub use error::{
    GatedhouseError, LoginCsrfError, LoginError, SphinxError, TokenVerificationError,
    TokenVerificationReason,
};
pub use factory::GatedhouseFactory;
pub use gatedhouse::Gatedhouse;
pub use group_manager::GroupManager;
pub use group_source::{GroupSource, LocalGroupSource};
pub use login_flow::LoginFlow;
pub use membership_manager::MembershipManager;
pub use permission_cache::{InMemoryPermissionCache, PermissionCache};
pub use permission_catalog::PermissionCatalog;
pub use role_manager::RoleManager;
pub use sphinx_client::{SphinxClient, TokenResponse};
pub use token_verifier::TokenVerifierConfig;
pub use types::{AuthenticatedSubject, EffectivePermission, PermissionCacheKey};
