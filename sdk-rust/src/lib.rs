// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

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
pub mod filters;
pub mod gated_context;
pub mod gatedhouse;
pub mod group_manager;
pub mod group_source;
pub mod membership_manager;
pub mod permission_cache;
pub mod permission_catalog;
pub mod role_manager;
pub mod sphinx_client;
pub mod token_verifier;
pub mod types;

mod just_token_verifier;
mod jwt_verification;
mod migrator;
mod schema_check;

// Re-exports — what hosts typically import.
pub use config::{GatedhouseConfig, GatedhouseConfigBuilder};
pub use database::{ConninfoDatabase, Database};
pub use enums::{EntityType, MembershipStatus};
pub use error::{GatedhouseError, TokenVerificationError, TokenVerificationReason};
pub use factory::GatedhouseFactory;
pub use filters::{
    FilterError, GatedhouseApiFilter, GatedhouseWebFilter, WebFilterOutcome, DEFAULT_LOGIN_PATH,
    DEFAULT_SESSION_TOKEN_ATTR, SECURITY_HEADERS,
};
pub use gated_context::GatedContext;
pub use gatedhouse::Gatedhouse;
pub use group_manager::GroupManager;
pub use group_source::{GroupSource, LocalGroupSource};
pub use membership_manager::MembershipManager;
pub use permission_cache::{InMemoryPermissionCache, PermissionCache};
pub use permission_catalog::PermissionCatalog;
pub use role_manager::RoleManager;
pub use sphinx_client::{SphinxClient, SphinxError, TokenResponse};
pub use token_verifier::TokenVerifierConfig;
pub use types::{AuthenticatedSubject, EffectivePermission, PermissionCacheKey};
