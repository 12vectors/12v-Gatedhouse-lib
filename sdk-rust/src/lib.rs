//! Gatedhouse authorization library for the SuperAgent Platform.

pub mod types;
pub mod config;
pub mod permissions;
pub mod roles;
pub mod membership;
pub mod delegation;
pub mod policies;
pub mod events;
pub mod audit;
pub mod metrics;

#[cfg(feature = "database")]
pub mod database;

#[cfg(feature = "jwt")]
pub mod jwt;

#[cfg(feature = "web")]
pub mod middleware;

#[cfg(feature = "web")]
pub mod admin;

pub use types::*;
pub use config::{GatehouseConfig, ResolvedConfig};
pub use permissions::matcher::{
    match_permission, has_permission, has_all_permissions,
    has_any_permission, intersect_permissions,
};
pub use permissions::checker::PermissionChecker;
