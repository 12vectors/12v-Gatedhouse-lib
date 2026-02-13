//! Axum middleware and extractors for Gatedhouse.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};

use crate::types::GatedContext;

/// Axum middleware layer key for storing GatedContext in request extensions.
pub async fn gatedhouse_middleware(
    request: Request,
    next: Next,
) -> Response {
    // In production, this would:
    // 1. Extract Bearer token from Authorization header
    // 2. Verify JWT via JwtVerifier
    // 3. Resolve membership, permissions, delegation
    // 4. Insert GatedContext into request extensions
    //
    // For now, if a GatedContext is already in extensions, pass through.
    next.run(request).await
}

/// Require a specific permission. Returns 403 if not satisfied.
pub fn require_permission(
    ctx: &GatedContext,
    required: &str,
) -> Result<(), StatusCode> {
    let checker = crate::permissions::checker::PermissionChecker::new();
    if checker.check(ctx, required).allowed {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

/// Require all permissions. Returns 403 if any are not satisfied.
pub fn require_all_permissions(
    ctx: &GatedContext,
    required: &[String],
) -> Result<(), StatusCode> {
    let checker = crate::permissions::checker::PermissionChecker::new();
    if checker.check_all(ctx, required) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

/// Require any permission. Returns 403 if none are satisfied.
pub fn require_any_permission(
    ctx: &GatedContext,
    required: &[String],
) -> Result<(), StatusCode> {
    let checker = crate::permissions::checker::PermissionChecker::new();
    if checker.check_any(ctx, required) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}
