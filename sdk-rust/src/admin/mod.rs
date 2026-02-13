//! Admin REST API router for role and permission management (Axum).

use axum::{
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RoleCreateRequest {
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub inherits: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RoleAssignRequest {
    pub membership_id: String,
    pub role_id: String,
    pub assigned_by: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: String,
}

/// Create the admin API router.
/// In production, this would take a shared state containing
/// repositories, assignments, and resolver references.
pub fn create_admin_router() -> Router {
    Router::new()
        .route("/gatedhouse/admin/health", get(health_check))
}

async fn health_check() -> impl IntoResponse {
    Json(StatusResponse { status: "ok".to_string() })
}
