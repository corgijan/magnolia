mod errors;
mod handlers;
mod state;
mod auth;

pub use errors::ApiError;
pub use state::AppState;
pub use auth::AuthGrant;

use axum::routing::{delete, get, post};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(handlers::health))
        .route("/api/v1/whoami", get(handlers::whoami))
        .route("/api/v1/config", get(handlers::config))
        .route("/api/v1/signing-key", get(handlers::signing_key))
        .route("/api/v1/upload", post(handlers::upload_sbom))
        .route(
            "/api/v1/tree-head/latest",
            get(handlers::tree_head_latest),
        )
        .route(
            "/api/v1/tree-head/:tree_size",
            get(handlers::tree_head_at),
        )
        .route(
            "/api/v1/proof/inclusion/:leaf_index",
            get(handlers::inclusion_proof),
        )
        .route(
            "/api/v1/proof/consistency/:old_tree_size/:new_tree_size",
            get(handlers::consistency_proof),
        )
        .route("/api/v1/leaves", get(handlers::leaves))
        .route("/api/v1/manifest/:manifest_hash", get(handlers::manifest))
        .route(
            "/api/v1/manifest/:manifest_hash/revoke",
            post(handlers::revoke_manifest),
        )
        .route(
            "/api/v1/manifests/current",
            get(handlers::current_manifests),
        )
        .route(
            "/api/v1/namespaces/hidden",
            get(handlers::list_hidden_namespaces).post(handlers::set_namespace_hidden),
        )
        .route(
            "/api/v1/keys",
            get(handlers::list_keys).post(handlers::create_key),
        )
        .route("/api/v1/keys/:key_id/revoke", post(handlers::revoke_key))
        .route(
            "/api/v1/tenants",
            get(handlers::list_tenants).post(handlers::create_tenant),
        )
        .route("/api/v1/tenants/:tenant_id", delete(handlers::delete_tenant))
        .route("/api/v1/audit-logs", get(handlers::audit_logs))
        .layer(cors)
        .with_state(state)
}