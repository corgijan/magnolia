mod dtrack_sync;
mod errors;
mod freshness_sync;
mod handlers;
mod malicious_check;
mod malicious_sync;
mod reputation_bucket;
mod reputation_sync;
mod snapshot;
mod state;
mod auth;
mod sync_loop;
mod webhooks;

pub use dtrack_sync::{run_sync_loop, sync_now};
pub use errors::ApiError;
pub use freshness_sync::run_freshness_sync_loop;
pub use malicious_sync::run_malicious_sync_loop;
pub use reputation_sync::run_reputation_sync_loop;
pub use state::AppState;
pub use auth::AuthGrant;
pub use webhooks::run_webhook_delivery_loop;

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, patch, post};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(handlers::health))
        .route("/install.sh", get(handlers::install_script))
        .route("/api/v1/whoami", get(handlers::whoami))
        .route("/api/v1/config", get(handlers::config))
        .route("/api/v1/signing-key", get(handlers::signing_key))
        .route(
            "/api/v1/upload",
            post(handlers::upload_sbom).layer(DefaultBodyLimit::max(
                handlers::MAX_SBOM_BYTES + 64 * 1024,
            )),
        )
        .route(
            "/api/v1/verify",
            post(handlers::verify_sbom).layer(DefaultBodyLimit::max(
                handlers::MAX_SBOM_BYTES + 64 * 1024,
            )),
        )
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
        .route("/api/v1/manifest/:manifest_hash/vex", get(handlers::manifest_vex))
        .route(
            "/api/v1/manifest/:manifest_hash/vex/import",
            post(handlers::import_manifest_vex).layer(DefaultBodyLimit::max(
                handlers::MAX_SBOM_BYTES + 64 * 1024,
            )),
        )
        .route("/api/v1/manifest/:manifest_hash/diff", get(handlers::manifest_diff))
        .route("/api/v1/namespaces/manifests", get(handlers::namespace_manifest_versions))
        .route(
            "/api/v1/manifest/:manifest_hash/revoke",
            post(handlers::revoke_manifest),
        )
        .route(
            "/api/v1/manifest/:manifest_hash/findings/:finding_key/triage",
            post(handlers::triage_finding),
        )
        .route(
            "/api/v1/manifest/:manifest_hash/findings/:finding_key/comments",
            get(handlers::list_finding_comments).post(handlers::add_finding_comment),
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
            "/api/v1/settings/dtrack-sync",
            get(handlers::dtrack_sync_setting).post(handlers::set_dtrack_sync_setting),
        )
        .route(
            "/api/v1/settings/semver-version",
            get(handlers::semver_setting).post(handlers::set_semver_setting),
        )
        .route(
            "/api/v1/settings/reputation-sync",
            get(handlers::reputation_tenant_setting).post(handlers::set_reputation_tenant_setting),
        )
        .route(
            "/api/v1/settings/freshness",
            get(handlers::freshness_tenant_setting).post(handlers::set_freshness_tenant_setting),
        )
        .route(
            "/api/v1/settings/malicious-check",
            get(handlers::malicious_check_tenant_setting).post(handlers::set_malicious_check_tenant_setting),
        )
        .route(
            "/api/v1/settings/namespace-registration",
            get(handlers::namespace_registration_setting).post(handlers::set_namespace_registration_setting),
        )
        .route(
            "/api/v1/namespaces/registered",
            get(handlers::list_registered_namespaces)
                .post(handlers::create_namespace)
                .delete(handlers::delete_namespace),
        )
        .route(
            "/api/v1/compliance/profiles",
            get(handlers::list_compliance_profiles),
        )
        .route(
            "/api/v1/compliance/settings",
            get(handlers::compliance_settings).post(handlers::set_compliance_setting),
        )
        .route(
            "/api/v1/settings/license-policy",
            get(handlers::license_policy).post(handlers::set_license_policy),
        )
        .route("/api/v1/snapshot", post(handlers::snapshot))
        .route(
            "/api/v1/search/components",
            get(handlers::search_components),
        )
        .route(
            "/api/v1/search/reindex",
            post(handlers::reindex_components),
        )
        .route(
            "/api/v1/tenants/cache/clear",
            post(handlers::clear_tenant_caches),
        )
        .route(
            "/api/v1/components/affected",
            get(handlers::components_affected),
        )
        .route(
            "/api/v1/vulnerabilities/:vuln_id/affected",
            get(handlers::vulnerability_affected),
        )
        .route("/api/v1/findings", get(handlers::list_findings))
        .route("/api/v1/dtrack/sync", post(handlers::force_dtrack_sync))
        .route("/api/v1/reputation/sync", post(handlers::force_reputation_sync))
        .route("/api/v1/reputation/status", get(handlers::reputation_status))
        .route("/api/v1/reputation/components", get(handlers::reputation_components))
        .route("/api/v1/freshness/sync", post(handlers::force_freshness_sync))
        .route("/api/v1/freshness/status", get(handlers::freshness_status))
        .route("/api/v1/malicious/sync", post(handlers::force_malicious_sync))
        .route("/api/v1/malicious/status", get(handlers::malicious_check_status))
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
        .route(
            "/api/v1/webhooks",
            get(handlers::list_webhooks).post(handlers::create_webhook),
        )
        .route(
            "/api/v1/webhooks/:id",
            patch(handlers::update_webhook).delete(handlers::delete_webhook),
        )
        .route("/api/v1/webhooks/:id/test", post(handlers::test_webhook))
        .route("/api/v1/webhooks/:id/deliveries", get(handlers::webhook_deliveries))
        .layer(cors)
        .with_state(state)
}