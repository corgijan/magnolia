//! HTTP surface.
//!
//! Small on purpose: create an analysis, read one, list them, plus health
//! and the OpenAPI document. The whole API is described with `utoipa`
//! annotations, so `/openapi.json` is generated from the same types the
//! handlers use and cannot drift from them.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tower_http::cors::CorsLayer;
use utoipa::{Modify, OpenApi};
use uuid::Uuid;

use crate::db::Db;
use crate::error::ApiError;
use crate::models::*;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    /// Echoed by `/health` so an operator can confirm which model a
    /// deployment is actually pointed at without shelling into the container.
    pub ai_model: String,
    pub ai_base_url: String,
    pub auth_enabled: bool,
    /// Result of the most recent inference-endpoint reachability probe (run
    /// once at startup, and never on the request path — see
    /// `crate::ai::ChatClient::probe`). `None` until the startup probe
    /// finishes, which `/health` reports as `"pending"` rather than guessing.
    /// In the shipped `main.rs`, this is only ever observably `None` for the
    /// instant between process start and the (blocking, startup-gating)
    /// probe resolving — by the time the listener accepts a connection at
    /// all, the probe has already succeeded, since anything else exits the
    /// process before binding. Still `Option`, not the bare value: this type
    /// is also used directly by tests that construct `AppState` without
    /// running that gate.
    pub ai_probe: Arc<tokio::sync::RwLock<Option<crate::ai::ProbeOutcome>>>,
    /// Turns a request's `ref` into the exact commit it names, once, at
    /// request time. A trait object so the API tests can stub it without a
    /// network or a git binary.
    pub resolver: Arc<dyn crate::fetcher::RefResolver>,
    /// `REACH_TEST_MODE` — every report is canned. Echoed by `/health`.
    pub test_mode: bool,
}

/// Registers the `bearer` security scheme the annotated paths refer to.
///
/// Without this, every `security(("bearer" = []))` below names a scheme that
/// appears nowhere in `components.securitySchemes`, which makes the emitted
/// document invalid OpenAPI — a dangling reference, not merely an
/// undocumented one. `utoipa` does not infer the scheme from the annotation,
/// so it has to be added here.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};

        // `components` is `None` until something populates it; `schemas(...)`
        // below already does, but building it defensively keeps this correct
        // if the schema list is ever emptied.
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "The value of REACH_API_TOKEN. Omitted entirely when the service is run \
                         without a token configured, which it warns about at startup.",
                    ))
                    .build(),
            ),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityAddon),
    paths(create_analysis, get_analysis, list_analyses, health),
    components(schemas(
        CreateAnalysis, CreateAnalysisResponse, AnalysisView, AnalysisSummary, AnalysisStatus,
        Report, Ruleset, EvidenceSite, RelevanceLabel, PriorityLabel, StageOutcome, StageStatus,
        Counters,
    )),
    tags((name = "analyses", description = "CVE reachability evidence")),
    info(
        title = "reach — CVE reachability evidence",
        version = "0.1.0",
        description = "Given an advisory and an exact source revision, reports where the \
                       advisory's vulnerable symbols are referenced, with every claim cited as \
                       file:line and every citation verified against the checkout. Produces \
                       evidence for a human analyst, never a verdict: no endpoint here returns \
                       an exploitability judgement, and the priority label is an ordinal name \
                       for which rules fired, not a probability."
    )
)]
pub struct ApiDoc;

/// Public routes (no token) plus the authenticated API.
pub fn create_router(state: AppState, api_token: Option<String>) -> Router {
    let api = Router::new()
        .route("/api/v1/analyses", post(create_analysis).get(list_analyses))
        .route("/api/v1/analyses/:id", get(get_analysis))
        .route_layer(axum::middleware::from_fn_with_state(
            api_token.map(Arc::new),
            crate::auth::require_token,
        ))
        .with_state(state.clone());

    Router::new()
        // Unauthenticated on purpose: a container health check has no token,
        // and neither carries nor reveals anything sensitive.
        .route("/health", get(health))
        .route("/openapi.json", get(openapi_json))
        .route("/docs", get(docs))
        .with_state(state)
        .merge(api)
        // AISE's frontend calls this directly in the dev stack.
        .layer(CorsLayer::permissive())
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    50
}

/// Queue an analysis.
#[utoipa::path(
    post,
    path = "/api/v1/analyses",
    tag = "analyses",
    request_body = CreateAnalysis,
    responses(
        (status = 202, description = "Analysis queued", body = CreateAnalysisResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
    security(("bearer" = []))
)]
pub async fn create_analysis(
    State(state): State<AppState>,
    Json(mut req): Json<CreateAnalysis>,
) -> Result<impl IntoResponse, ApiError> {
    // An advisory identifier alone is not analysable: this service does not
    // fetch advisories, AISE does (it already has the OSV and
    // Dependency-Track text on hand). Saying so is more useful than queueing
    // a job that can only fail.
    let advisory_text = req
        .advisory_text
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest(
                "advisory_text is required — this service does not fetch advisories by id; \
                 pass the advisory prose (osv_id is recorded alongside it)"
                    .to_string(),
            )
        })?
        .to_string();

    // Validate the repository target up front so the caller gets a 400 now
    // rather than a failed job in thirty seconds.
    let git_ref = req.git_ref.as_deref().map(str::trim).filter(|r| !r.is_empty()).map(str::to_string);
    if let Some(url) = req.repo_url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        crate::fetcher::validate_repo_url(url).map_err(|e| ApiError::BadRequest(e.to_string()))?;
        let commit = match (req.commit.as_deref().map(str::trim).filter(|c| !c.is_empty()), &git_ref) {
            // An exact commit always wins; a ref sent alongside it is ignored
            // rather than cross-checked, so it is not recorded either.
            (Some(commit), _) => {
                req.git_ref = None;
                crate::fetcher::validate_commit(commit).map_err(|e| ApiError::BadRequest(e.to_string()))?
            }
            // Resolved exactly once, here. Everything downstream — the job,
            // the fetch, the report — sees only the resulting commit, so the
            // evidence stays pinned even if the branch moves a second later.
            (None, Some(r)) => {
                let commit = state
                    .resolver
                    .resolve(url, r)
                    .await
                    .map_err(|e| ApiError::BadRequest(e.to_string()))?;
                tracing::info!(repo_url = %url, requested_ref = %r, %commit, "resolved ref to commit");
                req.git_ref = Some(r.clone());
                commit
            }
            (None, None) => {
                return Err(ApiError::BadRequest(
                    "commit is required when repo_url is given (or pass `ref` — a branch or tag \
                     name, resolved once to the exact commit it points at) — an analysis pinned \
                     to a moving ref could not be reproduced or audited"
                        .to_string(),
                ))
            }
        };
        req.commit = Some(commit);
    } else {
        // No repository: nothing to resolve, and nothing to record.
        req.commit = None;
        req.git_ref = None;
    }

    let id = state.db.insert_analysis(&req, &advisory_text).await?;
    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(CreateAnalysisResponse {
            id,
            status: AnalysisStatus::Queued,
            commit: req.commit,
            requested_ref: req.git_ref,
        }),
    ))
}

/// Fetch one analysis, with its report once it is finished.
#[utoipa::path(
    get,
    path = "/api/v1/analyses/{id}",
    tag = "analyses",
    params(("id" = Uuid, Path, description = "Analysis id")),
    responses(
        (status = 200, description = "The analysis", body = AnalysisView),
        (status = 404, description = "No such analysis"),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
    security(("bearer" = []))
)]
pub async fn get_analysis(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AnalysisView>, ApiError> {
    state.db.get_analysis(id).await?.map(Json).ok_or(ApiError::NotFound)
}

/// Most recent analyses.
#[utoipa::path(
    get,
    path = "/api/v1/analyses",
    tag = "analyses",
    params(("limit" = Option<i64>, Query, description = "Rows to return (1-500, default 50)")),
    responses(
        (status = 200, description = "Recent analyses", body = [AnalysisSummary]),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
    security(("bearer" = []))
)]
pub async fn list_analyses(
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<AnalysisSummary>>, ApiError> {
    Ok(Json(state.db.list_analyses(params.limit).await?))
}

/// Liveness, plus which inference endpoint this deployment is configured
/// against.
#[utoipa::path(
    get,
    path = "/health",
    responses((status = 200, description = "Service is up")),
)]
pub async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let ai_probe = state
        .ai_probe
        .read()
        .await
        .as_ref()
        .map(|p| serde_json::to_value(p).unwrap_or(serde_json::Value::Null))
        .unwrap_or_else(|| {
            // Test mode never probes, so "pending" would wait forever.
            serde_json::Value::String(if state.test_mode { "skipped" } else { "pending" }.to_string())
        });

    Json(serde_json::json!({
        "status": "ok",
        "service": "reach",
        "version": env!("CARGO_PKG_VERSION"),
        // Deliberately not the API key. `/health`'s own "status": "ok" still
        // answers "is this process alive" unconditionally — an unreachable
        // inference server is a degradation the pipeline already handles per
        // request, not a reason to take the whole container out of service —
        // but the last known probe result is surfaced here for an operator
        // to actually see, rather than only ever appearing once in a log at
        // startup.
        "ai_model": state.ai_model,
        "ai_base_url": state.ai_base_url,
        "auth_enabled": state.auth_enabled,
        "ai_probe": ai_probe,
        "test_mode": state.test_mode,
    }))
}

pub async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

/// Swagger UI, loaded from a CDN.
///
/// `utoipa-swagger-ui` would vendor the assets, but it downloads them during
/// `cargo build`, which makes the Docker image un-buildable without network
/// access to that specific host. The spec at `/openapi.json` — the actual
/// deliverable — is generated offline and needs nothing external; only this
/// convenience page does.
pub async fn docs() -> Html<&'static str> {
    Html(
        r##"<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <title>reach API</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css"/>
  </head>
  <body>
    <div id="ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.onload = () => SwaggerUIBundle({ url: "/openapi.json", dom_id: "#ui" });
    </script>
  </body>
</html>"##,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Resolves `main` to a fixed commit and everything else to "not found",
    /// without git or a network.
    struct StubResolver;

    const MAIN_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    #[async_trait::async_trait]
    impl crate::fetcher::RefResolver for StubResolver {
        async fn resolve(&self, _repo_url: &str, git_ref: &str) -> Result<String, crate::fetcher::FetchError> {
            match git_ref {
                "main" => Ok(MAIN_COMMIT.to_string()),
                other => Err(crate::fetcher::FetchError::RefNotFound(other.to_string())),
            }
        }
    }

    async fn app(token: Option<&str>) -> (Router, Arc<Db>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::connect(dir.path().join("api.db").to_str().unwrap()).await.unwrap());
        let state = AppState {
            db: db.clone(),
            ai_model: "test-model".to_string(),
            ai_base_url: "http://localhost:11434".to_string(),
            auth_enabled: token.is_some(),
            ai_probe: Arc::new(tokio::sync::RwLock::new(None)),
            resolver: Arc::new(StubResolver),
            test_mode: false,
        };
        (create_router(state, token.map(str::to_string)), db, dir)
    }

    fn post_json(uri: &str, body: serde_json::Value, token: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().method("POST").uri(uri).header("content-type", "application/json");
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        b.body(Body::from(body.to_string())).unwrap()
    }

    fn get(uri: &str, token: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().method("GET").uri(uri);
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        b.body(Body::empty()).unwrap()
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn health_is_reachable_without_a_token() {
        let (app, _db, _dir) = app(Some("secret")).await;
        let resp = app.oneshot(get("/health", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["status"], "ok");
        assert_eq!(json["ai_model"], "test-model");
        // Nothing has run the startup probe against this test's state.
        assert_eq!(json["ai_probe"], "pending");
        // The key must never be echoed.
        assert!(json.get("ai_api_key").is_none());
    }

    #[tokio::test]
    async fn health_surfaces_a_completed_probe_result() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::connect(dir.path().join("api.db").to_str().unwrap()).await.unwrap());
        let probe_slot = Arc::new(tokio::sync::RwLock::new(None));
        let state = AppState {
            db,
            ai_model: "test-model".to_string(),
            ai_base_url: "http://localhost:11434".to_string(),
            auth_enabled: false,
            ai_probe: probe_slot.clone(),
            resolver: Arc::new(StubResolver),
            test_mode: false,
        };
        let router = create_router(state, None);

        *probe_slot.write().await = Some(crate::ai::ProbeOutcome::Unreachable {
            detail: "connection refused".to_string(),
        });

        let resp = router.oneshot(get("/health", None)).await.unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["ai_probe"]["outcome"], "unreachable");
        assert_eq!(json["ai_probe"]["detail"], "connection refused");
    }

    #[tokio::test]
    async fn the_api_rejects_a_missing_or_wrong_token() {
        let (app, _db, _dir) = app(Some("secret")).await;
        for req in [get("/api/v1/analyses", None), get("/api/v1/analyses", Some("wrong"))] {
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        let resp = app.oneshot(get("/api/v1/analyses", Some("secret"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn creating_an_analysis_queues_it_and_returns_its_id() {
        let (app, db, _dir) = app(None).await;
        let resp = app
            .oneshot(post_json(
                "/api/v1/analyses",
                serde_json::json!({
                    "advisory_text": "A flaw in lookup().",
                    "osv_id": "CVE-2021-3",
                    "repo_url": "https://github.com/o/r",
                    "commit": "a".repeat(40),
                }),
                None,
            ))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let json = body_json(resp).await;
        let id: Uuid = serde_json::from_value(json["id"].clone()).unwrap();
        assert_eq!(db.get_analysis(id).await.unwrap().unwrap().status, AnalysisStatus::Queued);
    }

    #[tokio::test]
    async fn a_request_without_advisory_text_is_rejected_with_a_reason() {
        let (app, _db, _dir) = app(None).await;
        let resp = app
            .oneshot(post_json("/api/v1/analyses", serde_json::json!({ "osv_id": "CVE-1" }), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_json(resp).await["error"].as_str().unwrap().contains("advisory_text"));
    }

    #[tokio::test]
    async fn a_dangerous_repo_url_is_refused_at_the_edge() {
        // Rejected before a job is queued, so the caller learns immediately
        // rather than from a failed analysis later.
        let (app, _db, _dir) = app(None).await;
        let resp = app
            .oneshot(post_json(
                "/api/v1/analyses",
                serde_json::json!({
                    "advisory_text": "x",
                    "repo_url": "ext::sh -c evil",
                    "commit": "a".repeat(40),
                }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_repo_without_a_commit_is_refused() {
        let (app, _db, _dir) = app(None).await;
        let resp = app
            .oneshot(post_json(
                "/api/v1/analyses",
                serde_json::json!({ "advisory_text": "x", "repo_url": "https://h/r" }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_json(resp).await["error"].as_str().unwrap().contains("commit is required"));
    }

    #[tokio::test]
    async fn a_ref_is_resolved_once_and_the_analysis_is_pinned_to_the_commit() {
        let (app, db, _dir) = app(None).await;
        let resp = app
            .oneshot(post_json(
                "/api/v1/analyses",
                serde_json::json!({ "advisory_text": "x", "repo_url": "https://h/r", "ref": "main" }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let json = body_json(resp).await;
        assert_eq!(json["commit"], MAIN_COMMIT);
        assert_eq!(json["requested_ref"], "main");

        let id: Uuid = serde_json::from_value(json["id"].clone()).unwrap();
        let view = db.get_analysis(id).await.unwrap().unwrap();
        assert_eq!(view.commit.as_deref(), Some(MAIN_COMMIT));
        assert_eq!(view.requested_ref.as_deref(), Some("main"));
    }

    #[tokio::test]
    async fn an_exact_commit_wins_over_a_ref_and_the_ref_is_not_recorded() {
        let (app, db, _dir) = app(None).await;
        let resp = app
            .oneshot(post_json(
                "/api/v1/analyses",
                serde_json::json!({
                    "advisory_text": "x",
                    "repo_url": "https://h/r",
                    "commit": "b".repeat(40),
                    "ref": "does-not-exist",
                }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let json = body_json(resp).await;
        assert_eq!(json["commit"], "b".repeat(40));
        assert!(json["requested_ref"].is_null());
        let id: Uuid = serde_json::from_value(json["id"].clone()).unwrap();
        assert!(db.get_analysis(id).await.unwrap().unwrap().requested_ref.is_none());
    }

    #[tokio::test]
    async fn an_unresolvable_ref_is_refused_before_a_job_is_queued() {
        let (app, db, _dir) = app(None).await;
        let resp = app
            .oneshot(post_json(
                "/api/v1/analyses",
                serde_json::json!({ "advisory_text": "x", "repo_url": "https://h/r", "ref": "gone" }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_json(resp).await["error"].as_str().unwrap().contains("gone"));
        assert!(db.list_analyses(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_advisory_only_analysis_is_accepted() {
        // The fallback feature's entry point: no repository at all.
        let (app, _db, _dir) = app(None).await;
        let resp = app
            .oneshot(post_json(
                "/api/v1/analyses",
                serde_json::json!({ "advisory_text": "A flaw in lookup()." }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn an_unknown_analysis_is_a_404() {
        let (app, _db, _dir) = app(None).await;
        let resp =
            app.oneshot(get(&format!("/api/v1/analyses/{}", Uuid::new_v4()), None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_malformed_id_is_a_client_error_not_a_500() {
        let (app, _db, _dir) = app(None).await;
        let resp = app.oneshot(get("/api/v1/analyses/not-a-uuid", None)).await.unwrap();
        assert!(resp.status().is_client_error());
    }

    #[tokio::test]
    async fn the_openapi_document_is_served_and_describes_the_endpoints() {
        let (app, _db, _dir) = app(Some("secret")).await;
        let resp = app.oneshot(get("/openapi.json", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let spec = body_json(resp).await;
        assert!(spec["paths"]["/api/v1/analyses"]["post"].is_object());
        assert!(spec["paths"]["/api/v1/analyses/{id}"]["get"].is_object());
        assert!(spec["components"]["schemas"]["Report"].is_object());
        // The no-verdict framing is part of the published contract.
        assert!(spec["info"]["description"].as_str().unwrap().contains("never a verdict"));
    }

    #[tokio::test]
    async fn every_security_requirement_names_a_scheme_the_document_defines() {
        // A `security` entry referring to a scheme absent from
        // `components.securitySchemes` is a dangling reference: the document
        // fails OpenAPI validation, and a generated client has no way to know
        // how to authenticate. Checked against the real document rather than
        // asserting the one name, so adding a second scheme later cannot
        // quietly reintroduce the same gap.
        let (app, _db, _dir) = app(Some("secret")).await;
        let spec = body_json(app.oneshot(get("/openapi.json", None)).await.unwrap()).await;

        let defined = spec["components"]["securitySchemes"]
            .as_object()
            .expect("the document must define its security schemes");
        assert!(defined.contains_key("bearer"), "got: {defined:?}");
        assert_eq!(defined["bearer"]["scheme"], "bearer");

        let mut checked = 0usize;
        for (path, item) in spec["paths"].as_object().unwrap() {
            for (method, op) in item.as_object().unwrap() {
                let Some(requirements) = op["security"].as_array() else { continue };
                for requirement in requirements {
                    for name in requirement.as_object().unwrap().keys() {
                        assert!(
                            defined.contains_key(name),
                            "{method} {path} requires undefined security scheme {name:?}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 3, "the three authenticated operations must each declare the scheme");
    }
}
