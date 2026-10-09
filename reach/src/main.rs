//! Entry point.
//!
//! Reads the environment, opens the database, starts one worker, serves the
//! API. Nothing here decides *which* model answers — that is entirely
//! [`reach::Config`], so pointing this at Ollama instead of a hosted
//! endpoint is an env-var change and a restart.

use std::sync::Arc;

use reach::api::{create_router, AppState};
use reach::config::Config;
use reach::db::Db;
use reach::fetcher::{GitFetcher, GitRefResolver, LocalPathFetcher, RepoCache, RepoFetcher};
use reach::pipeline::PipelineDeps;
use reach::worker::run_worker;

/// Ceiling on a single git operation. Generous — a cold clone of a large
/// repository is slow — but finite, so a hung transport cannot pin the
/// single worker forever.
const GIT_TIMEOUT_SECS: u64 = 300;

#[tokio::main]
async fn main() {
    // `reach --healthcheck` probes the local /health endpoint and exits
    // 0/1. The runtime image is debian-slim with no curl or wget, and
    // adding either to get a container health check would mean shipping a
    // whole HTTP client in the image just to talk to ourselves.
    if std::env::args().any(|a| a == "--healthcheck") {
        std::process::exit(healthcheck().await);
    }

    reach::config::load_dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,reach=debug")),
        )
        .init();

    let config = Config::from_env();

    if config.api_token.is_none() {
        tracing::warn!(
            "REACH_API_TOKEN is not set — the API is UNAUTHENTICATED. Acceptable for a local \
             run against fixture repositories; never for anything reachable by other machines."
        );
    }
    tracing::info!(
        base_url = %config.ai.base_url,
        model = %config.ai.model,
        timeout_secs = config.ai.timeout.as_secs(),
        "inference endpoint configured (OpenAI-compatible /v1/chat/completions)"
    );

    let db = Arc::new(
        Db::connect(&config.db_path).await.expect("failed to open the reach database"),
    );

    let client = reach::ai::ChatClient::new(config.ai.clone());

    // Startup gate: the service refuses to come up at all unless a real
    // test completion succeeds against the configured inference endpoint.
    // Deliberately AWAITED, not spawned — nothing below this point (the
    // worker, the listener, the router) exists until this resolves. This is
    // a separate concern from the pipeline's own per-request degradation
    // (stage B/D handling an inference failure mid-analysis, tested
    // extensively elsewhere): once the process is up, an AI outage later is
    // still just a degraded report, never a broken flow. This gate is only
    // about not coming up misconfigured in the first place — "the container
    // is running" should mean "the AI feature is actually usable", not
    // "it's running, but every analysis will silently fail at stage B."
    //
    // Can take a while for a slow or cold local model (this is a real
    // generation, not a cheap listing call) — logged up front so a long
    // pause during `docker compose up` reads as "waiting", not "stuck".
    //
    // REACH_TEST_MODE: no model is needed, so there is nothing to gate on.
    // Every analysis gets a canned report (pipeline::test_mode).
    let ai_probe = if config.test_mode {
        tracing::warn!(
            "REACH_TEST_MODE is set — skipping the inference check; every analysis returns a \
             CANNED report and nothing is analysed. Never use this for real triage."
        );
        Arc::new(tokio::sync::RwLock::new(None))
    } else {
        Arc::new(tokio::sync::RwLock::new(Some(startup_gate(&client, &config).await)))
    };

    let git: Arc<dyn RepoFetcher> = Arc::new(GitFetcher::new(
        RepoCache::new(config.cache_dir.clone(), config.cache_mb),
        config.git_token.clone(),
        GIT_TIMEOUT_SECS,
        config.limits.max_repo_mb,
    ));
    let local: Arc<dyn RepoFetcher> = Arc::new(LocalPathFetcher::new(
        RepoCache::new(config.cache_dir.clone(), config.cache_mb),
        GIT_TIMEOUT_SECS,
    ));

    let deps = Arc::new(PipelineDeps {
        client,
        git,
        local,
        limits: config.limits.clone(),
        test_mode: config.test_mode,
    });
    tokio::spawn(run_worker(Arc::clone(&db), Arc::clone(&deps)));

    let state = AppState {
        db,
        ai_model: config.ai.model.clone(),
        ai_base_url: config.ai.base_url.clone(),
        auth_enabled: config.api_token.is_some(),
        ai_probe,
        test_mode: config.test_mode,
        resolver: Arc::new(GitRefResolver::new(
            config.git_token.clone(),
            reach::fetcher::resolve::RESOLVE_TIMEOUT_SECS,
        )),
    };
    let app = create_router(state, config.api_token.clone());

    let listener = tokio::net::TcpListener::bind(&config.server_addr)
        .await
        .expect("failed to bind REACH_SERVER_ADDR");
    tracing::info!(addr = %config.server_addr, "reach listening (docs at /docs)");
    axum::serve(listener, app).await.expect("server failed");
}

/// Refuses to start (exit 1) unless a real test completion succeeds against
/// the configured inference endpoint.
async fn startup_gate(
    client: &reach::ai::ChatClient,
    config: &Config,
) -> reach::ai::ProbeOutcome {
    tracing::info!(
        base_url = %config.ai.base_url, model = %config.ai.model,
        "checking the inference endpoint before starting — this sends a real test completion \
         and can take a while for a slow or cold local model"
    );
    let probe_outcome = client.probe().await;
    let base_url = &config.ai.base_url;
    let model = &config.ai.model;
    match &probe_outcome {
        reach::ai::ProbeOutcome::Reachable { model_listed: Some(true) } => {
            tracing::info!(
                %base_url, %model,
                "startup check passed: a test completion succeeded and the model listing \
                 confirms REACH_AI_MODEL"
            );
        }
        reach::ai::ProbeOutcome::Reachable { model_listed: Some(false) } => {
            tracing::warn!(
                %base_url, %model,
                "startup check passed (with a caveat): a test completion succeeded, but the \
                 server's model listing does not include REACH_AI_MODEL — double-check the \
                 exact name"
            );
        }
        reach::ai::ProbeOutcome::Reachable { model_listed: None } => {
            tracing::info!(
                %base_url, %model,
                "startup check passed: a test completion succeeded (the server does not \
                 support listing models, so REACH_AI_MODEL could not be cross-checked)"
            );
        }
        reach::ai::ProbeOutcome::RespondedWithError { status, detail } => {
            tracing::error!(%base_url, %model, %status, %detail, "startup check failed");
            eprintln!(
                "reach: refusing to start — the inference endpoint rejected a test completion \
                 (HTTP {status}): {detail}\n\
                 Check REACH_AI_API_KEY, REACH_AI_BASE_URL, and REACH_AI_MODEL."
            );
            std::process::exit(1);
        }
        reach::ai::ProbeOutcome::RespondedButUnusable { detail } => {
            tracing::error!(%base_url, %model, %detail, "startup check failed");
            eprintln!(
                "reach: refusing to start — the inference endpoint responded, but not with \
                 something this service can use: {detail}\n\
                 See reach/README.md#configuration."
            );
            std::process::exit(1);
        }
        reach::ai::ProbeOutcome::Unreachable { detail } => {
            tracing::error!(%base_url, %model, %detail, "startup check failed");
            eprintln!(
                "reach: refusing to start — the inference endpoint is not reachable: \
                 {detail}\n\
                 Check REACH_AI_BASE_URL and that the server is actually running."
            );
            std::process::exit(1);
        }
    }
    // From here on the outcome is definitely `Reachable` — everything above
    // that isn't already `exit(1)`'d.
    probe_outcome
}

/// Returns the process exit code: 0 when `/health` answers 2xx.
async fn healthcheck() -> i32 {
    let addr = std::env::var("REACH_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:3100".to_string());
    // The bind address may be a wildcard, which is not a valid destination.
    let target = addr.replace("0.0.0.0", "127.0.0.1").replace("[::]", "[::1]");
    let url = format!("http://{target}/health");

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return 1,
    };
    match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => 0,
        Ok(r) => {
            eprintln!("health check: HTTP {}", r.status());
            1
        }
        Err(e) => {
            eprintln!("health check: {e}");
            1
        }
    }
}
