use std::collections::HashMap;
use std::sync::Arc;

use magnolia_api::{
    create_router, run_freshness_sync_loop, run_malicious_sync_loop, run_reachability_auto_loop,
    run_reputation_sync_loop,
    run_sync_loop, run_webhook_delivery_loop, AppState,
};
use magnolia_audit::AuditLogger;
use magnolia_core::MerkleTree;
use magnolia_db::Database;
use magnolia_depsdev::DepsDevClient;
use magnolia_dtrack::DtrackClient;
use magnolia_osv::OsvClient;
use magnolia_reachability::ReachClient;
use magnolia_signer::LocalFileSigner;
use magnolia_storage::{FileStore, InMemoryStore, ObjectStore};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set (postgres://...)");
    let db = Database::connect(&database_url)
        .await
        .expect("failed to connect to database");

    run_migrations(&db.pool).await;
    bootstrap_super_admin_from_env(&db).await;

    let key_path = std::env::var("SIGNING_KEY_PATH")
        .unwrap_or_else(|_| ".sbomstash_key".to_string());
    ensure_signing_key(&key_path);
    let signer = Arc::new(LocalFileSigner::new(std::path::PathBuf::from(&key_path)));

    // Dev/test convenience: InMemoryStore loses all SBOM content on every
    // restart (only the Postgres metadata survives), which makes "locked"
    // leaves permanently unfetchable across `docker compose restart`. Set
    // STORAGE_PATH to persist SBOM bytes to disk instead — production still
    // wants S3Store (not built yet), but this closes the dev-data-loss gap
    // cheaply in the meantime.
    let (storage, storage_backend): (Arc<dyn ObjectStore>, &'static str) =
        match std::env::var("STORAGE_PATH") {
            Ok(path) => {
                tracing::info!(path = %path, "using file-based object storage");
                (Arc::new(FileStore::new(path)), "file")
            }
            Err(_) => {
                tracing::warn!("STORAGE_PATH not set — using in-memory storage; SBOM content will not survive a restart");
                (Arc::new(InMemoryStore::new()), "in-memory")
            }
        };

    let mut trees: HashMap<uuid::Uuid, MerkleTree> = HashMap::new();
    match db.load_all_leaf_hashes_by_tenant().await {
        Ok(rows) => {
            for (tenant_id, leaf_hash) in &rows {
                trees.entry(*tenant_id).or_insert_with(MerkleTree::new).add_leaf_hash(leaf_hash);
            }
            tracing::info!(tenants = trees.len(), "rebuilt per-tenant merkle trees from database");
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not load leaf hashes; starting with empty trees");
        }
    }

    let dev_mode = std::env::var("DEV_MODE")
        .map(|v| v == "true")
        .unwrap_or(false);
    if dev_mode {
        tracing::warn!("DEV_MODE=true — RBAC is relaxed for manifest revocation; never set this in production");
    }

    // Optional, deployment-wide (not per-tenant) — an operator either runs a
    // dtrack instance or doesn't, same presence-gated pattern as
    // STORAGE_PATH/SIGNING_KEY_PATH above. Both env vars must be set and
    // non-empty for the integration to turn on.
    //
    // DTRACK_API_KEY_FILE is the fully-automatic path (see
    // docker-compose.dtrack.yml): a one-shot bootstrap container mints the
    // key and writes it to a shared volume *before* this container starts
    // (`depends_on: condition: service_completed_successfully`), so reading
    // it fresh at our own startup is enough — no restart of this process
    // needed. A plain DTRACK_API_KEY env var still wins if both are set.
    let dtrack_url = std::env::var("DTRACK_URL").ok().filter(|s| !s.is_empty());
    let dtrack_api_key = std::env::var("DTRACK_API_KEY")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let path = std::env::var("DTRACK_API_KEY_FILE").ok()?;
            let key = std::fs::read_to_string(&path).ok()?.trim().to_string();
            if key.is_empty() {
                None
            } else {
                tracing::info!(path = %path, "read Dependency-Track API key from DTRACK_API_KEY_FILE");
                Some(key)
            }
        });
    let dtrack = match (dtrack_url, dtrack_api_key) {
        (Some(url), Some(key)) => {
            tracing::info!(url = %url, "Dependency-Track integration enabled");
            Some(Arc::new(DtrackClient::new(url, key)))
        }
        _ => {
            tracing::info!("DTRACK_URL/DTRACK_API_KEY not both set — Dependency-Track integration disabled");
            None
        }
    };

    let dtrack_sync_interval_secs = std::env::var("DTRACK_SYNC_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(600);

    // On by default -- OSV's public API needs no setup/API key, unlike
    // standing up a dtrack instance, so this is an opt-out rather than a
    // presence-gated pair of env vars.
    let malicious_sync_interval_secs = std::env::var("MALICIOUS_SYNC_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3600);
    let osv = if std::env::var("DISABLE_MALICIOUS_PACKAGE_CHECK").is_ok() {
        tracing::info!("DISABLE_MALICIOUS_PACKAGE_CHECK set — malicious-package check disabled");
        None
    } else {
        Some(Arc::new(OsvClient::default()))
    };

    // Also on by default, same reasoning as `osv` above -- deps.dev needs no
    // setup either.
    let reputation_sync_interval_secs = std::env::var("REPUTATION_SYNC_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3600);
    // Shares `depsdev`'s presence gate -- both jobs hit the same client and
    // the same `sbom_components.ecosystem`/`registry_name` backfill (see
    // `freshness_sync.rs`'s module doc comment), so there's no separate
    // `DISABLE_FRESHNESS_CHECK` flag.
    let freshness_sync_interval_secs = std::env::var("FRESHNESS_SYNC_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3600);
    let depsdev = if std::env::var("DISABLE_REPUTATION_CHECK").is_ok() {
        tracing::info!("DISABLE_REPUTATION_CHECK set — package reputation scoring disabled");
        None
    } else {
        Some(Arc::new(DepsDevClient::default()))
    };

    // Outbox delivery worker for `POST /webhooks` — polls frequently (unlike
    // the other sync loops, this isn't waiting on a slow external API, so a
    // short default keeps the backoff schedule's 1-minute first retry
    // actually meaningful rather than rounded up to the next tick).
    let webhook_delivery_interval_secs = std::env::var("WEBHOOK_DELIVERY_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30);

    // Shared by every dtrack/reputation/malicious/freshness sync loop (see
    // `sync_loop::run_burst_loop`): while a batch is finding pending work,
    // the next batch is tried after this short interval instead of waiting
    // out the full per-job `*_SYNC_INTERVAL_SECS` — lets a large backlog
    // (a bulk import, or the first run after a deployment's existing
    // archive predates one of these jobs) drain in minutes instead of one
    // bounded batch per hour. One knob for all four, not four separate
    // ones, since there's no reason they'd ever want different burst
    // cadences.
    let sync_burst_interval_secs = std::env::var("SYNC_BURST_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30);

    // Optional CVE-reachability analyser (the standalone `reach/` service).
    // Presence-gated on both env vars, exactly like the dtrack pair above:
    // an operator either runs the analyser or doesn't, and when they don't,
    // the "Analyze reachability" button explains itself as unavailable and
    // nothing else in the application changes.
    let reach_base_url = std::env::var("AISE_REACH_BASE_URL").ok().filter(|s| !s.is_empty());
    let reach_token = std::env::var("AISE_REACH_TOKEN").ok().filter(|s| !s.is_empty());
    let reach = match (reach_base_url, reach_token) {
        (Some(url), Some(token)) => {
            tracing::info!(url = %url, "CVE reachability analyser enabled");
            Some(Arc::new(ReachClient::new(url, token)))
        }
        _ => {
            tracing::info!(
                "AISE_REACH_BASE_URL/AISE_REACH_TOKEN not both set — CVE reachability analysis disabled"
            );
            None
        }
    };

    let db = Arc::new(db);

    tokio::spawn(run_webhook_delivery_loop(
        Arc::clone(&db),
        std::time::Duration::from_secs(webhook_delivery_interval_secs),
        dev_mode,
    ));

    let sync_burst_interval = std::time::Duration::from_secs(sync_burst_interval_secs);

    if let Some(client) = depsdev.clone() {
        tokio::spawn(run_reputation_sync_loop(
            Arc::clone(&db),
            client.clone(),
            std::time::Duration::from_secs(reputation_sync_interval_secs),
            sync_burst_interval,
        ));
        tokio::spawn(run_freshness_sync_loop(
            Arc::clone(&db),
            client,
            std::time::Duration::from_secs(freshness_sync_interval_secs),
            sync_burst_interval,
        ));
    }
    // Background reachability analysis for namespaces opted in with
    // `auto_analyze`. Only meaningful with an analyser configured; the
    // concurrency cap is deliberately small because the analyser works one
    // job at a time and each takes minutes against a local model.
    if let Some(client) = reach.clone() {
        if std::env::var("DISABLE_REACHABILITY_AUTO").is_ok() {
            tracing::info!("DISABLE_REACHABILITY_AUTO set — background reachability analysis disabled");
        } else {
            let interval_secs = std::env::var("REACHABILITY_AUTO_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(120);
            let max_in_flight = std::env::var("REACHABILITY_AUTO_MAX_IN_FLIGHT")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .filter(|n| *n > 0)
                .unwrap_or(2);
            // Announced like every other sync loop: this one starts spending
            // inference the moment any namespace flips `auto_analyze`, so an
            // operator must be able to see from the log that it is running,
            // and with what budget, rather than inferring it from the
            // analyser being configured at all.
            tracing::info!(
                interval_secs,
                max_in_flight,
                "background reachability analysis enabled for namespaces with auto_analyze"
            );
            tokio::spawn(run_reachability_auto_loop(
                Arc::clone(&db),
                client,
                std::time::Duration::from_secs(interval_secs),
                sync_burst_interval,
                max_in_flight,
            ));
        }
    }
    if let Some(client) = osv.clone() {
        tokio::spawn(run_malicious_sync_loop(
            Arc::clone(&db),
            client,
            std::time::Duration::from_secs(malicious_sync_interval_secs),
            sync_burst_interval,
        ));
    }
    let state = AppState {
        db: Arc::clone(&db),
        storage: Arc::clone(&storage),
        signer,
        trees: Arc::new(Mutex::new(trees)),
        audit: Arc::new(AuditLogger::new()),
        dev_mode,
        storage_backend,
        dtrack: dtrack.clone(),
        dtrack_sync_interval_secs,
        osv,
        depsdev,
        reach,
    };

    if let Some(client) = dtrack {
        tokio::spawn(run_sync_loop(
            db,
            storage,
            client,
            std::time::Duration::from_secs(dtrack_sync_interval_secs),
            sync_burst_interval,
        ));
    }

    let app = create_router(state);
    let addr = std::env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind server address");
    tracing::info!(%addr, "magnolia listening");
    axum::serve(listener, app).await.expect("server failed");
}

/// Applies every migration in `migrations/` automatically at startup — no
/// one should ever need to `psql < migrations/....sql` by hand, on a fresh
/// database or an existing one. Idempotent and safe to run on every boot:
/// sqlx tracks applied versions in `_sqlx_migrations` and only executes
/// what's new.
///
/// One-time transition handling: this project's schema was previously
/// applied by hand (`docker-entrypoint-initdb.d` on fresh volumes, manual
/// `psql` on existing ones) with no `_sqlx_migrations` bookkeeping at all.
/// If that's what this database is — schema clearly present, tracking
/// table absent — every currently-known migration is recorded as already
/// applied (using sqlx's own checksums, not hand-rolled ones) without
/// re-executing its SQL, so the real `migrator.run()` below only ever
/// applies genuinely new migrations from this point on. A truly fresh
/// database has neither table, so this block is skipped entirely and
/// `run()` just applies everything itself.
async fn run_migrations(pool: &sqlx::PgPool) {
    let migrator = sqlx::migrate!("../../migrations");

    let schema_predates_tracking: bool = sqlx::query_scalar(
        r#"
        SELECT to_regclass('public.merkle_leaves') IS NOT NULL
           AND to_regclass('public._sqlx_migrations') IS NULL
        "#,
    )
    .fetch_one(pool)
    .await
    .unwrap_or(false);

    if schema_predates_tracking {
        tracing::warn!(
            "existing schema found with no migration history — recording it as already applied"
        );
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS _sqlx_migrations (
                version BIGINT PRIMARY KEY,
                description TEXT NOT NULL,
                installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
                success BOOLEAN NOT NULL,
                checksum BYTEA NOT NULL,
                execution_time BIGINT NOT NULL
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("failed to create migration history table");

        for m in migrator.migrations.iter() {
            sqlx::query(
                "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
                 VALUES ($1, $2, TRUE, $3, 0)
                 ON CONFLICT (version) DO NOTHING",
            )
            .bind(m.version)
            .bind(m.description.as_ref())
            .bind(m.checksum.as_ref())
            .execute(pool)
            .await
            .expect("failed to backfill migration history");
        }
    }

    migrator
        .run(pool)
        .await
        .expect("failed to run database migrations");
}

/// If `BOOTSTRAP_SUPER_ADMIN_KEY` is set, ensure that exact key exists as a
/// super_admin key (creating its tenant from `BOOTSTRAP_TENANT_DOMAIN`/
/// `BOOTSTRAP_TENANT_NAME` if needed), so a fresh environment is usable
/// without a manual SQL bootstrap step. This is the only way to get a first
/// key into a new deployment; every key after that is self-service.
///
/// Accepts both token shapes (see `magnolia_auth::ApiKeyToken`): the
/// current `mag_<secret>`, and the legacy `<key_id>:<secret>`. Idempotent
/// either way — a `mag_` token is matched by its hash (possible only
/// because hashes are deterministic now; see `lookup_api_key_by_hash`),
/// a legacy one by its embedded key_id. Never overwrites an existing key.
async fn bootstrap_super_admin_from_env(db: &Database) {
    let Ok(full_key) = std::env::var("BOOTSTRAP_SUPER_ADMIN_KEY") else {
        return;
    };
    let full_key = full_key.trim();
    // Explicitly-empty is "no bootstrap key configured", not an error --
    // that's what `${BOOTSTRAP_SUPER_ADMIN_KEY:-}` expands to when the
    // operator hasn't set one, and a fresh deployment should fail closed
    // (no key) rather than fall back to any built-in default.
    if full_key.is_empty() {
        return;
    }

    let Some(token) = magnolia_auth::ApiKeyToken::parse(full_key) else {
        tracing::warn!(
            "BOOTSTRAP_SUPER_ADMIN_KEY must be `mag_<secret>` (or a legacy `<key_id>:<secret>`); ignoring"
        );
        return;
    };

    // The only path where a *human* supplies an API-key secret -- every
    // other key comes from `GeneratedKey::new`'s CSPRNG. Key hashes are
    // unsalted SHA-256 (see `ApiKey::hash`'s doc comment for why that is
    // safe for high-entropy secrets), so a short or guessable value here
    // *would* be brute-forceable from a database dump, unlike a generated
    // one. Warn rather than reject, so an upgrade can't brick an existing
    // deployment over a key that was already working.
    const MIN_BOOTSTRAP_SECRET_LEN: usize = 32;
    let entropy_bearing = match &token {
        magnolia_auth::ApiKeyToken::Prefixed { .. } => {
            full_key.len() - magnolia_auth::KEY_PREFIX.len()
        }
        magnolia_auth::ApiKeyToken::Legacy { secret, .. } => secret.len(),
    };
    if entropy_bearing < MIN_BOOTSTRAP_SECRET_LEN {
        tracing::warn!(
            length = entropy_bearing,
            minimum = MIN_BOOTSTRAP_SECRET_LEN,
            "BOOTSTRAP_SUPER_ADMIN_KEY's secret is short enough to be brute-forceable from a \
             database dump — generate one with `cargo run -p magnolia-auth --example bootstrap_key`"
        );
    }

    // Resolve the row this token would occupy: whether it already exists,
    // the id to insert under if it doesn't, and the hash to store.
    let (key_id, key_hash, key_exists) = match &token {
        magnolia_auth::ApiKeyToken::Prefixed { key_hash } => {
            match db.lookup_api_key_by_hash(key_hash).await {
                // A `mag_` token carries no id, so on first insert we mint
                // one; on later startups the existing row is found by hash
                // and this generated id is simply unused.
                Ok(existing) => (
                    existing.as_ref().map(|r| r.id).unwrap_or_else(uuid::Uuid::new_v4),
                    key_hash.clone(),
                    existing.is_some(),
                ),
                Err(e) => {
                    tracing::warn!(error = %e, "failed to check for existing bootstrap key; skipping bootstrap");
                    return;
                }
            }
        }
        magnolia_auth::ApiKeyToken::Legacy { key_id, secret } => {
            let exists = match db.lookup_api_key(*key_id).await {
                Ok(existing) => existing.is_some(),
                Err(e) => {
                    tracing::warn!(error = %e, "failed to check for existing bootstrap key; skipping bootstrap");
                    return;
                }
            };
            let hashed = match (magnolia_auth::ApiKey {
                key: secret.clone(),
                created_at: chrono::Utc::now(),
            })
            .hash()
            {
                Ok(h) => h.hash,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to hash bootstrap key; skipping bootstrap");
                    return;
                }
            };
            (*key_id, hashed, exists)
        }
    };

    let domain = std::env::var("BOOTSTRAP_TENANT_DOMAIN")
        .unwrap_or_else(|_| "test.example".to_string());
    let name = std::env::var("BOOTSTRAP_TENANT_NAME")
        .unwrap_or_else(|_| "Bootstrap Test Tenant".to_string());

    // Ensure the tenant exists and is marked as the platform tenant on
    // every startup — not just the first — so an environment that had this
    // bootstrap key from before `is_platform` was introduced gets upgraded
    // instead of silently staying non-platform forever.
    let tenant_id = match db.get_tenant_by_domain(&domain).await {
        Ok(Some(t)) => {
            if !t.is_platform {
                if let Err(e) = db.mark_tenant_platform(t.id).await {
                    tracing::warn!(error = %e, "failed to mark bootstrap tenant as platform");
                }
            }
            t.id
        }
        Ok(None) => {
            let id = uuid::Uuid::new_v4();
            if let Err(e) = db.insert_tenant(id, &domain, &name, "bootstrap-env", true).await {
                tracing::warn!(error = %e, "failed to create bootstrap tenant; skipping bootstrap");
                return;
            }
            id
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to look up bootstrap tenant; skipping bootstrap");
            return;
        }
    };

    if key_exists {
        tracing::info!(%key_id, "bootstrap super_admin key already exists; skipping key creation");
        return;
    }

    if let Err(e) = db
        .insert_api_key(key_id, tenant_id, &domain, "/", "super_admin", &key_hash, None)
        .await
    {
        tracing::warn!(error = %e, "failed to insert bootstrap super_admin key");
        return;
    }

    tracing::warn!(
        %key_id,
        domain,
        "bootstrapped super_admin key from BOOTSTRAP_SUPER_ADMIN_KEY — treat this value as a \
         production credential: it grants full platform super_admin access"
    );
}

fn ensure_signing_key(path: &str) {
    if std::path::Path::new(path).exists() {
        return;
    }
    let key = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    std::fs::write(path, key).expect("failed to write signing key file");
    tracing::warn!(
        path,
        "generated a new local signing key; keep it safe (MVP only, move to KMS before production)"
    );
}