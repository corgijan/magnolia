use std::collections::HashMap;
use std::sync::Arc;

use sbomstash_api::{create_router, AppState};
use sbomstash_audit::AuditLogger;
use sbomstash_core::MerkleTree;
use sbomstash_db::Database;
use sbomstash_signer::LocalFileSigner;
use sbomstash_storage::{InMemoryStore, ObjectStore};
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

    bootstrap_super_admin_from_env(&db).await;

    let key_path = std::env::var("SIGNING_KEY_PATH")
        .unwrap_or_else(|_| ".sbomstash_key".to_string());
    ensure_signing_key(&key_path);
    let signer = Arc::new(LocalFileSigner::new(std::path::PathBuf::from(&key_path)));

    let storage: Arc<dyn ObjectStore> = Arc::new(InMemoryStore::new());

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

    let state = AppState {
        db: Arc::new(db),
        storage,
        signer,
        trees: Arc::new(Mutex::new(trees)),
        audit: Arc::new(AuditLogger::new()),
    };

    let app = create_router(state);
    let addr = std::env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind server address");
    tracing::info!(%addr, "sbomstash listening");
    axum::serve(listener, app).await.expect("server failed");
}

/// Dev/test convenience: if `BOOTSTRAP_SUPER_ADMIN_KEY=<key_id>:<secret>` is
/// set, ensure that exact key exists as a super_admin key (creating its
/// tenant from `BOOTSTRAP_TENANT_DOMAIN`/`BOOTSTRAP_TENANT_NAME` if needed),
/// so a fresh environment (e.g. `docker compose up`) is immediately usable
/// without a manual SQL bootstrap step. Idempotent — does nothing if the
/// key_id already exists. Never overwrites an existing key.
async fn bootstrap_super_admin_from_env(db: &Database) {
    let Ok(full_key) = std::env::var("BOOTSTRAP_SUPER_ADMIN_KEY") else {
        return;
    };
    let Some((key_id_str, secret)) = full_key.split_once(':') else {
        tracing::warn!("BOOTSTRAP_SUPER_ADMIN_KEY must be <key_id>:<secret>; ignoring");
        return;
    };
    let Ok(key_id) = uuid::Uuid::parse_str(key_id_str) else {
        tracing::warn!(key_id = key_id_str, "BOOTSTRAP_SUPER_ADMIN_KEY key_id is not a valid UUID; ignoring");
        return;
    };

    match db.lookup_api_key(key_id).await {
        Ok(Some(_)) => {
            tracing::info!(%key_id, "bootstrap super_admin key already exists; skipping");
            return;
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(error = %e, "failed to check for existing bootstrap key; skipping bootstrap");
            return;
        }
    }

    let domain = std::env::var("BOOTSTRAP_TENANT_DOMAIN")
        .unwrap_or_else(|_| "test.example".to_string());
    let name = std::env::var("BOOTSTRAP_TENANT_NAME")
        .unwrap_or_else(|_| "Bootstrap Test Tenant".to_string());

    let tenant_id = match db.get_tenant_by_domain(&domain).await {
        Ok(Some(t)) => t.id,
        Ok(None) => {
            let id = uuid::Uuid::new_v4();
            if let Err(e) = db.insert_tenant(id, &domain, &name, "bootstrap-env").await {
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

    let hashed = match (sbomstash_auth::ApiKey {
        key: secret.to_string(),
        created_at: chrono::Utc::now(),
    })
    .hash()
    {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "failed to hash bootstrap key; skipping bootstrap");
            return;
        }
    };

    if let Err(e) = db
        .insert_api_key(key_id, tenant_id, &domain, "/", "super_admin", &hashed.hash, None)
        .await
    {
        tracing::warn!(error = %e, "failed to insert bootstrap super_admin key");
        return;
    }

    tracing::warn!(
        %key_id,
        domain,
        "bootstrapped super_admin key from BOOTSTRAP_SUPER_ADMIN_KEY env var — dev/test only, never set this in production"
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