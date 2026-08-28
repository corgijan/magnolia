use std::collections::HashMap;
use std::sync::Arc;

use magnolia_audit::AuditLogger;
use magnolia_core::MerkleTree;
use magnolia_db::Database;
use magnolia_depsdev::DepsDevClient;
use magnolia_dtrack::DtrackClient;
use magnolia_osv::OsvClient;
use magnolia_signer::Signer;
use magnolia_storage::ObjectStore;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Each tenant gets its own Merkle tree / signed-tree-head chain, so tenants
/// cannot see or infer anything about each other's data through the log.
pub struct AppState {
    pub db: Arc<Database>,
    pub storage: Arc<dyn ObjectStore>,
    pub signer: Arc<dyn Signer>,
    pub trees: Arc<Mutex<HashMap<Uuid, MerkleTree>>>,
    pub audit: Arc<AuditLogger>,
    /// From the `DEV_MODE` env var. Relaxes a small number of RBAC checks
    /// for local testing convenience (currently: who can revoke a
    /// manifest) — never set this in production.
    pub dev_mode: bool,
    /// Human-readable label for which `ObjectStore` impl is active
    /// ("file" or "in-memory") — surfaced via `GET /api/v1/config` so the
    /// UI can warn when uploads won't survive a restart. Not derived from
    /// `storage` itself since trait objects can't be introspected; set
    /// once at startup alongside the actual backend choice.
    pub storage_backend: &'static str,
    /// `None` means the optional Dependency-Track integration is off for
    /// this deployment (the `DTRACK_URL`/`DTRACK_API_KEY` env vars weren't
    /// both set at startup) — every dtrack-touching code path must treat
    /// this as "there is nothing to call," not an error.
    pub dtrack: Option<Arc<DtrackClient>>,
    /// The actual `DTRACK_SYNC_INTERVAL_SECS` the background sync loop was
    /// started with (or the same default it would use, when dtrack is
    /// disabled) — surfaced via `GET /api/v1/config` so the UI can tell a
    /// user "check back in about N minutes" instead of guessing a number.
    pub dtrack_sync_interval_secs: u64,
    /// `None` when `DISABLE_MALICIOUS_PACKAGE_CHECK` is set at startup —
    /// unlike `dtrack`, this is *on* by default (OSV's public API needs no
    /// setup/API key, unlike standing up a dtrack instance), so the opt-out
    /// is a disable flag rather than a presence-gated pair of env vars.
    /// Every osv-touching code path must treat `None` as "there is nothing
    /// to call," never as an error — same convention as `dtrack`.
    pub osv: Option<Arc<OsvClient>>,
    /// `None` when `DISABLE_REPUTATION_CHECK` is set at startup — same
    /// on-by-default/opt-out shape as `osv`. Stored on state (unlike the
    /// background loop's own copy, spawned separately in `main.rs`) so
    /// `force_reputation_sync` can run an on-demand pass from a request
    /// handler.
    pub depsdev: Option<Arc<DepsDevClient>>,
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            storage: Arc::clone(&self.storage),
            signer: Arc::clone(&self.signer),
            trees: Arc::clone(&self.trees),
            audit: Arc::clone(&self.audit),
            dev_mode: self.dev_mode,
            storage_backend: self.storage_backend,
            dtrack: self.dtrack.clone(),
            dtrack_sync_interval_secs: self.dtrack_sync_interval_secs,
            osv: self.osv.clone(),
            depsdev: self.depsdev.clone(),
        }
    }
}