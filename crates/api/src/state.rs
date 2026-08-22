use std::collections::HashMap;
use std::sync::Arc;

use magnolia_audit::AuditLogger;
use magnolia_core::MerkleTree;
use magnolia_db::Database;
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
        }
    }
}