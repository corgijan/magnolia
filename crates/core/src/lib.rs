mod merkle;
mod manifest;
mod errors;
mod schema_validation;
mod dsse;
mod keys;
mod compliance;
mod component_index;

pub use merkle::{
    ConsistencyProof, InclusionProof, MerkleNode, MerkleTree, PeakProof, ProofStep,
};
pub use manifest::SbomFormat;
pub use errors::CoreError;
pub use schema_validation::validate_sbom_schema;
pub use compliance::{
    profile_by_id, registered_profiles, ComplianceProfile, ComplianceReport,
};
pub use component_index::{extract_components, ExtractedComponent};
pub use dsse::{
    build_envelope, pae, DocumentPredicate, DocumentStatement, DsseEnvelope, DsseSignature,
    ManifestPredicate, ManifestStatement, SnapshotPredicate, SnapshotStatement, Statement,
    Subject, DOCUMENT_PREDICATE_TYPE, DSSE_PAYLOAD_TYPE, IN_TOTO_STATEMENT_TYPE,
    MANIFEST_PREDICATE_TYPE, SNAPSHOT_PREDICATE_TYPE,
};
pub use keys::{ed25519_public_key_base64, ed25519_public_key_pem};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub frontier: Vec<Vec<u8>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl SignedTreeHead {
    pub fn new(
        tree_size: u64,
        root_hash: Vec<u8>,
        frontier: Vec<Vec<u8>>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            tree_size,
            root_hash,
            frontier,
            signature,
            created_at: chrono::Utc::now(),
        }
    }

    /// Canonical byte representation signed by the Signer:
    /// `tree_size` (8 bytes big-endian) followed by `root_hash`.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(8 + self.root_hash.len());
        payload.extend_from_slice(&self.tree_size.to_be_bytes());
        payload.extend_from_slice(&self.root_hash);
        payload
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleLeaf {
    pub seq_id: i64,
    pub tenant_id: uuid::Uuid,
    pub sbom_s3_key: String,
    pub leaf_hash: Vec<u8>,
    pub status: LeafStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LeafStatus {
    #[serde(rename = "pending_lock")]
    PendingLock,
    #[serde(rename = "locked")]
    Locked,
}

impl std::fmt::Display for LeafStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeafStatus::PendingLock => write!(f, "pending_lock"),
            LeafStatus::Locked => write!(f, "locked"),
        }
    }
}