use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct SignedTreeHeadRecord {
    pub tenant_id: uuid::Uuid,
    pub tree_size: i64,
    pub root_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub frontier: Vec<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct MerkleLeafRecord {
    pub seq_id: i64,
    pub tenant_id: uuid::Uuid,
    pub tenant_leaf_index: i64,
    pub namespace: String,
    pub sbom_s3_key: String,
    pub leaf_hash: Vec<u8>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub manifest_hash: Option<String>,
    pub revoked: bool,
    pub domain: String,
    pub version: Option<String>,
    pub document_type: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct TenantRecord {
    pub id: uuid::Uuid,
    pub domain: String,
    pub name: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub is_platform: bool,
    pub hidden: bool,
}

#[derive(Debug, Clone, FromRow)]
pub struct MerkleNodeRecord {
    pub level: i32,
    pub index: i64,
    pub hash: Vec<u8>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ApiKeyRecord {
    pub id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub domain: String,
    pub namespace_scope: String,
    pub role: String,
    pub key_hash: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

/// Deliberately independent of `magnolia_core::ExtractedComponent` — this
/// crate doesn't otherwise depend on `magnolia-core` (`insert_manifest`
/// etc. already take plain primitives, not core domain types), so callers
/// convert into this shape rather than `magnolia-db` picking up a new
/// cross-crate dependency for one struct.
#[derive(Debug, Clone)]
pub struct NewSbomComponent {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub is_primary: bool,
}

#[derive(Debug, Clone, FromRow)]
pub struct SbomComponentSearchRow {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub is_primary: bool,
    pub manifest_hash: String,
    pub namespace: String,
    pub release_version: String,
    pub revoked: bool,
    pub document_type: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ComplianceSettingRecord {
    pub tenant_id: uuid::Uuid,
    pub profile_id: String,
    pub enabled: bool,
    pub enforce_level: String,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct AuditLogRecord {
    pub id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub result: String,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ManifestRecord {
    pub manifest_hash: String,
    pub leaf_seq_id: i64,
    pub tenant_id: uuid::Uuid,
    pub version: String,
    // `sbom_hash`/`sbom_format` hold the hash/format of whatever was
    // uploaded, not necessarily an SBOM — SBOM-specific only when
    // `document_type` is None; otherwise they describe a general
    // technical-documentation upload (risk assessment, test report, etc.)
    // reusing the same content-hash/format columns rather than adding a
    // parallel set for a documentation-only rename.
    pub sbom_hash: String,
    pub sbom_format: String,
    pub sbom_s3_key: String,
    pub namespace: String,
    pub previous_manifest_hash: Option<String>,
    pub signature: Option<Vec<u8>>,
    pub dsse_envelope: Option<serde_json::Value>,
    pub document_type: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
}
