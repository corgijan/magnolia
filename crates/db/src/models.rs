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
    pub dtrack_sync_disabled: bool,
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

#[derive(Debug, Clone, FromRow)]
pub struct DtrackProjectRecord {
    pub manifest_hash: String,
    pub dtrack_project_uuid: uuid::Uuid,
    pub pushed_at: DateTime<Utc>,
    pub last_synced_at: Option<DateTime<Utc>>,
}

/// One finding as reported by dtrack, ready to insert/upsert into
/// `dtrack_findings` — the input side of `replace_dtrack_findings`.
#[derive(Debug, Clone)]
pub struct NewDtrackFinding {
    pub finding_key: String,
    pub component_name: String,
    pub component_version: Option<String>,
    pub vulnerability_id: String,
    pub severity: String,
    pub description: Option<String>,
    pub analysis_state: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct DtrackFindingRecord {
    pub manifest_hash: String,
    pub finding_key: String,
    pub component_name: String,
    pub component_version: Option<String>,
    pub vulnerability_id: String,
    pub severity: String,
    pub description: Option<String>,
    pub analysis_state: Option<String>,
    pub synced_at: DateTime<Utc>,
    pub vex_status: Option<String>,
    pub vex_justification: Option<String>,
    pub triaged_by: Option<String>,
    pub triaged_at: Option<DateTime<Utc>>,
}

/// A finding plus enough manifest context (namespace/version/revoked) to
/// place it in the archive — used by the cross-manifest findings list
/// (`GET /api/v1/findings`), unlike `DtrackFindingRecord` which is always
/// scoped to one already-known manifest.
#[derive(Debug, Clone, FromRow)]
pub struct DtrackFindingWithContextRecord {
    pub manifest_hash: String,
    pub finding_key: String,
    pub component_name: String,
    pub component_version: Option<String>,
    pub vulnerability_id: String,
    pub severity: String,
    pub description: Option<String>,
    pub analysis_state: Option<String>,
    pub synced_at: DateTime<Utc>,
    pub vex_status: Option<String>,
    pub vex_justification: Option<String>,
    pub triaged_by: Option<String>,
    pub triaged_at: Option<DateTime<Utc>>,
    pub namespace: String,
    pub release_version: String,
    pub revoked: bool,
    pub comment_count: i64,
}

/// One entry in a finding's discussion thread — `author` is always the
/// calling principal (`AuthGrant::principal()`, i.e. the API key), matching
/// how `triaged_by` is populated, since there is no separate human-identity
/// concept in Magnolia's auth model.
#[derive(Debug, Clone, FromRow)]
pub struct FindingCommentRecord {
    pub id: uuid::Uuid,
    pub manifest_hash: String,
    pub finding_key: String,
    pub author: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
}

/// The most recent reason a manifest's push to dtrack failed — only
/// present while the manifest has never successfully synced (see
/// `dtrack_sync::push_phase`, which clears this row as soon as a push
/// succeeds).
#[derive(Debug, Clone, FromRow)]
pub struct DtrackPushFailureRecord {
    pub manifest_hash: String,
    pub error: String,
    pub failed_at: DateTime<Utc>,
}
