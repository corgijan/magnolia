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
    pub require_semver_version: bool,
    pub reputation_disabled: bool,
    pub require_namespace_registration: bool,
}

/// One registered namespace — the output of `list_registered_namespaces`,
/// and the input side of `create_namespace` (minus `created_at`, filled by
/// the DB).
#[derive(Debug, Clone, FromRow)]
pub struct RegisteredNamespaceRecord {
    pub namespace: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
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
    /// Registry identity derived from `purl` via
    /// `magnolia_core::purl_to_depsdev_package` — `None` when there's no
    /// purl, or its type isn't one deps.dev tracks. Stored so the
    /// reputation background job can join on it in SQL.
    pub ecosystem: Option<String>,
    pub registry_name: Option<String>,
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

/// One manifest in one namespace's upload history — the output of
/// `list_manifest_versions_in_namespace`, backing the diff UI's version
/// picker.
#[derive(Debug, Clone, FromRow)]
pub struct ManifestVersionRow {
    pub manifest_hash: String,
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
}

/// One manifest's indexed component, without the manifest-context columns
/// `SbomComponentSearchRow` carries — used by `manifest_diff` to fetch
/// exactly two manifests' component lists for comparison, not to search
/// across the whole archive.
#[derive(Debug, Clone, FromRow)]
pub struct SbomComponentRow {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub is_primary: bool,
}

/// A distinct (ecosystem, registry_name) pair from `sbom_components` that
/// either has no `component_reputation` row yet or has a stale one — the
/// output of `list_components_needing_reputation`, consumed by the
/// reputation background job.
#[derive(Debug, Clone, FromRow)]
pub struct ComponentIdentity {
    pub ecosystem: String,
    pub registry_name: String,
    /// One concrete version of this package known to the archive — deps.dev
    /// has no version-less "get this package's project" call, `GetVersion`
    /// needs a specific version to resolve `relatedProjects` from. Any known
    /// version works equally well for this purpose: a Scorecard result is a
    /// per-project signal, not per-version (see `component_reputation`'s
    /// migration comment), so which one is picked doesn't affect the result.
    pub sample_version: String,
}

/// Deployment-wide reputation-check summary — the output of
/// `reputation_status`, surfaced in the Settings UI so an operator can tell
/// "nothing pending, nothing checked yet either" (a fresh deployment, or one
/// where no manifest has any purl-bearing component) apart from "checked,
/// just nothing found."
#[derive(Debug, Clone, FromRow)]
pub struct ReputationStatus {
    /// Distinct (ecosystem, registry_name) pairs with no fresh
    /// `component_reputation` row — what the background job still has left
    /// to do, same definition `list_components_needing_reputation` uses.
    pub pending: i64,
    /// `component_reputation` rows with no `fetch_error` — checked
    /// successfully, regardless of whether a scorecard was actually found.
    pub checked: i64,
    /// `component_reputation` rows with a `fetch_error` — checked, but the
    /// attempt itself failed (network, unexpected response shape).
    pub failed: i64,
}

/// One component's cached deps.dev/OpenSSF Scorecard result — the output of
/// `upsert_component_reputation` reads and `list_reputation_for_manifest`.
#[derive(Debug, Clone, FromRow)]
pub struct ComponentReputationRecord {
    pub component_name: String,
    pub component_version: Option<String>,
    pub ecosystem: String,
    pub registry_name: String,
    pub scorecard_score: Option<f32>,
    pub project_repo: Option<String>,
    /// `None` means the reputation background job hasn't reached this
    /// component yet ("pending"), not an error — distinct from a fetch that
    /// ran and found nothing (`checked_at: Some`, `scorecard_score: None`,
    /// `fetch_error: None`) or one that failed (`fetch_error: Some`).
    pub checked_at: Option<DateTime<Utc>>,
    pub fetch_error: Option<String>,
}

/// One package's cached score, deployment-wide (not scoped to any one
/// manifest) — the output of `list_all_reputation`, backing the Settings
/// page's "all scored packages" aggregation modal.
#[derive(Debug, Clone, FromRow)]
pub struct ComponentReputationSummaryRow {
    pub ecosystem: String,
    pub name: String,
    pub scorecard_score: f32,
    pub project_repo: Option<String>,
    pub checked_at: DateTime<Utc>,
}

/// One confirmed-malicious match for a manifest's component, found via a
/// batched OSV query at upload time — the input side of
/// `insert_malicious_findings`.
#[derive(Debug, Clone)]
pub struct NewMaliciousFinding {
    pub component_name: String,
    pub component_version: Option<String>,
    pub purl: Option<String>,
    pub osv_id: String,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct MaliciousFindingRecord {
    pub component_name: String,
    pub component_version: Option<String>,
    pub purl: Option<String>,
    pub osv_id: String,
    pub summary: Option<String>,
    pub detected_at: DateTime<Utc>,
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
    /// dtrack's own component/vulnerability UUIDs — see the
    /// `dtrack_finding_uuids` migration comment.
    pub component_uuid: String,
    pub vulnerability_uuid: String,
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
    pub vex_comment: Option<String>,
    pub triaged_by: Option<String>,
    pub triaged_at: Option<DateTime<Utc>>,
    /// `None` for findings cached before the `dtrack_finding_uuids`
    /// migration, until their next sync refresh — a triage push to dtrack
    /// skips a finding without these rather than erroring.
    pub component_uuid: Option<String>,
    pub vulnerability_uuid: Option<String>,
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
    pub vex_comment: Option<String>,
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
