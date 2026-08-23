use std::str::FromStr;

use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use magnolia_audit::{AuditLogEntry, AuditResult};
use magnolia_auth::{generate_server_key, Action, Role};
use magnolia_core::{
    build_envelope, ed25519_public_key_base64, ed25519_public_key_pem, pae, profile_by_id,
    registered_profiles, ComplianceReport as CoreComplianceReport, ConsistencyProof,
    DocumentPredicate, DocumentStatement, InclusionProof, ManifestPredicate, ManifestStatement,
    MerkleTree, SbomFormat, SignedTreeHead, Statement, Subject, DOCUMENT_PREDICATE_TYPE,
    DSSE_PAYLOAD_TYPE, IN_TOTO_STATEMENT_TYPE, MANIFEST_PREDICATE_TYPE,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::{require, AuthGrant};
use crate::errors::ApiError;
use crate::state::AppState;

const MAX_SBOM_BYTES: usize = 10 * 1024 * 1024;

// ---------- DTOs ----------

#[derive(serde::Serialize)]
pub struct TreeHeadJson {
    pub tree_size: u64,
    pub root_hash: String,
    pub signature: String,
    pub frontier: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub signature_verified: bool,
}

#[derive(serde::Serialize)]
pub struct UploadResponse {
    pub sbom_hash: String,
    pub manifest_hash: String,
    pub version: String,
    pub namespace: String,
    pub domain: String,
    pub tree_size: u64,
    pub leaf_index: u64,
    pub leaf_seq_id: i64,
    pub signed_tree_head: TreeHeadJson,
}

#[derive(serde::Serialize)]
pub struct LeafJson {
    pub seq_id: i64,
    pub leaf_index: u64,
    pub tenant_id: Uuid,
    pub namespace: String,
    pub sbom_s3_key: String,
    pub leaf_hash: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub manifest_hash: Option<String>,
    pub revoked: bool,
    pub domain: String,
    pub version: Option<String>,
    pub document_type: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ManifestJson {
    pub manifest_hash: String,
    pub leaf_seq_id: i64,
    pub tenant_id: Uuid,
    pub domain: String,
    pub version: String,
    pub sbom_hash: String,
    pub sbom_format: String,
    pub sbom_s3_key: String,
    pub namespace: String,
    pub previous_manifest_hash: Option<String>,
    /// Legacy hex-encoded signature — only populated for manifests signed
    /// before the DSSE migration. `None` for anything with `dsse_envelope`.
    pub signature: Option<String>,
    /// The canonical signed artifact for manifests signed after the DSSE
    /// migration. `None` for legacy manifests, which cannot be
    /// retroactively upgraded (no way to produce a new valid signature for
    /// old content without the original signing context).
    pub dsse_envelope: Option<serde_json::Value>,
    pub document_type: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub sbom_hex: String,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
    /// One report per compliance profile enabled for this tenant (empty
    /// when none are enabled, or when the enabled ones don't apply to this
    /// upload's format — e.g. a generic `document`).
    pub compliance: Vec<ComplianceReportJson>,
}

#[derive(serde::Serialize)]
pub struct ComplianceProfileJson {
    pub id: String,
    pub name: String,
}

#[derive(serde::Serialize)]
pub struct ComplianceSettingJson {
    pub profile_id: String,
    pub profile_name: String,
    pub enabled: bool,
    pub enforce_level: String,
}

#[derive(serde::Deserialize)]
pub struct SetComplianceSettingRequest {
    pub profile_id: String,
    pub enabled: bool,
    pub enforce_level: String,
}

#[derive(serde::Serialize, Clone)]
pub struct ComplianceReportJson {
    pub profile_id: String,
    pub profile_name: String,
    pub applicable: bool,
    pub meets_minimum: bool,
    pub minimum_issues: Vec<String>,
    pub fully_compliant: bool,
    pub missing_fields: Vec<String>,
}

impl From<CoreComplianceReport> for ComplianceReportJson {
    fn from(r: CoreComplianceReport) -> Self {
        Self {
            profile_id: r.profile_id,
            profile_name: r.profile_name,
            applicable: r.applicable,
            meets_minimum: r.meets_minimum,
            minimum_issues: r.minimum_issues,
            fully_compliant: r.fully_compliant,
            missing_fields: r.missing_fields,
        }
    }
}

#[derive(serde::Serialize)]
pub struct CurrentManifestJson {
    pub namespace: String,
    pub domain: String,
    pub version: String,
    pub manifest_hash: String,
    pub sbom_hash: String,
    pub sbom_format: String,
    pub created_at: DateTime<Utc>,
}

#[derive(serde::Deserialize)]
pub struct CreateKeyRequest {
    #[serde(default = "default_namespace_scope")]
    pub namespace_scope: String,
    pub role: String,
    pub expires_at: Option<String>,
    /// super_admin only: create this key for another tenant instead of
    /// your own.
    pub tenant_id: Option<Uuid>,
}

fn default_namespace_scope() -> String {
    "/".to_string()
}

#[derive(serde::Serialize)]
pub struct CreateKeyResponse {
    pub key: String,
    pub key_id: Uuid,
    pub tenant_id: Uuid,
    pub domain: String,
    pub namespace_scope: String,
    pub role: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(serde::Deserialize)]
pub struct CreateTenantRequest {
    pub domain: String,
    pub name: String,
}

#[derive(serde::Serialize)]
pub struct TenantJson {
    pub id: Uuid,
    pub domain: String,
    pub name: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub is_platform: bool,
}

#[derive(serde::Serialize)]
pub struct CreateTenantResponse {
    pub tenant: TenantJson,
    /// The tenant's first key (domain_admin, unrestricted namespace scope),
    /// shown once so the caller can bootstrap the rest of the tenant.
    pub initial_key: CreateKeyResponse,
}

#[derive(serde::Serialize)]
pub struct KeyJson {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub domain: String,
    pub namespace_scope: String,
    pub role: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(serde::Serialize)]
pub struct AuditJson {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub result: String,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(serde::Deserialize)]
pub struct LeavesQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub tenant_id: Option<Uuid>,
}

#[derive(serde::Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    pub limit: i64,
    pub tenant_id: Option<Uuid>,
}

fn default_limit() -> i64 {
    50
}

fn default_audit_limit() -> i64 {
    100
}

// ---------- helpers ----------

/// Query param accepted by every tenant-scoped read/manage endpoint: lets a
/// super_admin act on a tenant other than its own ("see and manage all
/// other tenants"). Anyone else supplying it is rejected outright.
#[derive(serde::Deserialize)]
pub struct TenantOverrideQuery {
    pub tenant_id: Option<Uuid>,
}

/// Resolves which tenant a request should act on: the grant's own tenant by
/// default, or an explicit override — only ever honored for a super_admin
/// key belonging to the platform/bootstrap tenant (`is_platform_tenant`).
/// A super_admin key self-minted by some other tenant's domain_admin does
/// NOT get this reach, even though the role string is the same — otherwise
/// any tenant could grant itself platform-wide access to every other
/// tenant just by creating a key with role="super_admin" for itself.
/// The second element is `true` when acting on a tenant other than the
/// grant's own, in which case the grant's `namespace_scope` does not apply
/// (there's no meaningful "my namespace scope" in someone else's tenant —
/// a cross-tenant super_admin sees/manages that tenant in full).
fn effective_tenant(grant: &AuthGrant, requested: Option<Uuid>) -> Result<(Uuid, bool), ApiError> {
    match requested {
        Some(id) if grant.role == Role::SuperAdmin && grant.is_platform_tenant => {
            Ok((id, id != grant.tenant_id))
        }
        Some(_) => Err(ApiError::Forbidden(
            "only the platform super_admin can act on another tenant".to_string(),
        )),
        None => Ok((grant.tenant_id, false)),
    }
}

fn db_err(e: impl std::fmt::Display) -> ApiError {
    ApiError::InternalError(e.to_string())
}

/// `created_by`/principal is `apikey:<full key_id uuid>` — the key_id, not
/// the secret, but still a stable per-key identifier we don't want handed
/// out in full to anyone with read access to a namespace. Only the last 5
/// characters ever leave the server; the rest is truncated here, not just
/// hidden client-side, so the full value never reaches the browser at all.
fn mask_principal(principal: &str) -> String {
    let tail_len = 5.min(principal.len());
    format!("…{}", &principal[principal.len() - tail_len..])
}

fn normalize_namespace(raw: &str) -> Result<String, ApiError> {
    let mut ns = raw.trim().to_lowercase();
    if ns.contains("..") {
        return Err(ApiError::BadRequest(
            "namespace must not contain '..'".to_string(),
        ));
    }
    if !ns.starts_with('/') {
        ns.insert(0, '/');
    }
    while ns.len() > 1 && ns.ends_with('/') {
        ns.pop();
    }
    let cleaned: Vec<&str> = ns.split("//").collect();
    ns = cleaned.join("/");
    if ns.is_empty() {
        ns = "/".to_string();
    }
    Ok(ns)
}

fn normalize_domain(raw: &str) -> Result<String, ApiError> {
    let domain = raw.trim().to_lowercase();
    if domain.is_empty() {
        return Err(ApiError::BadRequest("domain must not be empty".to_string()));
    }
    Ok(domain)
}

/// Validates the uploaded bytes are a genuinely well-formed CycloneDX or
/// SPDX document (real JSON Schema validation against the official spec,
/// not just "valid JSON with the right marker field") — see
/// `magnolia_core::validate_sbom_schema`.
fn validate_sbom_content(data: &[u8], format: &str) -> Result<(), ApiError> {
    let sbom_format = match format {
        "cyclonedx" => SbomFormat::CycloneDx,
        "spdx" => SbomFormat::Spdx,
        other => {
            return Err(ApiError::BadRequest(format!(
                "unsupported format: {} (use cyclonedx or spdx)",
                other
            )))
        }
    };
    magnolia_core::validate_sbom_schema(data, sbom_format).map_err(|e| ApiError::BadRequest(e.to_string()))
}

/// Rejects an upload at the door when a compliance profile is enforced for
/// this tenant and the SBOM doesn't meet the configured bar. Runs after
/// schema validation (so `check()` can assume well-formed JSON) and after
/// the RBAC upload check (so an unauthorized caller learns nothing about
/// tenant policy), but before any side effect — storage write, Merkle
/// mutation, DB insert — so a rejection here leaves nothing to clean up.
async fn enforce_compliance(state: &AppState, tenant_id: Uuid, format: &str, sbom_bytes: &[u8]) -> Result<(), ApiError> {
    for profile in registered_profiles() {
        let Some(setting) = state.db.get_compliance_setting(tenant_id, profile.id()).await.map_err(db_err)? else {
            continue;
        };
        if !setting.enabled || setting.enforce_level == "off" {
            continue;
        }
        let report = profile.check(format, sbom_bytes);
        if !report.applicable {
            continue;
        }
        if !report.meets_minimum {
            return Err(ApiError::BadRequest(format!(
                "upload rejected: does not meet {} minimum compliance: {}",
                profile.name(),
                report.minimum_issues.join("; ")
            )));
        }
        if setting.enforce_level == "full" && !report.fully_compliant {
            return Err(ApiError::BadRequest(format!(
                "upload rejected: does not meet {} full compliance, missing: {}",
                profile.name(),
                report.missing_fields.join("; ")
            )));
        }
    }
    Ok(())
}

async fn record_audit(
    state: &AppState,
    grant: &AuthGrant,
    action: &str,
    resource: &str,
    success: bool,
    reason: Option<String>,
) {
    let entry = if success {
        AuditLogEntry::success(
            grant.tenant_id,
            grant.principal(),
            action.to_string(),
            resource.to_string(),
            reason,
        )
    } else {
        AuditLogEntry::failure(
            grant.tenant_id,
            grant.principal(),
            action.to_string(),
            resource.to_string(),
            reason.unwrap_or_default(),
        )
    };
    let result_str = match entry.result {
        AuditResult::Success => "success",
        AuditResult::Failure => "failure",
    };
    state.audit.log(entry.clone());
    if let Err(e) = state
        .db
        .insert_audit_log(
            entry.id,
            entry.tenant_id,
            &entry.principal,
            &entry.action,
            &entry.resource,
            result_str,
            entry.reason.as_deref(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to persist audit log entry");
    }
}

fn sth_to_json(sth: &SignedTreeHead, verified: bool) -> TreeHeadJson {
    TreeHeadJson {
        tree_size: sth.tree_size,
        root_hash: hex::encode(&sth.root_hash),
        signature: hex::encode(&sth.signature),
        frontier: sth.frontier.iter().map(|h| hex::encode(h)).collect(),
        created_at: sth.created_at,
        signature_verified: verified,
    }
}

// ---------- handlers ----------

pub async fn health() -> StatusCode {
    StatusCode::OK
}

#[derive(serde::Serialize)]
pub struct WhoAmIJson {
    pub key_id: Uuid,
    pub tenant_id: Uuid,
    pub domain: String,
    pub namespace_scope: String,
    pub role: String,
    /// Whether this key's tenant is the platform tenant — only then can it
    /// pass `?tenant_id=` to act on another tenant. The UI uses this to
    /// decide whether to offer that at all (the backend enforces it
    /// independently either way).
    pub is_platform_tenant: bool,
}

/// Confirms the caller's key is authenticated (not revoked/expired,
/// verified against its hash) without requiring any specific RBAC action —
/// every valid key can see its own identity. Used by the frontend to gate
/// access to the rest of the UI.
pub async fn whoami(grant: AuthGrant) -> Json<WhoAmIJson> {
    Json(WhoAmIJson {
        key_id: grant.key_id,
        tenant_id: grant.tenant_id,
        domain: grant.domain,
        namespace_scope: grant.namespace_scope,
        role: grant.role.to_string(),
        is_platform_tenant: grant.is_platform_tenant,
    })
}

#[derive(serde::Serialize)]
pub struct ConfigJson {
    pub storage_backend: String,
    pub signer_backend: String,
    pub dev_mode: bool,
}

/// Server-operational info, not tenant data — safe for any authenticated
/// key to see (no RBAC action required, same as `whoami`). Deliberately
/// excludes anything sensitive like file paths or connection strings;
/// exists so the UI can warn when running against a non-durable dev setup
/// (e.g. in-memory storage) rather than a silent trap.
pub async fn config(State(state): State<AppState>, _grant: AuthGrant) -> Json<ConfigJson> {
    Json(ConfigJson {
        storage_backend: state.storage_backend.to_string(),
        signer_backend: "local_file".to_string(),
        dev_mode: state.dev_mode,
    })
}

#[derive(serde::Serialize)]
pub struct SigningKeyJson {
    pub algorithm: String,
    pub keyid: String,
    pub public_key_base64: String,
    pub public_key_pem: String,
}

/// Exposes the signing public key so DSSE-signed manifests can be verified
/// by third-party tooling (`cosign verify-blob-attestation`, `openssl
/// pkeyutl -verify -rawin`, etc.) without trusting Magnolia's own
/// verification code. Same auth tier as `config`/`whoami`: any valid key,
/// no RBAC action — server-operational material, not tenant data.
pub async fn signing_key(
    State(state): State<AppState>,
    _grant: AuthGrant,
) -> Result<Json<SigningKeyJson>, ApiError> {
    let raw = state
        .signer
        .public_key()
        .await
        .map_err(|e| ApiError::InternalError(format!("public key lookup failed: {}", e)))?;
    Ok(Json(SigningKeyJson {
        algorithm: "ed25519".to_string(),
        keyid: hex::encode(Sha256::digest(&raw)),
        public_key_base64: ed25519_public_key_base64(&raw),
        public_key_pem: ed25519_public_key_pem(&raw).map_err(|e| ApiError::InternalError(e.to_string()))?,
    }))
}

pub async fn upload_sbom(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, ApiError> {
    let field = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::BadRequest("invalid multipart body".to_string()))?
        .ok_or_else(|| ApiError::BadRequest("missing sbom_file field".to_string()))?;
    let _file_name = field.file_name().map(|s| s.to_string());
    let sbom_bytes = field
        .bytes()
        .await
        .map_err(|_| ApiError::BadRequest("invalid sbom_file field".to_string()))?
        .to_vec();

    let mut format = "cyclonedx".to_string();
    let mut namespace = "/".to_string();
    let mut version = String::new();
    let mut document_type = String::new();
    while let Some(next) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::BadRequest("invalid multipart body".to_string()))?
    {
        match next.name() {
            Some("format") => format = next
                .text()
                .await
                .map_err(|_| ApiError::BadRequest("invalid format field".to_string()))?
                .to_lowercase(),
            Some("namespace") => namespace = next
                .text()
                .await
                .map_err(|_| ApiError::BadRequest("invalid namespace field".to_string()))?
                .to_string(),
            Some("version") => version = next
                .text()
                .await
                .map_err(|_| ApiError::BadRequest("invalid version field".to_string()))?
                .trim()
                .to_string(),
            Some("document_type") => document_type = next
                .text()
                .await
                .map_err(|_| ApiError::BadRequest("invalid document_type field".to_string()))?
                .trim()
                .to_string(),
            _ => {}
        }
    }

    let namespace = normalize_namespace(&namespace)?;
    if version.is_empty() {
        return Err(ApiError::BadRequest("version is required".to_string()));
    }

    if sbom_bytes.is_empty() {
        return Err(ApiError::BadRequest("sbom_file is empty".to_string()));
    }
    if sbom_bytes.len() > MAX_SBOM_BYTES {
        return Err(ApiError::BadRequest(
            "sbom_file exceeds 10 MiB limit".to_string(),
        ));
    }
    if !matches!(format.as_str(), "cyclonedx" | "spdx" | "document") {
        return Err(ApiError::BadRequest(format!(
            "unsupported format: {} (use cyclonedx, spdx, or document)",
            format
        )));
    }
    if format == "document" && document_type.is_empty() {
        return Err(ApiError::BadRequest(
            "document_type is required when format=document".to_string(),
        ));
    }
    if format != "document" {
        validate_sbom_content(&sbom_bytes, &format)?;
    }

    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    // Cross-tenant uploads are only reachable at all if `effective_tenant`
    // already proved this is the platform super_admin — that implies full
    // access to the target tenant, so the grant's own namespace_scope
    // (which describes ITS tenant, not the target's) doesn't apply. Normal
    // same-tenant uploads still go through the regular RBAC/scope check.
    if !cross_tenant {
        if let Err(e) = require(&grant, Action::Upload, &namespace) {
            let _ = record_audit(
                &state,
                &grant,
                "upload",
                &format!("{}:{}", grant.domain, namespace),
                false,
                Some(e.to_string()),
            )
            .await;
            return Err(e);
        }
    }

    if format != "document" {
        enforce_compliance(&state, tenant_id, &format, &sbom_bytes).await?;
    }

    let target_tenant = if cross_tenant {
        Some(
            state
                .db
                .get_tenant(tenant_id)
                .await
                .map_err(db_err)?
                .ok_or_else(|| ApiError::BadRequest("unknown tenant_id".to_string()))?,
        )
    } else {
        None
    };

    // The platform tenant exists to hold the bootstrap/admin key that
    // manages every other tenant — it's not a product tenant, and letting
    // real SBOM data accumulate there defeats the "keep it clean and
    // administrative only" separation the whole multi-tenancy model relies
    // on. Blocked unconditionally, even for the platform super_admin.
    let is_platform_target = if cross_tenant {
        target_tenant.as_ref().map(|t| t.is_platform).unwrap_or(false)
    } else {
        grant.is_platform_tenant
    };
    if is_platform_target {
        return Err(ApiError::BadRequest(
            "uploads are not allowed to the platform tenant".to_string(),
        ));
    }

    let domain = if cross_tenant {
        target_tenant.map(|t| t.domain).unwrap_or_default()
    } else {
        grant.domain.clone()
    };

    let sbom_hash = hex::encode(Sha256::digest(&sbom_bytes));
    let s3_key = format!("tenants/{}/sboms/{}.sbom", tenant_id, sbom_hash);

    state
        .storage
        .put(&s3_key, &sbom_bytes)
        .await
        .map_err(|e| ApiError::InternalError(format!("storage put failed: {}", e)))?;

    let (leaf_hash, tree_size, tenant_leaf_index, sth) = {
        let mut trees = state.trees.lock().await;
        let tree = trees.entry(tenant_id).or_insert_with(MerkleTree::new);
        let leaf_hash = tree.add_leaf(&sbom_bytes);
        let tree_size = tree.tree_size();
        let mut sth = SignedTreeHead::new(
            tree_size,
            tree.root_hash().to_vec(),
            tree.frontier_hashes(),
            Vec::new(),
        );
        let signature = state
            .signer
            .sign(&sth.signing_payload())
            .await
            .map_err(|e| ApiError::InternalError(format!("signing failed: {}", e)))?;
        sth.signature = signature;
        (leaf_hash, tree_size, (tree_size - 1) as i64, sth)
    };

    let leaf_seq_id = state
        .db
        .insert_merkle_leaf(
            tenant_id,
            tenant_leaf_index,
            &namespace,
            &s3_key,
            &leaf_hash,
            "locked",
        )
        .await
        .map_err(db_err)?;

    state
        .db
        .insert_signed_tree_head(
            tenant_id,
            tree_size as i64,
            &sth.root_hash,
            &sth.signature,
            &sth.frontier,
        )
        .await
        .map_err(db_err)?;

    let previous = state.db.latest_manifest(tenant_id).await.map_err(db_err)?;
    let previous_manifest_hash = previous.as_ref().map(|m| m.manifest_hash.clone());

    let manifest_created_at = Utc::now();

    // The in-toto Statement's subject digest is the SAME sbom_hash already
    // fed to tree.add_leaf() above — this is what makes DSSE verification
    // also a structural binding check between "this metadata" and "this
    // exact SBOM content", not just a signature over arbitrary bytes.
    //
    // Documents reuse the exact same Statement/PAE/sign/envelope pipeline
    // as SBOM manifests, just with a different predicate shape and type —
    // everything from here down operates only on `statement_bytes`.
    let document_type_opt = if format == "document" {
        Some(document_type.as_str())
    } else {
        None
    };
    let statement_bytes = if let Some(document_type) = document_type_opt {
        let statement: DocumentStatement = Statement {
            statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
            subject: vec![Subject {
                name: format!("{}{}@{}", domain, namespace, version),
                digest: [("sha256".to_string(), sbom_hash.clone())].into_iter().collect(),
            }],
            predicate_type: DOCUMENT_PREDICATE_TYPE.to_string(),
            predicate: DocumentPredicate {
                document_type: document_type.to_string(),
                version: version.clone(),
                namespace: namespace.clone(),
                previous_manifest_hash: previous_manifest_hash.clone(),
                created_by: grant.principal(),
                created_at: manifest_created_at,
                tenant_id,
            },
        };
        serde_json::to_vec(&statement).map_err(|e| ApiError::InternalError(e.to_string()))?
    } else {
        let statement: ManifestStatement = Statement {
            statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
            subject: vec![Subject {
                name: format!("{}{}@{}", domain, namespace, version),
                digest: [("sha256".to_string(), sbom_hash.clone())].into_iter().collect(),
            }],
            predicate_type: MANIFEST_PREDICATE_TYPE.to_string(),
            predicate: ManifestPredicate {
                version: version.clone(),
                namespace: namespace.clone(),
                previous_manifest_hash: previous_manifest_hash.clone(),
                sbom_format: format.clone(),
                created_by: grant.principal(),
                created_at: manifest_created_at,
                tenant_id,
            },
        };
        serde_json::to_vec(&statement).map_err(|e| ApiError::InternalError(e.to_string()))?
    };

    let pae_bytes = pae(DSSE_PAYLOAD_TYPE, &statement_bytes);
    let raw_signature = state
        .signer
        .sign(&pae_bytes)
        .await
        .map_err(|e| ApiError::InternalError(format!("manifest signing failed: {}", e)))?;
    let public_key = state
        .signer
        .public_key()
        .await
        .map_err(|e| ApiError::InternalError(format!("public key lookup failed: {}", e)))?;
    let keyid = hex::encode(Sha256::digest(&public_key));

    let envelope = build_envelope(DSSE_PAYLOAD_TYPE, &statement_bytes, &raw_signature, &keyid);
    let envelope_json =
        serde_json::to_value(&envelope).map_err(|e| ApiError::InternalError(e.to_string()))?;
    let manifest_hash = hex::encode(Sha256::digest(
        serde_json::to_vec(&envelope_json).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ));

    state
        .db
        .insert_manifest(
            &manifest_hash,
            leaf_seq_id,
            tenant_id,
            &version,
            &sbom_hash,
            &format,
            &s3_key,
            &namespace,
            previous_manifest_hash.as_deref(),
            &envelope_json,
            document_type_opt,
            &grant.principal(),
            manifest_created_at,
        )
        .await
        .map_err(db_err)?;

    let sth_json = sth_to_json(&sth, true);
    let _ = record_audit(
        &state,
        &grant,
        "upload",
        &manifest_hash,
        true,
        None,
    )
    .await;

    Ok(Json(UploadResponse {
        sbom_hash,
        manifest_hash,
        version,
        namespace,
        domain,
        tree_size,
        leaf_index: tree_size - 1,
        leaf_seq_id,
        signed_tree_head: sth_json,
    }))
}

pub async fn tree_head_latest(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<TreeHeadJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _) = effective_tenant(&grant, q.tenant_id)?;

    let record = state
        .db
        .get_latest_signed_tree_head(tenant_id)
        .await
        .map_err(db_err)?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(tree_head_record_to_json(&state, record).await?))
}

pub async fn tree_head_at(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(tree_size): Path<i64>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<TreeHeadJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _) = effective_tenant(&grant, q.tenant_id)?;

    let record = state
        .db
        .get_signed_tree_head(tenant_id, tree_size)
        .await
        .map_err(db_err)?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(tree_head_record_to_json(&state, record).await?))
}

async fn tree_head_record_to_json(
    state: &AppState,
    record: magnolia_db::SignedTreeHeadRecord,
) -> Result<TreeHeadJson, ApiError> {
    let sth = SignedTreeHead {
        tree_size: record.tree_size as u64,
        root_hash: record.root_hash.clone(),
        signature: record.signature.clone(),
        frontier: record.frontier,
        created_at: record.created_at,
    };
    let verified = state
        .signer
        .verify(&sth.signing_payload(), &sth.signature)
        .await
        .unwrap_or(false);
    Ok(sth_to_json(&sth, verified))
}

pub async fn inclusion_proof(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(leaf_index): Path<u64>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<InclusionProof>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _) = effective_tenant(&grant, q.tenant_id)?;

    let trees = state.trees.lock().await;
    let tree = trees.get(&tenant_id).ok_or(ApiError::NotFound)?;
    let proof = tree
        .generate_inclusion_proof(leaf_index)
        .map_err(|_| ApiError::NotFound)?;
    let _ = record_audit(
        &state,
        &grant,
        "proof_inclusion",
        &leaf_index.to_string(),
        true,
        None,
    )
    .await;
    Ok(Json(proof))
}

pub async fn consistency_proof(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path((old_tree_size, new_tree_size)): Path<(u64, u64)>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<ConsistencyProof>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _) = effective_tenant(&grant, q.tenant_id)?;

    if old_tree_size > new_tree_size {
        return Err(ApiError::BadRequest(
            "old_tree_size must be <= new_tree_size".to_string(),
        ));
    }
    let trees = state.trees.lock().await;
    let tree = trees.get(&tenant_id).cloned().unwrap_or_default();
    if new_tree_size != tree.tree_size() {
        return Err(ApiError::BadRequest(format!(
            "new_tree_size must equal the current tree size ({})",
            tree.tree_size()
        )));
    }
    let proof = tree
        .generate_consistency_proof(old_tree_size)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let _ = record_audit(
        &state,
        &grant,
        "proof_consistency",
        &format!("{}->{}", old_tree_size, new_tree_size),
        true,
        None,
    )
    .await;
    Ok(Json(proof))
}

pub async fn leaves(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(query): Query<LeavesQuery>,
) -> Result<Json<Vec<LeafJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, query.tenant_id)?;
    // Acting on another tenant sees it in full — "my namespace scope"
    // doesn't apply to someone else's tenant.
    let scope = if cross_tenant { "/" } else { &grant.namespace_scope };

    let limit = query.limit.clamp(1, 500);
    let offset = query.offset.max(0);
    let rows = state
        .db
        .list_merkle_leaves(tenant_id, scope, limit, offset)
        .await
        .map_err(db_err)?;
    Ok(Json(
        rows.into_iter()
            .map(|row| LeafJson {
                leaf_index: row.tenant_leaf_index.max(0) as u64,
                leaf_hash: hex::encode(&row.leaf_hash),
                seq_id: row.seq_id,
                tenant_id: row.tenant_id,
                namespace: row.namespace,
                sbom_s3_key: row.sbom_s3_key,
                status: row.status,
                created_at: row.created_at,
                manifest_hash: row.manifest_hash,
                revoked: row.revoked,
                domain: row.domain,
                version: row.version,
                document_type: row.document_type,
            })
            .collect(),
    ))
}

pub async fn manifest(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(manifest_hash): Path<String>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<ManifestJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let record = state
        .db
        .get_manifest(&manifest_hash)
        .await
        .map_err(db_err)?
        .ok_or(ApiError::NotFound)?;

    // Don't confirm existence of another tenant's (or another namespace's)
    // manifest: 404, not 403, either way. A cross-tenant super_admin sees
    // the target tenant in full — namespace scope doesn't apply there.
    if record.tenant_id != tenant_id
        || (!cross_tenant
            && !magnolia_auth::namespace_in_scope(&record.namespace, &grant.namespace_scope))
    {
        return Err(ApiError::NotFound);
    }

    let domain = if cross_tenant {
        state
            .db
            .get_tenant(tenant_id)
            .await
            .map_err(db_err)?
            .map(|t| t.domain)
            .unwrap_or_default()
    } else {
        grant.domain.clone()
    };

    let sbom_bytes = state
        .storage
        .get(&record.sbom_s3_key)
        .await
        .map_err(|e| ApiError::InternalError(format!("storage get failed: {}", e)))?;

    // Only computed for profiles this tenant has actually enabled — a
    // disabled profile's report would just be noise in the response.
    let compliance: Vec<ComplianceReportJson> = {
        let settings = state.db.list_compliance_settings(tenant_id).await.map_err(db_err)?;
        let enabled_ids: std::collections::HashSet<_> =
            settings.into_iter().filter(|s| s.enabled).map(|s| s.profile_id).collect();
        registered_profiles()
            .iter()
            .filter(|p| enabled_ids.contains(p.id()))
            .filter_map(|p| {
                let r = p.check(&record.sbom_format, &sbom_bytes);
                if r.applicable { Some(ComplianceReportJson::from(r)) } else { None }
            })
            .collect()
    };

    Ok(Json(ManifestJson {
        sbom_hex: hex::encode(&sbom_bytes),
        manifest_hash: record.manifest_hash,
        leaf_seq_id: record.leaf_seq_id,
        tenant_id: record.tenant_id,
        domain,
        version: record.version,
        sbom_hash: record.sbom_hash,
        sbom_format: record.sbom_format,
        sbom_s3_key: record.sbom_s3_key,
        namespace: record.namespace,
        previous_manifest_hash: record.previous_manifest_hash,
        signature: record.signature.as_ref().map(hex::encode),
        dsse_envelope: record.dsse_envelope.clone(),
        document_type: record.document_type.clone(),
        created_by: mask_principal(&record.created_by),
        created_at: record.created_at,
        revoked: record.revoked,
        revoked_at: record.revoked_at,
        revoked_by: record.revoked_by,
        compliance,
    }))
}

/// The most recent non-revoked manifest per namespace — "what's currently
/// deployed" for each deployable, not just the single latest upload
/// tenant-wide. Recency (`created_at`), not `version` magnitude, decides
/// "current" — a rollback to an older version number is still correctly
/// reported as current, since it's what was actually deployed last.
pub async fn current_manifests(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<Vec<CurrentManifestJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let scope = if cross_tenant { "/" } else { &grant.namespace_scope };

    let domain = if cross_tenant {
        state
            .db
            .get_tenant(tenant_id)
            .await
            .map_err(db_err)?
            .map(|t| t.domain)
            .unwrap_or_default()
    } else {
        grant.domain.clone()
    };

    let rows = state
        .db
        .latest_manifests_by_namespace(tenant_id, scope)
        .await
        .map_err(db_err)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| CurrentManifestJson {
                namespace: r.namespace,
                domain: domain.clone(),
                version: r.version,
                manifest_hash: r.manifest_hash,
                sbom_hash: r.sbom_hash,
                sbom_format: r.sbom_format,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

/// Namespaces currently opted out of the "current" view for this tenant
/// (scoped to the caller's `namespace_scope`, or the full tenant when
/// acting cross-tenant).
pub async fn list_hidden_namespaces(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<Vec<String>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let scope = if cross_tenant { "/" } else { &grant.namespace_scope };

    let rows = state
        .db
        .list_hidden_namespaces(tenant_id, scope)
        .await
        .map_err(db_err)?;
    Ok(Json(rows))
}

#[derive(serde::Deserialize)]
pub struct SetNamespaceHiddenRequest {
    pub namespace: String,
    pub hidden: bool,
}

/// Toggles whether a namespace is excluded from the "current" view — a
/// display filter only (declutter test/staging namespaces from "what's
/// running in prod"), not a tracking pause: uploads, revocation, and the
/// Merkle log/proofs are entirely unaffected either way. Gated with
/// `Action::ManageSettings` — a tenant-wide setting, not a per-item
/// curatorial action, so (unlike manifest revocation) `auditor` may view
/// it but not change it.
pub async fn set_namespace_hidden(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<SetNamespaceHiddenRequest>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let namespace = normalize_namespace(&body.namespace)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    if !cross_tenant && !magnolia_auth::namespace_in_scope(&namespace, &grant.namespace_scope) {
        return Err(ApiError::Forbidden("namespace out of scope".to_string()));
    }

    state
        .db
        .set_namespace_hidden(tenant_id, &namespace, body.hidden, &grant.principal())
        .await
        .map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Every registered compliance profile — informational, not tenant-scoped,
/// so plain `Action::Read` is enough.
pub async fn list_compliance_profiles(grant: AuthGrant) -> Result<Json<Vec<ComplianceProfileJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    Ok(Json(
        registered_profiles()
            .iter()
            .map(|p| ComplianceProfileJson { id: p.id().to_string(), name: p.name().to_string() })
            .collect(),
    ))
}

/// This tenant's setting for every registered profile — always the full
/// list, even for profiles the tenant has never touched (those default to
/// disabled/off). Viewing is `Action::Read`; only `set_compliance_setting`
/// (below) requires `Action::ManageSettings`.
pub async fn compliance_settings(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<Vec<ComplianceSettingJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let rows = state.db.list_compliance_settings(tenant_id).await.map_err(db_err)?;
    let by_id: std::collections::HashMap<_, _> = rows.into_iter().map(|r| (r.profile_id.clone(), r)).collect();
    Ok(Json(
        registered_profiles()
            .iter()
            .map(|p| {
                let row = by_id.get(p.id());
                ComplianceSettingJson {
                    profile_id: p.id().to_string(),
                    profile_name: p.name().to_string(),
                    enabled: row.map(|r| r.enabled).unwrap_or(false),
                    enforce_level: row.map(|r| r.enforce_level.clone()).unwrap_or_else(|| "off".to_string()),
                }
            })
            .collect(),
    ))
}

/// Enables/disables a compliance profile for this tenant and sets its
/// enforcement level. `Action::ManageSettings` — deliberately excludes
/// `auditor`, since this can turn on upload-rejecting enforcement for the
/// whole tenant.
pub async fn set_compliance_setting(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<SetComplianceSettingRequest>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    if profile_by_id(&body.profile_id).is_none() {
        return Err(ApiError::BadRequest(format!("unknown compliance profile_id: {}", body.profile_id)));
    }
    if !matches!(body.enforce_level.as_str(), "off" | "minimum" | "full") {
        return Err(ApiError::BadRequest("enforce_level must be one of: off, minimum, full".to_string()));
    }
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    state
        .db
        .set_compliance_setting(tenant_id, &body.profile_id, body.enabled, &body.enforce_level, &grant.principal())
        .await
        .map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Marks a manifest revoked — a status flag, not a delete: the manifest
/// row, its signature, and the Merkle leaf/hash it's chained from are
/// untouched, so the append-only log and tamper-evidence are unaffected.
///
/// Normally requires `Action::Annotate` (super_admin, domain_admin,
/// auditor). If the server has `DEV_MODE=true` set, an `uploader`-role key
/// may also revoke — for local testing where the same pipeline that
/// uploaded a bad SBOM wants to retract it without a separate admin key.
/// Never relies on DEV_MODE for anything beyond that one relaxation.
pub async fn revoke_manifest(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(manifest_hash): Path<String>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<StatusCode, ApiError> {
    if let Err(e) = require(&grant, Action::Annotate, &grant.namespace_scope) {
        if state.dev_mode {
            require(&grant, Action::Upload, &grant.namespace_scope)?;
        } else {
            return Err(e);
        }
    }

    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let record = state
        .db
        .get_manifest(&manifest_hash)
        .await
        .map_err(db_err)?
        .ok_or(ApiError::NotFound)?;

    if record.tenant_id != tenant_id
        || (!cross_tenant
            && !magnolia_auth::namespace_in_scope(&record.namespace, &grant.namespace_scope))
    {
        return Err(ApiError::NotFound);
    }

    let updated = state
        .db
        .revoke_manifest(tenant_id, &manifest_hash, &grant.principal())
        .await
        .map_err(db_err)?;

    if !updated {
        return Err(ApiError::BadRequest("manifest already revoked".to_string()));
    }

    let _ = record_audit(&state, &grant, "manifest_revoke", &manifest_hash, true, None).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Mints a key for `tenant_id`/`domain`. Shared by `create_key` (caller
/// creates a key for their own tenant) and `create_tenant` (mints the new
/// tenant's first key).
async fn mint_key(
    state: &AppState,
    tenant_id: Uuid,
    domain: &str,
    role: Role,
    namespace_scope: &str,
    expires_at: Option<DateTime<Utc>>,
) -> Result<CreateKeyResponse, ApiError> {
    let (key_id, secret, full_key) = generate_server_key();
    let key_material = magnolia_auth::ApiKey {
        key: secret,
        created_at: Utc::now(),
    };
    let hashed = key_material
        .hash()
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    state
        .db
        .insert_api_key(
            key_id,
            tenant_id,
            domain,
            namespace_scope,
            &role.to_string(),
            &hashed.hash,
            expires_at,
        )
        .await
        .map_err(db_err)?;

    Ok(CreateKeyResponse {
        key: full_key,
        key_id,
        tenant_id,
        domain: domain.to_string(),
        namespace_scope: namespace_scope.to_string(),
        role: role.to_string(),
        expires_at,
    })
}

fn parse_expires_at(text: &Option<String>) -> Result<Option<DateTime<Utc>>, ApiError> {
    match text {
        Some(text) => Ok(Some(
            DateTime::parse_from_rfc3339(text)
                .map_err(|_| ApiError::BadRequest("expires_at must be RFC3339".to_string()))?
                .with_timezone(&Utc),
        )),
        None => Ok(None),
    }
}

pub async fn create_key(
    State(state): State<AppState>,
    grant: AuthGrant,
    Json(request): Json<CreateKeyRequest>,
) -> Result<Json<CreateKeyResponse>, ApiError> {
    require(&grant, Action::ManageKeys, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, request.tenant_id)?;

    let role = Role::from_str(&request.role)
        .map_err(|_| ApiError::BadRequest(format!("unknown role: {}", request.role)))?;
    let namespace_scope = normalize_namespace(&request.namespace_scope)?;
    let expires_at = parse_expires_at(&request.expires_at)?;

    // A key is created for the caller's own tenant/domain by default; only
    // super_admin can target another tenant (and must supply its domain
    // explicitly, since a key row always carries one).
    let domain = if cross_tenant {
        state
            .db
            .get_tenant(tenant_id)
            .await
            .map_err(db_err)?
            .ok_or_else(|| ApiError::BadRequest("unknown tenant_id".to_string()))?
            .domain
    } else {
        grant.domain.clone()
    };

    let response = mint_key(&state, tenant_id, &domain, role, &namespace_scope, expires_at).await?;

    let _ = record_audit(
        &state,
        &grant,
        "key_create",
        &response.key_id.to_string(),
        true,
        None,
    )
    .await;

    Ok(Json(response))
}

pub async fn create_tenant(
    State(state): State<AppState>,
    grant: AuthGrant,
    Json(request): Json<CreateTenantRequest>,
) -> Result<Json<CreateTenantResponse>, ApiError> {
    require(&grant, Action::ManageTenants, "")?;

    let domain = normalize_domain(&request.domain)?;
    let name = request.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".to_string()));
    }

    let tenant_id = Uuid::new_v4();
    let created_at = Utc::now();
    state
        .db
        .insert_tenant(tenant_id, &domain, name, &grant.principal(), false)
        .await
        .map_err(|e| match e {
            magnolia_db::DbError::Conflict(_) => {
                ApiError::BadRequest(format!("domain '{}' is already in use", domain))
            }
            other => db_err(other),
        })?;

    let initial_key = mint_key(
        &state,
        tenant_id,
        &domain,
        Role::DomainAdmin,
        "/",
        None,
    )
    .await?;

    let _ = record_audit(
        &state,
        &grant,
        "tenant_create",
        &tenant_id.to_string(),
        true,
        None,
    )
    .await;

    Ok(Json(CreateTenantResponse {
        tenant: TenantJson {
            id: tenant_id,
            domain,
            name: name.to_string(),
            created_by: grant.principal(),
            created_at,
            is_platform: false,
        },
        initial_key,
    }))
}

pub async fn list_tenants(
    State(state): State<AppState>,
    grant: AuthGrant,
) -> Result<Json<Vec<TenantJson>>, ApiError> {
    require(&grant, Action::ManageTenants, "")?;

    let rows = state.db.list_tenants().await.map_err(db_err)?;
    Ok(Json(
        rows.into_iter()
            .map(|row| TenantJson {
                id: row.id,
                domain: row.domain,
                name: row.name,
                created_by: row.created_by,
                created_at: row.created_at,
                is_platform: row.is_platform,
            })
            .collect(),
    ))
}

/// Outside `DEV_MODE`, "deleting" a tenant only hides it — everything it
/// owns (keys, leaves, manifests, signed tree heads, audit log) stays
/// fully intact and still reachable directly (e.g. via `?tenant_id=`
/// override); it just disappears from listings/selectors. A compliance
/// archive shouldn't let one admin action permanently erase years of SBOM
/// history with no retention floor. The hard, cascading delete is only
/// available when `DEV_MODE=true`, for local test cleanup.
///
/// Gated more strictly than `create_tenant`/`list_tenants`: those allow any
/// super_admin (`Action::ManageTenants`), but this is a cross-tenant action
/// on another tenant's entire history, so it requires the platform
/// super_admin specifically — the same bar as the `?tenant_id` override
/// elsewhere. The platform tenant itself can never be deleted or hidden
/// (it's the one tenant capable of managing all the others).
pub async fn delete_tenant(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(tenant_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    if !(grant.role == Role::SuperAdmin && grant.is_platform_tenant) {
        return Err(ApiError::Forbidden(
            "only the platform super_admin can delete a tenant".to_string(),
        ));
    }

    let target = state
        .db
        .get_tenant(tenant_id)
        .await
        .map_err(db_err)?
        .ok_or(ApiError::NotFound)?;

    if target.is_platform {
        return Err(ApiError::BadRequest(
            "cannot delete the platform tenant".to_string(),
        ));
    }

    if state.dev_mode {
        state.db.delete_tenant(tenant_id).await.map_err(db_err)?;
        state.trees.lock().await.remove(&tenant_id);

        let _ = record_audit(
            &state,
            &grant,
            "tenant_delete",
            &format!("{} ({})", tenant_id, target.domain),
            true,
            None,
        )
        .await;
    } else {
        state.db.hide_tenant(tenant_id).await.map_err(db_err)?;

        let _ = record_audit(
            &state,
            &grant,
            "tenant_hide",
            &format!("{} ({})", tenant_id, target.domain),
            true,
            None,
        )
        .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_keys(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<Vec<KeyJson>>, ApiError> {
    require(&grant, Action::ManageKeys, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let domain = if cross_tenant {
        state
            .db
            .get_tenant(tenant_id)
            .await
            .map_err(db_err)?
            .ok_or_else(|| ApiError::BadRequest("unknown tenant_id".to_string()))?
            .domain
    } else {
        grant.domain.clone()
    };

    let rows = state.db.list_api_keys(&domain).await.map_err(db_err)?;
    Ok(Json(
        rows.into_iter()
            .map(|row| KeyJson {
                id: row.id,
                tenant_id: row.tenant_id,
                domain: row.domain,
                namespace_scope: row.namespace_scope,
                role: row.role,
                expires_at: row.expires_at,
                revoked: row.revoked,
                created_at: row.created_at,
            })
            .collect(),
    ))
}

pub async fn revoke_key(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(key_id): Path<Uuid>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageKeys, &grant.namespace_scope)?;
    let (tenant_id, _) = effective_tenant(&grant, q.tenant_id)?;

    // Scoped to the target tenant at the DB layer: a key can only ever be
    // revoked by (an admin of) its own tenant — or a super_admin acting on
    // that tenant explicitly.
    let found = state
        .db
        .revoke_api_key(tenant_id, key_id)
        .await
        .map_err(db_err)?;

    if !found {
        return Err(ApiError::NotFound);
    }

    let _ = record_audit(&state, &grant, "key_revoke", &key_id.to_string(), true, None).await;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn audit_logs(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _) = effective_tenant(&grant, query.tenant_id)?;

    let rows = state
        .db
        .list_audit_logs(tenant_id, query.limit.clamp(1, 500))
        .await
        .map_err(db_err)?;
    Ok(Json(
        rows.into_iter()
            .map(|row| AuditJson {
                id: row.id,
                tenant_id: row.tenant_id,
                principal: row.principal,
                action: row.action,
                resource: row.resource,
                result: row.result,
                reason: row.reason,
                created_at: row.created_at,
            })
            .collect(),
    ))
}