use std::str::FromStr;

use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use sbomstash_audit::{AuditLogEntry, AuditResult};
use sbomstash_auth::{generate_server_key, Action, Role};
use sbomstash_core::{
    ConsistencyProof, InclusionProof, Manifest, MerkleTree, SbomFormat, SignedTreeHead,
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
    pub signature: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub sbom_hex: String,
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
/// default, or an explicit override — only ever honored for super_admin.
/// The second element is `true` when acting on a tenant other than the
/// grant's own, in which case the grant's `namespace_scope` does not apply
/// (there's no meaningful "my namespace scope" in someone else's tenant —
/// a cross-tenant super_admin sees/manages that tenant in full).
fn effective_tenant(grant: &AuthGrant, requested: Option<Uuid>) -> Result<(Uuid, bool), ApiError> {
    match requested {
        Some(id) if grant.role == Role::SuperAdmin => Ok((id, id != grant.tenant_id)),
        Some(_) => Err(ApiError::Forbidden(
            "only super_admin can act on another tenant".to_string(),
        )),
        None => Ok((grant.tenant_id, false)),
    }
}

fn db_err(e: impl std::fmt::Display) -> ApiError {
    ApiError::InternalError(e.to_string())
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

fn validate_sbom_content(data: &[u8], format: &str) -> Result<(), ApiError> {
    let doc: serde_json::Value = serde_json::from_slice(data).map_err(|_| {
        ApiError::BadRequest("SBOM must be valid JSON".to_string())
    })?;
    let obj = doc
        .as_object()
        .ok_or_else(|| ApiError::BadRequest("SBOM must be a JSON object".to_string()))?;

    match format {
        "cyclonedx" => {
            let bom_format = obj
                .get("bomFormat")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if bom_format != "CycloneDX" {
                return Err(ApiError::BadRequest(
                    "cyclonedx SBOM must have bomFormat == \"CycloneDX\"".to_string(),
                ));
            }
        }
        "spdx" => {
            if !obj.contains_key("spdxVersion") {
                return Err(ApiError::BadRequest(
                    "spdx SBOM must have a spdxVersion field".to_string(),
                ));
            }
        }
        other => {
            return Err(ApiError::BadRequest(format!(
                "unsupported format: {} (use cyclonedx or spdx)",
                other
            )))
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
    })
}

pub async fn upload_sbom(
    State(state): State<AppState>,
    grant: AuthGrant,
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
    if !matches!(format.as_str(), "cyclonedx" | "spdx") {
        return Err(ApiError::BadRequest(format!(
            "unsupported format: {} (use cyclonedx or spdx)",
            format
        )));
    }
    validate_sbom_content(&sbom_bytes, &format)?;

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

    let sbom_format = match format.as_str() {
        "cyclonedx" => SbomFormat::CycloneDx,
        _ => SbomFormat::Spdx,
    };

    let sbom_hash = hex::encode(Sha256::digest(&sbom_bytes));
    let s3_key = format!(
        "tenants/{}/sboms/{}.sbom",
        grant.tenant_id, sbom_hash
    );

    state
        .storage
        .put(&s3_key, &sbom_bytes)
        .await
        .map_err(|e| ApiError::InternalError(format!("storage put failed: {}", e)))?;

    let (leaf_hash, tree_size, tenant_leaf_index, sth) = {
        let mut trees = state.trees.lock().await;
        let tree = trees.entry(grant.tenant_id).or_insert_with(MerkleTree::new);
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
            grant.tenant_id,
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
            grant.tenant_id,
            tree_size as i64,
            &sth.root_hash,
            &sth.signature,
            &sth.frontier,
        )
        .await
        .map_err(db_err)?;

    let previous = state.db.latest_manifest(grant.tenant_id).await.map_err(db_err)?;
    let previous_manifest_hash = previous.as_ref().map(|m| m.manifest_hash.clone());

    let manifest_created_at = Utc::now();
    let mut manifest = Manifest::new(
        version.clone(),
        sbom_hash.clone(),
        sbom_format,
        s3_key.clone(),
        grant.tenant_id,
        namespace.clone(),
        grant.domain.clone(),
    );
    if let Some(ref prev) = previous_manifest_hash {
        manifest = manifest.with_previous(prev.clone());
    }
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| ApiError::InternalError(e.to_string()))?;
    let manifest_signature = state
        .signer
        .sign(&manifest_bytes)
        .await
        .map_err(|e| ApiError::InternalError(format!("manifest signing failed: {}", e)))?;
    manifest.signature = hex::encode(&manifest_signature);
    manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| ApiError::InternalError(e.to_string()))?;
    let manifest_hash = hex::encode(Sha256::digest(&manifest_bytes));

    state
        .db
        .insert_manifest(
            &manifest_hash,
            leaf_seq_id,
            grant.tenant_id,
            &version,
            &sbom_hash,
            &format,
            &s3_key,
            &namespace,
            previous_manifest_hash.as_deref(),
            &manifest_signature,
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
        domain: grant.domain.clone(),
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
    record: sbomstash_db::SignedTreeHeadRecord,
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
            && !sbomstash_auth::namespace_in_scope(&record.namespace, &grant.namespace_scope))
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
        signature: hex::encode(&record.signature),
        created_by: record.created_by,
        created_at: record.created_at,
    }))
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
    let key_material = sbomstash_auth::ApiKey {
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
        .insert_tenant(tenant_id, &domain, name, &grant.principal())
        .await
        .map_err(|e| match e {
            sbomstash_db::DbError::Conflict(_) => {
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
            })
            .collect(),
    ))
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