use std::collections::HashSet;

use chrono::Utc;
use magnolia_core::{
    build_envelope, pae, registered_profiles, ComplianceReport, SnapshotPredicate,
    SnapshotStatement, Statement, Subject, DSSE_PAYLOAD_TYPE, IN_TOTO_STATEMENT_TYPE,
    SNAPSHOT_PREDICATE_TYPE,
};
use magnolia_db::ManifestRecord;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;

/// Turns a namespace path into a filesystem-safe directory path inside the
/// archive. The literal root namespace ("/") has no segments of its own,
/// so it gets a fixed name rather than an empty path.
fn sanitize_namespace_path(namespace: &str) -> String {
    let trimmed = namespace.trim_start_matches('/');
    if trimmed.is_empty() {
        "_root".to_string()
    } else {
        trimmed.to_string()
    }
}

/// CycloneDX/SPDX are always JSON, so those get a real `.json` outright.
/// Generic "document" uploads can be anything (a CVD policy PDF, a
/// git-repo tar/tar.gz, plain text) with no stored MIME type, so this
/// sniffs the actual bytes rather than always falling back to `.bin` —
/// mirrors the exact heuristics `frontend/src/App.tsx` already uses to
/// decide how to preview a document (`isPdf`, gzip/ustar magic bytes,
/// `displayableText`'s control-character-ratio check for plain text).
fn content_extension(sbom_format: &str, bytes: &[u8]) -> String {
    match sbom_format {
        "cyclonedx" | "spdx" => "json".to_string(),
        _ => sniff_extension(bytes).to_string(),
    }
}

fn sniff_extension(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"%PDF-") {
        return "pdf";
    }
    if bytes.len() > 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        // Gzip magic — a plain `.gz` would be equally correct, but a
        // gzip-wrapped upload in this app is overwhelmingly a git-repo
        // archive, so `.tar.gz` is the more useful guess.
        return "tar.gz";
    }
    if bytes.len() > 262 && &bytes[257..262] == b"ustar" {
        return "tar";
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        return "zip";
    }
    if serde_json::from_slice::<serde_json::Value>(bytes).is_ok() {
        return "json";
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        let len = text.chars().count();
        let control_count = text
            .chars()
            .filter(|c| (*c as u32) < 32 && !matches!(c, '\t' | '\n' | '\r'))
            .count();
        if len == 0 || (control_count as f64 / len as f64) <= 0.01 {
            return "txt";
        }
    }
    "bin"
}

fn append_file(builder: &mut tar::Builder<Vec<u8>>, path: &str, data: &[u8]) -> Result<(), ApiError> {
    let mut header = tar::Header::new_gnu();
    header
        .set_path(path)
        .map_err(|e| ApiError::InternalError(format!("snapshot tar path {path}: {e}")))?;
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(Utc::now().timestamp() as u64);
    header.set_cksum();
    builder
        .append(&header, data)
        .map_err(|e| ApiError::InternalError(format!("snapshot tar append {path}: {e}")))
}

/// Builds a signed audit archive: every manifest/document matching scope,
/// deliberately uncurated (see `list_manifests_for_export`'s doc comment),
/// packaged as a tar with each item's raw content, its own pre-existing
/// DSSE envelope, a fresh Merkle inclusion proof, and (if any compliance
/// profile is enabled for the tenant) a frozen compliance report — plus a
/// top-level DSSE envelope over the whole set, so the archive's own
/// contents-claim is independently verifiable, not just asserted.
pub async fn build_snapshot_tar(
    state: &AppState,
    tenant_id: Uuid,
    domain: &str,
    created_by: &str,
    namespace_scope: &str,
    namespace_filter: Option<&str>,
    version_filter: Option<&str>,
) -> Result<Vec<u8>, ApiError> {
    let scope = match (namespace_filter, version_filter) {
        (None, None) => "all".to_string(),
        (Some(ns), None) => format!("namespace={ns}"),
        (None, Some(v)) => format!("version={v}"),
        (Some(ns), Some(v)) => format!("namespace={ns} version={v}"),
    };

    let records = state
        .db
        .list_manifests_for_export(tenant_id, namespace_scope, namespace_filter, version_filter)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    if records.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "No manifests or documents match scope \"{scope}\" — the archive would be empty. \
             Check the namespace/version filters and try again."
        )));
    }

    let enabled_profile_ids: HashSet<String> = state
        .db
        .list_compliance_settings(tenant_id)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?
        .into_iter()
        .filter(|s| s.enabled)
        .map(|s| s.profile_id)
        .collect();

    let sth = state
        .db
        .get_latest_signed_tree_head(tenant_id)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;
    let (tree_size, root_hash) = match &sth {
        Some(r) => (r.tree_size as u64, hex::encode(&r.root_hash)),
        None => (0, String::new()),
    };

    let mut subjects = Vec::with_capacity(records.len());
    let mut index_entries = Vec::with_capacity(records.len());
    let mut item_files: Vec<(String, Vec<u8>)> = Vec::new();

    for record in &records {
        let bytes = state
            .storage
            .get(&record.sbom_s3_key)
            .await
            .map_err(|e| ApiError::InternalError(format!("storage get failed: {e}")))?;

        let leaf = state
            .db
            .get_merkle_leaf(record.leaf_seq_id)
            .await
            .map_err(|e| ApiError::InternalError(e.to_string()))?;

        let inclusion_proof = if let Some(leaf) = leaf {
            let trees = state.trees.lock().await;
            trees
                .get(&tenant_id)
                .and_then(|tree| tree.generate_inclusion_proof(leaf.tenant_leaf_index.max(0) as u64).ok())
        } else {
            None
        };

        let compliance: Vec<ComplianceReport> = registered_profiles()
            .iter()
            .filter(|p| enabled_profile_ids.contains(p.id()))
            .map(|p| p.check(&record.sbom_format, &bytes))
            .filter(|r| r.applicable)
            .collect();

        let dir = format!(
            "items/{}/{}-{}",
            sanitize_namespace_path(&record.namespace),
            record.version,
            &record.manifest_hash[..12.min(record.manifest_hash.len())]
        );
        let ext = content_extension(&record.sbom_format, &bytes);

        item_files.push((format!("{dir}/content.{ext}"), bytes.clone()));
        if let Some(envelope) = &record.dsse_envelope {
            item_files.push((
                format!("{dir}/dsse-envelope.json"),
                serde_json::to_vec_pretty(envelope).unwrap_or_default(),
            ));
        }
        if let Some(proof) = &inclusion_proof {
            item_files.push((
                format!("{dir}/inclusion-proof.json"),
                serde_json::to_vec_pretty(proof).unwrap_or_default(),
            ));
        }
        if !compliance.is_empty() {
            item_files.push((
                format!("{dir}/compliance.json"),
                serde_json::to_vec_pretty(&compliance).unwrap_or_default(),
            ));
        }
        item_files.push((format!("{dir}/meta.json"), meta_json_bytes(record)));

        index_entries.push(serde_json::json!({
            "namespace": record.namespace,
            "version": record.version,
            "manifest_hash": record.manifest_hash,
            "document_type": record.document_type,
            "path": dir,
        }));

        subjects.push(Subject {
            name: format!("{domain}{}@{}", record.namespace, record.version),
            digest: [("sha256".to_string(), record.sbom_hash.clone())].into_iter().collect(),
        });
    }

    let created_at = Utc::now();
    let statement: SnapshotStatement = Statement {
        statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
        subject: subjects,
        predicate_type: SNAPSHOT_PREDICATE_TYPE.to_string(),
        predicate: SnapshotPredicate {
            tenant_id,
            domain: domain.to_string(),
            created_by: created_by.to_string(),
            created_at,
            tree_size,
            root_hash: root_hash.clone(),
            scope: scope.clone(),
        },
    };
    let statement_bytes =
        serde_json::to_vec(&statement).map_err(|e| ApiError::InternalError(e.to_string()))?;
    let pae_bytes = pae(DSSE_PAYLOAD_TYPE, &statement_bytes);
    let raw_signature = state
        .signer
        .sign(&pae_bytes)
        .await
        .map_err(|e| ApiError::InternalError(format!("snapshot signing failed: {e}")))?;
    let public_key = state
        .signer
        .public_key()
        .await
        .map_err(|e| ApiError::InternalError(format!("public key lookup failed: {e}")))?;
    let keyid = hex::encode(Sha256::digest(&public_key));
    let envelope = build_envelope(DSSE_PAYLOAD_TYPE, &statement_bytes, &raw_signature, &keyid);

    let top_level = serde_json::json!({
        "scope": scope,
        "created_at": created_at,
        "created_by": created_by,
        "domain": domain,
        "tree_size": tree_size,
        "root_hash": root_hash,
        "item_count": records.len(),
        "items": index_entries,
    });

    let mut builder = tar::Builder::new(Vec::new());
    append_file(
        &mut builder,
        "snapshot.json",
        &serde_json::to_vec_pretty(&top_level).map_err(|e| ApiError::InternalError(e.to_string()))?,
    )?;
    append_file(
        &mut builder,
        "snapshot.dsse.json",
        &serde_json::to_vec_pretty(&envelope).map_err(|e| ApiError::InternalError(e.to_string()))?,
    )?;
    for (path, bytes) in &item_files {
        append_file(&mut builder, path, bytes)?;
    }

    builder
        .into_inner()
        .map_err(|e| ApiError::InternalError(format!("snapshot tar finalize: {e}")))
}

fn meta_json_bytes(record: &ManifestRecord) -> Vec<u8> {
    let masked_created_by = crate::handlers::mask_principal(&record.created_by);
    let meta = serde_json::json!({
        "manifest_hash": record.manifest_hash,
        "namespace": record.namespace,
        "version": record.version,
        "document_type": record.document_type,
        "sbom_format": record.sbom_format,
        "revoked": record.revoked,
        "revoked_at": record.revoked_at,
        "revoked_by": record.revoked_by,
        "created_at": record.created_at,
        "created_by": masked_created_by,
    });
    serde_json::to_vec_pretty(&meta).unwrap_or_default()
}
