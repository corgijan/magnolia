mod models;
mod errors;

pub use models::{
    ApiKeyRecord, AuditLogRecord, ComplianceSettingRecord, DtrackFindingRecord,
    DtrackFindingWithContextRecord, DtrackProjectRecord, DtrackPushFailureRecord,
    FindingCommentRecord, ManifestRecord, MerkleLeafRecord, MerkleNodeRecord, NewDtrackFinding,
    NewSbomComponent, SbomComponentSearchRow, SignedTreeHeadRecord, TenantRecord,
};
pub use errors::DbError;

use errors::map_query_error;

use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
}

impl Database {
    pub async fn connect(database_url: &str) -> Result<Self, DbError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(|e| DbError::ConnectionError(e.to_string()))?;

        Ok(Self { pool })
    }

    // ---- Tenants ----

    pub async fn insert_tenant(
        &self,
        id: Uuid,
        domain: &str,
        name: &str,
        created_by: &str,
        is_platform: bool,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO tenants (id, domain, name, created_by, created_at, is_platform)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(id)
        .bind(domain)
        .bind(name)
        .bind(created_by)
        .bind(chrono::Utc::now())
        .bind(is_platform)
        .execute(&self.pool)
        .await
        .map_err(map_query_error)?;

        Ok(())
    }

    /// Idempotently marks a tenant as the platform tenant (super_admin keys
    /// in it can act across all other tenants). Only ever called from the
    /// `BOOTSTRAP_SUPER_ADMIN_KEY` startup path — never reachable via the
    /// public API.
    pub async fn mark_tenant_platform(&self, id: Uuid) -> Result<(), DbError> {
        sqlx::query("UPDATE tenants SET is_platform = TRUE WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::QueryError(e.to_string()))?;
        Ok(())
    }

    /// Deletes a tenant and, via `ON DELETE CASCADE`, everything scoped to
    /// it (keys, leaves, manifests, signed tree heads, audit log). The
    /// caller is responsible for gating who may call this and for refusing
    /// to ever delete the platform tenant — this is a raw, unconditional
    /// delete at the DB layer. Returns `true` if a row existed and was
    /// removed.
    pub async fn delete_tenant(&self, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::QueryError(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_tenant(&self, id: Uuid) -> Result<Option<TenantRecord>, DbError> {
        sqlx::query_as::<_, TenantRecord>(
            "SELECT id, domain, name, created_by, created_at, is_platform, hidden, dtrack_sync_disabled FROM tenants WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    pub async fn get_tenant_by_domain(
        &self,
        domain: &str,
    ) -> Result<Option<TenantRecord>, DbError> {
        sqlx::query_as::<_, TenantRecord>(
            "SELECT id, domain, name, created_by, created_at, is_platform, hidden, dtrack_sync_disabled FROM tenants WHERE domain = $1",
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    /// Excludes hidden tenants — this backs the tenant listing/selector, so
    /// a tenant "deleted" outside DEV_MODE (hidden, not dropped) correctly
    /// disappears from view while its data stays fully intact and still
    /// reachable directly (e.g. `?tenant_id=` override), just not listed.
    pub async fn list_tenants(&self) -> Result<Vec<TenantRecord>, DbError> {
        sqlx::query_as::<_, TenantRecord>(
            "SELECT id, domain, name, created_by, created_at, is_platform, hidden, dtrack_sync_disabled FROM tenants WHERE hidden = FALSE ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    /// Per-tenant opt-out of the deployment-wide dtrack sync (see the
    /// `dtrack_sync_disabled` migration comment) — does not touch any
    /// already-cached `dtrack_findings`, only whether future sync passes
    /// push/refresh this tenant's manifests.
    pub async fn set_tenant_dtrack_sync_disabled(&self, tenant_id: Uuid, disabled: bool) -> Result<(), DbError> {
        sqlx::query("UPDATE tenants SET dtrack_sync_disabled = $1 WHERE id = $2")
            .bind(disabled)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::QueryError(e.to_string()))?;
        Ok(())
    }

    /// Marks a tenant hidden instead of deleting it — used outside
    /// DEV_MODE so "delete tenant" can never destroy a compliance archive's
    /// data. Returns `true` if a row existed and was updated.
    pub async fn hide_tenant(&self, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("UPDATE tenants SET hidden = TRUE WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::QueryError(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    // ---- Signed tree heads ----

    pub async fn insert_signed_tree_head(
        &self,
        tenant_id: Uuid,
        tree_size: i64,
        root_hash: &[u8],
        signature: &[u8],
        frontier: &[Vec<u8>],
    ) -> Result<(), DbError> {
        let now = chrono::Utc::now();
        sqlx::query(
            r#"
            INSERT INTO signed_tree_heads (tenant_id, tree_size, root_hash, signature, frontier, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(tenant_id)
        .bind(tree_size)
        .bind(root_hash)
        .bind(signature)
        .bind(frontier)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_signed_tree_head(
        &self,
        tenant_id: Uuid,
        tree_size: i64,
    ) -> Result<Option<SignedTreeHeadRecord>, DbError> {
        sqlx::query_as::<_, SignedTreeHeadRecord>(
            "SELECT tenant_id, tree_size, root_hash, signature, frontier, created_at FROM signed_tree_heads WHERE tenant_id = $1 AND tree_size = $2"
        )
        .bind(tenant_id)
        .bind(tree_size)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    pub async fn get_latest_signed_tree_head(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<SignedTreeHeadRecord>, DbError> {
        sqlx::query_as::<_, SignedTreeHeadRecord>(
            "SELECT tenant_id, tree_size, root_hash, signature, frontier, created_at FROM signed_tree_heads WHERE tenant_id = $1 ORDER BY tree_size DESC LIMIT 1"
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    // ---- Merkle leaves ----

    pub async fn insert_merkle_leaf(
        &self,
        tenant_id: Uuid,
        tenant_leaf_index: i64,
        namespace: &str,
        sbom_s3_key: &str,
        leaf_hash: &[u8],
        status: &str,
    ) -> Result<i64, DbError> {
        let now = chrono::Utc::now();
        let row = sqlx::query(
            r#"
            INSERT INTO merkle_leaves (tenant_id, tenant_leaf_index, namespace, sbom_s3_key, leaf_hash, status, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING seq_id
            "#,
        )
        .bind(tenant_id)
        .bind(tenant_leaf_index)
        .bind(namespace)
        .bind(sbom_s3_key)
        .bind(leaf_hash)
        .bind(status)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))?;

        let seq_id: i64 = row.try_get("seq_id").map_err(|e| DbError::QueryError(e.to_string()))?;
        Ok(seq_id)
    }

    pub async fn get_merkle_leaf(
        &self,
        seq_id: i64,
    ) -> Result<Option<MerkleLeafRecord>, DbError> {
        sqlx::query_as::<_, MerkleLeafRecord>(
            r#"
            SELECT ml.seq_id, ml.tenant_id, ml.tenant_leaf_index, ml.namespace, ml.sbom_s3_key,
                   ml.leaf_hash, ml.status, ml.created_at, m.manifest_hash,
                   COALESCE(m.revoked, FALSE) AS revoked, t.domain, m.version, m.document_type
            FROM merkle_leaves ml
            LEFT JOIN manifests m ON m.leaf_seq_id = ml.seq_id
            JOIN tenants t ON t.id = ml.tenant_id
            WHERE ml.seq_id = $1
            "#,
        )
        .bind(seq_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    /// Lists leaves for a tenant, filtered to `namespace_scope` (segment-aware
    /// prefix match, "/" covers everything) so a namespace-scoped key only
    /// ever sees leaves within its own scope.
    pub async fn list_merkle_leaves(
        &self,
        tenant_id: Uuid,
        namespace_scope: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MerkleLeafRecord>, DbError> {
        sqlx::query_as::<_, MerkleLeafRecord>(
            r#"
            SELECT ml.seq_id, ml.tenant_id, ml.tenant_leaf_index, ml.namespace, ml.sbom_s3_key,
                   ml.leaf_hash, ml.status, ml.created_at, m.manifest_hash,
                   COALESCE(m.revoked, FALSE) AS revoked, t.domain, m.version, m.document_type
            FROM merkle_leaves ml
            LEFT JOIN manifests m ON m.leaf_seq_id = ml.seq_id
            JOIN tenants t ON t.id = ml.tenant_id
            WHERE ml.tenant_id = $1
              AND ($4 = '/' OR ml.namespace = $4 OR starts_with(ml.namespace, $4 || '/'))
            ORDER BY ml.seq_id DESC LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .bind(namespace_scope)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    /// All leaf hashes for every tenant, in per-tenant append order; used to
    /// rebuild each tenant's in-memory MMR after a restart.
    pub async fn load_all_leaf_hashes_by_tenant(
        &self,
    ) -> Result<Vec<(Uuid, Vec<u8>)>, DbError> {
        let rows = sqlx::query(
            "SELECT tenant_id, leaf_hash FROM merkle_leaves ORDER BY tenant_id ASC, seq_id ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))?;
        rows.iter()
            .map(|row| {
                let tenant_id: Uuid = row.try_get("tenant_id")?;
                let leaf_hash: Vec<u8> = row.try_get("leaf_hash")?;
                Ok((tenant_id, leaf_hash))
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(|e| DbError::QueryError(e.to_string()))
    }

    // ---- API keys ----

    pub async fn lookup_api_key(&self, id: Uuid) -> Result<Option<ApiKeyRecord>, DbError> {
        sqlx::query_as::<_, ApiKeyRecord>(
            r#"
            SELECT id, tenant_id, domain, namespace_scope, role, key_hash,
                   expires_at, revoked, created_at
            FROM api_keys
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    pub async fn insert_api_key(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        domain: &str,
        namespace_scope: &str,
        role: &str,
        key_hash: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), DbError> {
        let now = chrono::Utc::now();
        sqlx::query(
            r#"
            INSERT INTO api_keys (id, tenant_id, domain, namespace_scope, role, key_hash, expires_at, revoked, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, $8)
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(domain)
        .bind(namespace_scope)
        .bind(role)
        .bind(key_hash)
        .bind(expires_at)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))?;

        Ok(())
    }

    pub async fn list_api_keys(&self, domain: &str) -> Result<Vec<ApiKeyRecord>, DbError> {
        sqlx::query_as::<_, ApiKeyRecord>(
            r#"
            SELECT id, tenant_id, domain, namespace_scope, role, key_hash,
                   expires_at, revoked, created_at
            FROM api_keys
            WHERE domain = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(domain)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    /// Revokes a key, scoped to `tenant_id` so a key can only ever be
    /// revoked by its own tenant. Returns `true` if a row was updated
    /// (i.e. the key exists and belongs to that tenant).
    pub async fn revoke_api_key(&self, tenant_id: Uuid, key_id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query(
            "UPDATE api_keys SET revoked = TRUE WHERE id = $1 AND tenant_id = $2",
        )
        .bind(key_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }

    // ---- Audit logs ----

    pub async fn insert_audit_log(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        principal: &str,
        action: &str,
        resource: &str,
        result: &str,
        reason: Option<&str>,
    ) -> Result<(), DbError> {
        let now = chrono::Utc::now();
        sqlx::query(
            r#"
            INSERT INTO audit_logs (id, tenant_id, principal, action, resource, result, reason, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(principal)
        .bind(action)
        .bind(resource)
        .bind(result)
        .bind(reason)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))?;

        Ok(())
    }

    pub async fn list_audit_logs(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<AuditLogRecord>, DbError> {
        sqlx::query_as::<_, AuditLogRecord>(
            "SELECT id, tenant_id, principal, action, resource, result, reason, created_at FROM audit_logs WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2"
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    // ---- Manifests ----

    pub async fn insert_manifest(
        &self,
        manifest_hash: &str,
        leaf_seq_id: i64,
        tenant_id: Uuid,
        version: &str,
        sbom_hash: &str,
        sbom_format: &str,
        sbom_s3_key: &str,
        namespace: &str,
        previous_manifest_hash: Option<&str>,
        dsse_envelope: &serde_json::Value,
        document_type: Option<&str>,
        created_by: &str,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO manifests (manifest_hash, leaf_seq_id, tenant_id, version, sbom_hash, sbom_format,
                                   sbom_s3_key, namespace, previous_manifest_hash, dsse_envelope, document_type, created_by, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(manifest_hash)
        .bind(leaf_seq_id)
        .bind(tenant_id)
        .bind(version)
        .bind(sbom_hash)
        .bind(sbom_format)
        .bind(sbom_s3_key)
        .bind(namespace)
        .bind(previous_manifest_hash)
        .bind(dsse_envelope)
        .bind(document_type)
        .bind(created_by)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_manifest(
        &self,
        manifest_hash: &str,
    ) -> Result<Option<ManifestRecord>, DbError> {
        sqlx::query_as::<_, ManifestRecord>(
            r#"
            SELECT manifest_hash, leaf_seq_id, tenant_id, version, sbom_hash, sbom_format,
                   sbom_s3_key, namespace, previous_manifest_hash, signature, dsse_envelope, document_type, created_by, created_at,
                   revoked, revoked_at, revoked_by
            FROM manifests
            WHERE manifest_hash = $1
            "#,
        )
        .bind(manifest_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    pub async fn latest_manifest(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<ManifestRecord>, DbError> {
        sqlx::query_as::<_, ManifestRecord>(
            r#"
            SELECT manifest_hash, leaf_seq_id, tenant_id, version, sbom_hash, sbom_format,
                   sbom_s3_key, namespace, previous_manifest_hash, signature, dsse_envelope, document_type, created_by, created_at,
                   revoked, revoked_at, revoked_by
            FROM manifests
            WHERE tenant_id = $1
            ORDER BY created_at DESC, leaf_seq_id DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    /// Most recent non-revoked manifest per namespace, within a tenant and
    /// namespace scope. Unlike `latest_manifest` (tenant-wide single row,
    /// used to chain `previous_manifest_hash` on upload), this groups by
    /// namespace and excludes revoked entries — "what's currently
    /// deployed" per deployable, not "the single latest thing uploaded
    /// anywhere."
    pub async fn latest_manifests_by_namespace(
        &self,
        tenant_id: Uuid,
        namespace_scope: &str,
    ) -> Result<Vec<ManifestRecord>, DbError> {
        sqlx::query_as::<_, ManifestRecord>(
            r#"
            SELECT DISTINCT ON (namespace)
                   manifest_hash, leaf_seq_id, tenant_id, version, sbom_hash, sbom_format,
                   sbom_s3_key, namespace, previous_manifest_hash, signature, dsse_envelope, document_type, created_by, created_at,
                   revoked, revoked_at, revoked_by
            FROM manifests
            WHERE tenant_id = $1
              AND revoked = FALSE
              AND document_type IS NULL
              AND ($2 = '/' OR namespace = $2 OR starts_with(namespace, $2 || '/'))
              AND NOT EXISTS (
                  SELECT 1 FROM namespace_current_hidden h
                  WHERE h.tenant_id = manifests.tenant_id AND h.namespace = manifests.namespace
              )
            ORDER BY namespace, created_at DESC, leaf_seq_id DESC
            "#,
        )
        .bind(tenant_id)
        .bind(namespace_scope)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    /// Every manifest/document matching scope — deliberately uncurated,
    /// for the audit archive export. Unlike `latest_manifests_by_namespace`
    /// this has no `revoked = FALSE`, no `document_type IS NULL`, and no
    /// `namespace_current_hidden` exclusion: an audit export must not be
    /// able to silently miss something because of "currently running"
    /// curation logic (or bugs in it). `namespace_filter`/`version_filter`
    /// are optional further narrowing on top of the caller's own RBAC
    /// `namespace_scope`, which always applies.
    pub async fn list_manifests_for_export(
        &self,
        tenant_id: Uuid,
        namespace_scope: &str,
        namespace_filter: Option<&str>,
        version_filter: Option<&str>,
    ) -> Result<Vec<ManifestRecord>, DbError> {
        sqlx::query_as::<_, ManifestRecord>(
            r#"
            SELECT manifest_hash, leaf_seq_id, tenant_id, version, sbom_hash, sbom_format,
                   sbom_s3_key, namespace, previous_manifest_hash, signature, dsse_envelope, document_type, created_by, created_at,
                   revoked, revoked_at, revoked_by
            FROM manifests
            WHERE tenant_id = $1
              AND ($2 = '/' OR namespace = $2 OR starts_with(namespace, $2 || '/'))
              AND ($3::text IS NULL OR namespace = $3 OR starts_with(namespace, $3 || '/'))
              AND ($4::text IS NULL OR version = $4)
            ORDER BY namespace, created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(namespace_scope)
        .bind(namespace_filter)
        .bind(version_filter)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    /// Namespaces opted out of the "current" view for a tenant, scoped the
    /// same way as `latest_manifests_by_namespace` so a narrowly-scoped key
    /// only sees toggles within its own reach.
    pub async fn list_hidden_namespaces(
        &self,
        tenant_id: Uuid,
        namespace_scope: &str,
    ) -> Result<Vec<String>, DbError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT namespace FROM namespace_current_hidden
            WHERE tenant_id = $1
              AND ($2 = '/' OR namespace = $2 OR starts_with(namespace, $2 || '/'))
            ORDER BY namespace
            "#,
        )
        .bind(tenant_id)
        .bind(namespace_scope)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))?;
        Ok(rows.into_iter().map(|(n,)| n).collect())
    }

    /// Toggles whether a namespace is excluded from the "current" view.
    /// `hidden = true` upserts (refreshing `hidden_by`/`hidden_at` if
    /// already hidden); `hidden = false` deletes the row — namespaces are
    /// visible by default, so "not hidden" means "no row," not a row with
    /// a false flag.
    pub async fn set_namespace_hidden(
        &self,
        tenant_id: Uuid,
        namespace: &str,
        hidden: bool,
        hidden_by: &str,
    ) -> Result<(), DbError> {
        if hidden {
            sqlx::query(
                r#"
                INSERT INTO namespace_current_hidden (tenant_id, namespace, hidden_by, hidden_at)
                VALUES ($1, $2, $3, now())
                ON CONFLICT (tenant_id, namespace)
                DO UPDATE SET hidden_by = EXCLUDED.hidden_by, hidden_at = EXCLUDED.hidden_at
                "#,
            )
            .bind(tenant_id)
            .bind(namespace)
            .bind(hidden_by)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::QueryError(e.to_string()))?;
        } else {
            sqlx::query("DELETE FROM namespace_current_hidden WHERE tenant_id = $1 AND namespace = $2")
                .bind(tenant_id)
                .bind(namespace)
                .execute(&self.pool)
                .await
                .map_err(|e| DbError::QueryError(e.to_string()))?;
        }
        Ok(())
    }

    // ---- Compliance profile settings ----

    /// All settings rows a tenant has ever written. Profiles never touched
    /// aren't included — callers apply the enabled=false/enforce_level="off"
    /// default themselves, since this layer has no notion of which profile
    /// ids exist (that's owned by `magnolia_core::registered_profiles`).
    pub async fn list_compliance_settings(&self, tenant_id: Uuid) -> Result<Vec<ComplianceSettingRecord>, DbError> {
        sqlx::query_as::<_, ComplianceSettingRecord>(
            r#"
            SELECT tenant_id, profile_id, enabled, enforce_level, updated_by, updated_at
            FROM compliance_profile_settings
            WHERE tenant_id = $1
            ORDER BY profile_id
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    pub async fn get_compliance_setting(
        &self,
        tenant_id: Uuid,
        profile_id: &str,
    ) -> Result<Option<ComplianceSettingRecord>, DbError> {
        sqlx::query_as::<_, ComplianceSettingRecord>(
            r#"
            SELECT tenant_id, profile_id, enabled, enforce_level, updated_by, updated_at
            FROM compliance_profile_settings
            WHERE tenant_id = $1 AND profile_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Upserts one profile's setting for a tenant — always writes a row,
    /// never deletes on "off" (two independent values need to persist; see
    /// the migration's header comment for why this differs from
    /// `set_namespace_hidden`'s delete-on-default pattern).
    pub async fn set_compliance_setting(
        &self,
        tenant_id: Uuid,
        profile_id: &str,
        enabled: bool,
        enforce_level: &str,
        updated_by: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO compliance_profile_settings
                (tenant_id, profile_id, enabled, enforce_level, updated_by, updated_at)
            VALUES ($1, $2, $3, $4, $5, now())
            ON CONFLICT (tenant_id, profile_id)
            DO UPDATE SET enabled = EXCLUDED.enabled,
                           enforce_level = EXCLUDED.enforce_level,
                           updated_by = EXCLUDED.updated_by,
                           updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(profile_id)
        .bind(enabled)
        .bind(enforce_level)
        .bind(updated_by)
        .execute(&self.pool)
        .await
        .map_err(map_query_error)?;
        Ok(())
    }

    // ---- Component reverse-search index ----

    /// Batched — a single INSERT for the whole component list of one SBOM,
    /// not one row at a time, so indexing cost stays a single round trip
    /// regardless of component count.
    pub async fn insert_sbom_components(
        &self,
        tenant_id: Uuid,
        manifest_hash: &str,
        components: &[NewSbomComponent],
    ) -> Result<(), DbError> {
        if components.is_empty() {
            return Ok(());
        }
        let mut sql = String::from(
            "INSERT INTO sbom_components (manifest_hash, tenant_id, name, version, purl, cpe, is_primary) VALUES ",
        );
        let mut placeholders = Vec::with_capacity(components.len());
        for i in 0..components.len() {
            let base = i * 5;
            placeholders.push(format!(
                "($1, $2, ${}, ${}, ${}, ${}, ${})",
                base + 3,
                base + 4,
                base + 5,
                base + 6,
                base + 7
            ));
        }
        sql.push_str(&placeholders.join(", "));

        let mut q = sqlx::query(&sql).bind(manifest_hash).bind(tenant_id);
        for c in components {
            q = q
                .bind(&c.name)
                .bind(&c.version)
                .bind(&c.purl)
                .bind(&c.cpe)
                .bind(c.is_primary);
        }
        q.execute(&self.pool).await.map_err(map_query_error)?;
        Ok(())
    }

    /// Component-name prefix (case-insensitive) and/or exact-purl reverse
    /// search, scoped to `namespace_scope` the same way every other
    /// tenant-scoped listing already is. At least one of `name_prefix`/
    /// `purl` should be provided by the caller — this method doesn't
    /// enforce that itself, an unfiltered call just returns everything in
    /// scope (bounded by `limit`).
    pub async fn search_sbom_components(
        &self,
        tenant_id: Uuid,
        namespace_scope: &str,
        namespace_filter: Option<&str>,
        name_contains: Option<&str>,
        component_version: Option<&str>,
        purl: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SbomComponentSearchRow>, DbError> {
        sqlx::query_as::<_, SbomComponentSearchRow>(
            r#"
            SELECT sc.name, sc.version, sc.purl, sc.cpe, sc.is_primary,
                   m.manifest_hash, m.namespace, m.version AS release_version, m.revoked, m.document_type
            FROM sbom_components sc
            JOIN manifests m ON m.manifest_hash = sc.manifest_hash
            WHERE sc.tenant_id = $1
              AND ($2 = '/' OR m.namespace = $2 OR starts_with(m.namespace, $2 || '/'))
              AND ($3::text IS NULL OR m.namespace = $3 OR starts_with(m.namespace, $3 || '/'))
              AND ($4::text IS NULL OR lower(sc.name) LIKE '%' || lower($4) || '%')
              AND ($5::text IS NULL OR sc.version = $5)
              AND ($6::text IS NULL OR sc.purl = $6)
            ORDER BY m.namespace, m.created_at DESC
            LIMIT $7 OFFSET $8
            "#,
        )
        .bind(tenant_id)
        .bind(namespace_scope)
        .bind(namespace_filter)
        .bind(name_contains)
        .bind(component_version)
        .bind(purl)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Manifests with SBOM content (not generic documents) that have no
    /// rows in `sbom_components` yet — used by the one-time reindex
    /// endpoint to backfill manifests uploaded before this feature shipped.
    pub async fn list_manifests_missing_from_component_index(
        &self,
        tenant_id: Uuid,
        namespace_scope: &str,
    ) -> Result<Vec<ManifestRecord>, DbError> {
        sqlx::query_as::<_, ManifestRecord>(
            r#"
            SELECT manifest_hash, leaf_seq_id, tenant_id, version, sbom_hash, sbom_format,
                   sbom_s3_key, namespace, previous_manifest_hash, signature, dsse_envelope, document_type, created_by, created_at,
                   revoked, revoked_at, revoked_by
            FROM manifests
            WHERE tenant_id = $1
              AND document_type IS NULL
              AND ($2 = '/' OR namespace = $2 OR starts_with(namespace, $2 || '/'))
              AND NOT EXISTS (SELECT 1 FROM sbom_components sc WHERE sc.manifest_hash = manifests.manifest_hash)
            ORDER BY created_at
            "#,
        )
        .bind(tenant_id)
        .bind(namespace_scope)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Marks a manifest revoked, scoped to `tenant_id` so it can only be
    /// revoked by (an admin of) its own tenant. Returns `true` if a row was
    /// updated (i.e. it existed, belonged to that tenant, and wasn't
    /// already revoked) — idempotent-safe, never double-stamps.
    pub async fn revoke_manifest(
        &self,
        tenant_id: Uuid,
        manifest_hash: &str,
        revoked_by: &str,
    ) -> Result<bool, DbError> {
        let result = sqlx::query(
            r#"
            UPDATE manifests
            SET revoked = TRUE, revoked_at = NOW(), revoked_by = $1
            WHERE manifest_hash = $2 AND tenant_id = $3 AND revoked = FALSE
            "#,
        )
        .bind(revoked_by)
        .bind(manifest_hash)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }

    // ---- Dependency-Track integration ----

    /// Manifests still needing a dtrack project pushed — CycloneDX only for
    /// v1 (dtrack's SPDX BOM support is unverified), and never revoked
    /// manifests (nothing to gain from scanning something already
    /// superseded). `tenant_id: None` means every tenant (the periodic
    /// loop's own pass); `Some(id)` scopes to one tenant (the "force sync
    /// now" button, so a tenant can only ever trigger work for its own
    /// archive, not everyone else's).
    pub async fn list_manifests_without_dtrack_project(
        &self,
        tenant_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<ManifestRecord>, DbError> {
        sqlx::query_as::<_, ManifestRecord>(
            r#"
            SELECT m.manifest_hash, m.leaf_seq_id, m.tenant_id, m.version, m.sbom_hash, m.sbom_format,
                   m.sbom_s3_key, m.namespace, m.previous_manifest_hash, m.signature, m.dsse_envelope, m.document_type, m.created_by, m.created_at,
                   m.revoked, m.revoked_at, m.revoked_by
            FROM manifests m
            JOIN tenants t ON t.id = m.tenant_id
            WHERE m.sbom_format = 'cyclonedx'
              AND m.revoked = FALSE
              AND t.dtrack_sync_disabled = FALSE
              AND ($1::uuid IS NULL OR m.tenant_id = $1)
              AND m.manifest_hash NOT IN (SELECT manifest_hash FROM dtrack_projects)
            ORDER BY m.created_at
            LIMIT $2
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    pub async fn insert_dtrack_project(&self, manifest_hash: &str, project_uuid: Uuid) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO dtrack_projects (manifest_hash, dtrack_project_uuid) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(manifest_hash)
        .bind(project_uuid)
        .execute(&self.pool)
        .await
        .map_err(map_query_error)?;
        Ok(())
    }

    /// Looks up whether this manifest has a dtrack project at all, and if
    /// so, whether it's ever been refreshed (`last_synced_at`) — lets a
    /// caller distinguish "not synced yet, still pending" from "synced and
    /// genuinely has zero findings" instead of treating an empty
    /// `dtrack_findings` result as always meaning the former (see
    /// `manifest()`'s `dtrack_synced_at` field).
    pub async fn get_dtrack_project(&self, manifest_hash: &str) -> Result<Option<DtrackProjectRecord>, DbError> {
        sqlx::query_as::<_, DtrackProjectRecord>(
            "SELECT manifest_hash, dtrack_project_uuid, pushed_at, last_synced_at
             FROM dtrack_projects WHERE manifest_hash = $1",
        )
        .bind(manifest_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Records why a manifest's push to dtrack failed, replacing any
    /// earlier failure — called from `push_phase` on every failed attempt,
    /// so a permanent rejection (dtrack will never accept this content) is
    /// visible instead of looking identical to "hasn't been picked up yet".
    pub async fn record_dtrack_push_failure(&self, manifest_hash: &str, error: &str) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO dtrack_push_failures (manifest_hash, error, failed_at)
            VALUES ($1, $2, now())
            ON CONFLICT (manifest_hash) DO UPDATE SET error = EXCLUDED.error, failed_at = EXCLUDED.failed_at
            "#,
        )
        .bind(manifest_hash)
        .bind(error)
        .execute(&self.pool)
        .await
        .map_err(map_query_error)?;
        Ok(())
    }

    /// Clears a manifest's recorded push failure — called from `push_phase`
    /// as soon as a push succeeds, since the manifest is no longer stuck.
    pub async fn clear_dtrack_push_failure(&self, manifest_hash: &str) -> Result<(), DbError> {
        sqlx::query("DELETE FROM dtrack_push_failures WHERE manifest_hash = $1")
            .bind(manifest_hash)
            .execute(&self.pool)
            .await
            .map_err(map_query_error)?;
        Ok(())
    }

    pub async fn get_dtrack_push_failure(
        &self,
        manifest_hash: &str,
    ) -> Result<Option<DtrackPushFailureRecord>, DbError> {
        sqlx::query_as::<_, DtrackPushFailureRecord>(
            "SELECT manifest_hash, error, failed_at FROM dtrack_push_failures WHERE manifest_hash = $1",
        )
        .bind(manifest_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Self-heal for a project dtrack no longer knows about (e.g. its own
    /// database was reset independently of Magnolia's) — called when a
    /// refresh pass gets a 404 for a project. Deleting the stale record
    /// makes the manifest eligible for `list_manifests_without_dtrack_project`
    /// again, so the next push phase re-creates the project from scratch
    /// instead of 404ing on the same dead UUID forever.
    pub async fn delete_dtrack_project(&self, manifest_hash: &str) -> Result<(), DbError> {
        sqlx::query("DELETE FROM dtrack_projects WHERE manifest_hash = $1")
            .bind(manifest_hash)
            .execute(&self.pool)
            .await
            .map_err(map_query_error)?;
        Ok(())
    }

    /// Stalest-first (`last_synced_at ASC NULLS FIRST`) so never-synced
    /// projects always get priority each pass.
    /// Excludes projects whose manifest belongs to a tenant that has since
    /// disabled dtrack sync (`dtrack_sync_disabled`) — refresh stops for
    /// that tenant going forward, but existing cached `dtrack_findings`
    /// rows are left untouched (not deleted) so the archive detail view
    /// keeps showing whatever was last synced, same "mark, don't delete"
    /// idiom as `list_manifests_without_dtrack_project`. Same `tenant_id`
    /// scoping convention as that method: `None` = every tenant (periodic
    /// loop), `Some(id)` = just one (force-sync button).
    pub async fn list_dtrack_projects(
        &self,
        tenant_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<DtrackProjectRecord>, DbError> {
        sqlx::query_as::<_, DtrackProjectRecord>(
            r#"
            SELECT dp.manifest_hash, dp.dtrack_project_uuid, dp.pushed_at, dp.last_synced_at
            FROM dtrack_projects dp
            JOIN manifests m ON m.manifest_hash = dp.manifest_hash
            JOIN tenants t ON t.id = m.tenant_id
            WHERE t.dtrack_sync_disabled = FALSE
              AND ($1::uuid IS NULL OR m.tenant_id = $1)
            ORDER BY dp.last_synced_at ASC NULLS FIRST
            LIMIT $2
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    pub async fn touch_dtrack_project_synced(&self, manifest_hash: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE dtrack_projects SET last_synced_at = now() WHERE manifest_hash = $1")
            .bind(manifest_hash)
            .execute(&self.pool)
            .await
            .map_err(map_query_error)?;
        Ok(())
    }

    /// Replaces the cached findings for one manifest with a fresh set from
    /// dtrack. Findings no longer present (remediated, reanalyzed away) are
    /// deleted; findings still present are upserted rather than
    /// delete-then-inserted, so an analyst's `vex_status`/`vex_justification`/
    /// `triaged_by`/`triaged_at` on a still-present finding survives a
    /// routine sync pass instead of being silently wiped.
    pub async fn replace_dtrack_findings(
        &self,
        manifest_hash: &str,
        findings: &[NewDtrackFinding],
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_query_error)?;

        let keys: Vec<String> = findings.iter().map(|f| f.finding_key.clone()).collect();
        sqlx::query("DELETE FROM dtrack_findings WHERE manifest_hash = $1 AND NOT (finding_key = ANY($2))")
            .bind(manifest_hash)
            .bind(&keys)
            .execute(&mut *tx)
            .await
            .map_err(map_query_error)?;

        for f in findings {
            sqlx::query(
                r#"
                INSERT INTO dtrack_findings
                    (manifest_hash, finding_key, component_name, component_version,
                     vulnerability_id, severity, description, analysis_state, synced_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
                ON CONFLICT (manifest_hash, finding_key)
                DO UPDATE SET component_name = EXCLUDED.component_name,
                               component_version = EXCLUDED.component_version,
                               vulnerability_id = EXCLUDED.vulnerability_id,
                               severity = EXCLUDED.severity,
                               description = EXCLUDED.description,
                               analysis_state = EXCLUDED.analysis_state,
                               synced_at = EXCLUDED.synced_at
                "#,
            )
            .bind(manifest_hash)
            .bind(&f.finding_key)
            .bind(&f.component_name)
            .bind(&f.component_version)
            .bind(&f.vulnerability_id)
            .bind(&f.severity)
            .bind(&f.description)
            .bind(&f.analysis_state)
            .execute(&mut *tx)
            .await
            .map_err(map_query_error)?;
        }

        tx.commit().await.map_err(map_query_error)?;
        Ok(())
    }

    pub async fn list_dtrack_findings(&self, manifest_hash: &str) -> Result<Vec<DtrackFindingRecord>, DbError> {
        sqlx::query_as::<_, DtrackFindingRecord>(
            r#"
            SELECT manifest_hash, finding_key, component_name, component_version,
                   vulnerability_id, severity, description, analysis_state, synced_at,
                   vex_status, vex_justification, triaged_by, triaged_at
            FROM dtrack_findings
            WHERE manifest_hash = $1
            ORDER BY severity, vulnerability_id
            "#,
        )
        .bind(manifest_hash)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Every cached finding across the tenant's archive (within
    /// `namespace_scope`), for the standalone Findings tab — unlike
    /// `list_dtrack_findings` above, which is always scoped to one
    /// already-known, already-authorized manifest. Severity filter is
    /// case-insensitive exact match (dtrack's own vocabulary is uppercase,
    /// e.g. "CRITICAL"/"HIGH", but this doesn't assume callers get the case
    /// right). Critical-first ordering, since this view exists for triage
    /// review — most-urgent-first is far more useful here than the
    /// alphabetical order `list_dtrack_findings` uses for a single
    /// manifest's much shorter list.
    pub async fn list_findings_for_tenant(
        &self,
        tenant_id: Uuid,
        namespace_scope: &str,
        severity: Option<&str>,
        manifest_hash: Option<&str>,
        namespace_filter: Option<&str>,
        release_version_filter: Option<&str>,
        // "untriaged" matches vex_status IS NULL; any other value is
        // matched exactly against the vex_status column.
        vex_status_filter: Option<&str>,
        // When true, only findings on each namespace's currently-running
        // manifest are returned — same "latest non-revoked upload per
        // namespace" definition as `latest_manifests_by_namespace`/the
        // Dashboard's "currently running" view, reused here (not
        // duplicated) via the identical DISTINCT ON query as a subquery.
        // Old versions can still carry real findings worth knowing about
        // (what was running and attackable at the time), so this narrows
        // the *default* triage view rather than deleting/hiding that
        // history anywhere else.
        current_only: bool,
        // When true, only the single newest non-revoked manifest per
        // namespace is returned — an unconditional guarantee, unlike
        // `current_only` above, which additionally respects the
        // admin-curated `namespace_current_hidden` exclusion (a namespace
        // hidden from "currently running" drops out of `current_only`
        // entirely, but this still shows its newest version). Deliberately
        // duplicates `current_only`'s DISTINCT ON pattern rather than
        // reusing it, since the two intentionally differ by exactly that
        // one clause.
        hide_stale: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DtrackFindingWithContextRecord>, DbError> {
        sqlx::query_as::<_, DtrackFindingWithContextRecord>(
            r#"
            SELECT df.manifest_hash, df.finding_key, df.component_name, df.component_version,
                   df.vulnerability_id, df.severity, df.description, df.analysis_state, df.synced_at,
                   df.vex_status, df.vex_justification, df.triaged_by, df.triaged_at,
                   m.namespace, m.version AS release_version, m.revoked,
                   (SELECT count(*) FROM finding_comments fc
                    WHERE fc.manifest_hash = df.manifest_hash AND fc.finding_key = df.finding_key) AS comment_count
            FROM dtrack_findings df
            JOIN manifests m ON m.manifest_hash = df.manifest_hash
            WHERE m.tenant_id = $1
              AND ($2 = '/' OR m.namespace = $2 OR starts_with(m.namespace, $2 || '/'))
              -- $3 accepts a comma-separated list (e.g. "CRITICAL,HIGH" for
              -- the frontend's "critical + high" quick filter) as well as a
              -- single value — both go through the same array match.
              AND ($3::text IS NULL OR upper(df.severity) = ANY(string_to_array(upper($3), ',')))
              AND ($6::text IS NULL OR df.manifest_hash = $6)
              AND ($7::text IS NULL OR m.namespace = $7 OR starts_with(m.namespace, $7 || '/'))
              AND ($8::text IS NULL OR m.version = $8)
              AND (
                $9::text IS NULL
                OR ($9 = 'untriaged' AND df.vex_status IS NULL)
                OR df.vex_status = $9
              )
              AND (
                $10::bool IS NOT TRUE
                OR m.manifest_hash IN (
                  SELECT DISTINCT ON (namespace) manifest_hash
                  FROM manifests
                  WHERE tenant_id = $1
                    AND revoked = FALSE
                    AND document_type IS NULL
                    AND NOT EXISTS (
                      SELECT 1 FROM namespace_current_hidden h
                      WHERE h.tenant_id = manifests.tenant_id AND h.namespace = manifests.namespace
                    )
                  ORDER BY namespace, created_at DESC, leaf_seq_id DESC
                )
              )
              AND (
                $11::bool IS NOT TRUE
                OR m.manifest_hash IN (
                  SELECT DISTINCT ON (namespace) manifest_hash
                  FROM manifests
                  WHERE tenant_id = $1
                    AND revoked = FALSE
                    AND document_type IS NULL
                  ORDER BY namespace, created_at DESC, leaf_seq_id DESC
                )
              )
            ORDER BY
              CASE upper(df.severity)
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                WHEN 'INFO' THEN 4
                ELSE 5
              END,
              df.vulnerability_id
            LIMIT $4 OFFSET $5
            "#,
        )
        .bind(tenant_id)
        .bind(namespace_scope)
        .bind(severity)
        .bind(limit)
        .bind(offset)
        .bind(manifest_hash)
        .bind(namespace_filter)
        .bind(release_version_filter)
        .bind(vex_status_filter)
        .bind(current_only)
        .bind(hide_stale)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Adds one comment to a finding's discussion thread. `None` if the
    /// finding doesn't exist (never posted, or since resolved away by a
    /// dtrack sync) — resolved to `ApiError::NotFound` at the handler layer,
    /// matching `set_finding_triage`'s convention.
    pub async fn add_finding_comment(
        &self,
        manifest_hash: &str,
        finding_key: &str,
        author: &str,
        body: &str,
    ) -> Result<Option<FindingCommentRecord>, DbError> {
        sqlx::query_as::<_, FindingCommentRecord>(
            r#"
            INSERT INTO finding_comments (id, manifest_hash, finding_key, author, body)
            SELECT $1, $2, $3, $4, $5
            WHERE EXISTS (
                SELECT 1 FROM dtrack_findings WHERE manifest_hash = $2 AND finding_key = $3
            )
            RETURNING id, manifest_hash, finding_key, author, body, created_at
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(manifest_hash)
        .bind(finding_key)
        .bind(author)
        .bind(body)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_query_error)
    }

    pub async fn list_finding_comments(
        &self,
        manifest_hash: &str,
        finding_key: &str,
    ) -> Result<Vec<FindingCommentRecord>, DbError> {
        sqlx::query_as::<_, FindingCommentRecord>(
            r#"
            SELECT id, manifest_hash, finding_key, author, body, created_at
            FROM finding_comments
            WHERE manifest_hash = $1 AND finding_key = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(manifest_hash)
        .bind(finding_key)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Sets this tenant's VEX-style triage on one finding. `None` if the
    /// finding no longer exists (e.g. resolved by a later dtrack sync) —
    /// resolved to `ApiError::NotFound` at the handler layer.
    pub async fn set_finding_triage(
        &self,
        manifest_hash: &str,
        finding_key: &str,
        vex_status: &str,
        justification: Option<&str>,
        triaged_by: &str,
    ) -> Result<Option<DtrackFindingRecord>, DbError> {
        sqlx::query_as::<_, DtrackFindingRecord>(
            r#"
            UPDATE dtrack_findings
            SET vex_status = $1, vex_justification = $2, triaged_by = $3, triaged_at = now()
            WHERE manifest_hash = $4 AND finding_key = $5
            RETURNING manifest_hash, finding_key, component_name, component_version,
                      vulnerability_id, severity, description, analysis_state, synced_at,
                      vex_status, vex_justification, triaged_by, triaged_at
            "#,
        )
        .bind(vex_status)
        .bind(justification)
        .bind(triaged_by)
        .bind(manifest_hash)
        .bind(finding_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_query_error)
    }
}