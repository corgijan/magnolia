mod models;
mod errors;

pub use models::{
    AffectedManifestRow, ApiKeyRecord, AuditLogRecord, ComplianceSettingRecord, ComponentFreshnessRecord,
    ComponentFreshnessStatus, ComponentIdentity,
    ComponentReputationRecord, DtrackFindingRecord, DtrackFindingWithContextRecord,
    DtrackProjectRecord, DtrackPushFailureRecord, DueWebhookDelivery, FindingCommentRecord, ManifestRecord,
    MaliciousCheckStatus, MaliciousFindingRecord, MerkleLeafRecord, MerkleNodeRecord, NewDtrackFinding,
    ManifestVersionRow, NewMaliciousFinding, NewSbomComponent, RegisteredNamespaceRecord,
    ComponentReputationSummaryRow, ReputationStatus, SbomComponentRow, SbomComponentSearchRow,
    SignedTreeHeadRecord, TenantLicensePolicyRecord, TenantRecord, WebhookDeliveryRecord,
    WebhookEndpointRecord,
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
            "SELECT id, domain, name, created_by, created_at, is_platform, hidden, dtrack_sync_disabled, require_semver_version, reputation_disabled, require_namespace_registration, malicious_check_disabled, freshness_disabled FROM tenants WHERE id = $1",
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
            "SELECT id, domain, name, created_by, created_at, is_platform, hidden, dtrack_sync_disabled, require_semver_version, reputation_disabled, require_namespace_registration, malicious_check_disabled, freshness_disabled FROM tenants WHERE domain = $1",
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
            "SELECT id, domain, name, created_by, created_at, is_platform, hidden, dtrack_sync_disabled, require_semver_version, reputation_disabled, require_namespace_registration, malicious_check_disabled, freshness_disabled FROM tenants WHERE hidden = FALSE ORDER BY created_at DESC",
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

    /// Per-tenant toggle requiring `upload_sbom`'s `version` field to be
    /// SemVer 2.0.0-compliant (on by default; see the `require_semver_version` migration
    /// comment).
    pub async fn set_tenant_require_semver_version(&self, tenant_id: Uuid, required: bool) -> Result<(), DbError> {
        sqlx::query("UPDATE tenants SET require_semver_version = $1 WHERE id = $2")
            .bind(required)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::QueryError(e.to_string()))?;
        Ok(())
    }

    /// Per-tenant opt-out of the "Package reputation" panel appearing on
    /// this tenant's SBOM detail views (see the `reputation_disabled`
    /// migration comment) — unlike `set_tenant_dtrack_sync_disabled`, this
    /// has no effect on the background job itself, only on display.
    pub async fn set_tenant_reputation_disabled(&self, tenant_id: Uuid, disabled: bool) -> Result<(), DbError> {
        sqlx::query("UPDATE tenants SET reputation_disabled = $1 WHERE id = $2")
            .bind(disabled)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::QueryError(e.to_string()))?;
        Ok(())
    }

    /// Per-tenant opt-out of the "malicious package" panel appearing on
    /// this tenant's SBOM detail views (see the `malicious_check_disabled`
    /// migration comment) — same display-only shape as
    /// `set_tenant_reputation_disabled`: detection at upload time is
    /// untouched either way.
    pub async fn set_tenant_malicious_check_disabled(&self, tenant_id: Uuid, disabled: bool) -> Result<(), DbError> {
        sqlx::query("UPDATE tenants SET malicious_check_disabled = $1 WHERE id = $2")
            .bind(disabled)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::QueryError(e.to_string()))?;
        Ok(())
    }

    /// Per-tenant opt-out of the "Outdated components" panel appearing on
    /// this tenant's SBOM detail views (see the `freshness_disabled`
    /// migration comment) — same display-only shape as
    /// `set_tenant_reputation_disabled`: the background freshness job is
    /// untouched either way.
    pub async fn set_tenant_freshness_disabled(&self, tenant_id: Uuid, disabled: bool) -> Result<(), DbError> {
        sqlx::query("UPDATE tenants SET freshness_disabled = $1 WHERE id = $2")
            .bind(disabled)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::QueryError(e.to_string()))?;
        Ok(())
    }

    /// Per-tenant opt-in requiring `upload_sbom`'s target namespace to
    /// already exist in `registered_namespaces` (see that table's migration
    /// comment).
    pub async fn set_tenant_require_namespace_registration(&self, tenant_id: Uuid, required: bool) -> Result<(), DbError> {
        sqlx::query("UPDATE tenants SET require_namespace_registration = $1 WHERE id = $2")
            .bind(required)
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

    /// Finds a key by its stored hash — the lookup path for `mag_`-prefixed
    /// tokens, which (unlike the legacy `<key_id>:<secret>` form) don't
    /// carry a row id for us to select on.
    ///
    /// This is only possible because key hashes are deterministic and
    /// unsalted (see `ApiKey::hash`): the caller can compute the exact
    /// stored value from the token alone. It would not work against the
    /// salted Argon2 rows, which is precisely why those keep using
    /// `lookup_api_key` by id.
    ///
    /// Matching on the hash rather than the secret means the secret itself
    /// is never sent to the database, never appears in a query log, and
    /// never sits in a bind parameter.
    pub async fn lookup_api_key_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<ApiKeyRecord>, DbError> {
        sqlx::query_as::<_, ApiKeyRecord>(
            r#"
            SELECT id, tenant_id, domain, namespace_scope, role, key_hash,
                   expires_at, revoked, created_at
            FROM api_keys
            WHERE key_hash = $1
            "#,
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

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

    /// The manifest immediately before a given point in one namespace's own
    /// upload history (ordered by `created_at`, `leaf_seq_id` as tiebreaker)
    /// — unlike `previous_manifest_hash` on `manifests` itself, which chains
    /// the tenant-wide append-order log, not per-namespace version history.
    /// Used by `manifest_diff`'s default "diff against the previous
    /// version" when no explicit `against` is given. Includes revoked
    /// manifests — they're still real history of what was there before.
    pub async fn get_previous_manifest_in_namespace(
        &self,
        tenant_id: Uuid,
        namespace: &str,
        before_created_at: chrono::DateTime<chrono::Utc>,
        before_leaf_seq_id: i64,
    ) -> Result<Option<ManifestRecord>, DbError> {
        sqlx::query_as::<_, ManifestRecord>(
            r#"
            SELECT manifest_hash, leaf_seq_id, tenant_id, version, sbom_hash, sbom_format,
                   sbom_s3_key, namespace, previous_manifest_hash, signature, dsse_envelope, document_type, created_by, created_at,
                   revoked, revoked_at, revoked_by
            FROM manifests
            WHERE tenant_id = $1
              AND namespace = $2
              AND (created_at, leaf_seq_id) < ($3, $4)
            ORDER BY created_at DESC, leaf_seq_id DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(namespace)
        .bind(before_created_at)
        .bind(before_leaf_seq_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    /// Every real-SBOM manifest (`document_type IS NULL`) ever uploaded to
    /// one exact namespace, newest first — backs the diff UI's "choose which
    /// version to diff against" picker. Exact match, not prefix, unlike most
    /// namespace-scoped listings here: a version picker for namespace
    /// `/a` showing manifests from `/a/b` too would be confusing, not useful.
    pub async fn list_manifest_versions_in_namespace(
        &self,
        tenant_id: Uuid,
        namespace: &str,
    ) -> Result<Vec<ManifestVersionRow>, DbError> {
        sqlx::query_as::<_, ManifestVersionRow>(
            r#"
            SELECT manifest_hash, version, created_at, revoked
            FROM manifests
            WHERE tenant_id = $1 AND namespace = $2 AND document_type IS NULL
            ORDER BY created_at DESC, leaf_seq_id DESC
            "#,
        )
        .bind(tenant_id)
        .bind(namespace)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
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

    // ---- Namespace registry (see `registered_namespaces`'s migration comment) ----

    pub async fn list_registered_namespaces(
        &self,
        tenant_id: Uuid,
        namespace_scope: &str,
    ) -> Result<Vec<RegisteredNamespaceRecord>, DbError> {
        sqlx::query_as::<_, RegisteredNamespaceRecord>(
            r#"
            SELECT namespace, created_by, created_at FROM registered_namespaces
            WHERE tenant_id = $1
              AND ($2 = '/' OR namespace = $2 OR starts_with(namespace, $2 || '/'))
            ORDER BY namespace
            "#,
        )
        .bind(tenant_id)
        .bind(namespace_scope)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Registers one namespace. Returns `false` (not an error) if it was
    /// already registered — idempotent, so a caller doesn't need to check
    /// existence first to avoid a conflict.
    pub async fn create_namespace(&self, tenant_id: Uuid, namespace: &str, created_by: &str) -> Result<bool, DbError> {
        let result = sqlx::query(
            r#"
            INSERT INTO registered_namespaces (tenant_id, namespace, created_by, created_at)
            VALUES ($1, $2, $3, now())
            ON CONFLICT (tenant_id, namespace) DO NOTHING
            "#,
        )
        .bind(tenant_id)
        .bind(namespace)
        .bind(created_by)
        .execute(&self.pool)
        .await
        .map_err(map_query_error)?;
        Ok(result.rows_affected() > 0)
    }

    /// Un-registers one namespace. Returns `false` (not an error) if it
    /// wasn't registered to begin with — same idempotent shape as
    /// `create_namespace`. The only way to recover from registering the
    /// wrong namespace (a typo, most commonly) once `require_namespace_registration`
    /// is on, since a registered namespace otherwise has no expiry.
    pub async fn delete_namespace(&self, tenant_id: Uuid, namespace: &str) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM registered_namespaces WHERE tenant_id = $1 AND namespace = $2")
            .bind(tenant_id)
            .bind(namespace)
            .execute(&self.pool)
            .await
            .map_err(map_query_error)?;
        Ok(result.rows_affected() > 0)
    }

    /// Clears this tenant's component-search index (`sbom_components`) —
    /// paired with `reindex_components`/`index_manifest_components`, which
    /// only ever add rows; this is the way back if the index needs to be
    /// rebuilt from scratch. Component Search returns nothing for this
    /// tenant until a fresh upload or a manual reindex repopulates it.
    /// Returns rows deleted.
    pub async fn clear_component_index(&self, tenant_id: Uuid) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM sbom_components WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(map_query_error)?;
        Ok(result.rows_affected())
    }

    /// Clears this tenant's cached malicious-package findings
    /// (`malicious_component_findings`) — that table only carries
    /// `manifest_hash`, not `tenant_id`, so scoping goes through
    /// `manifests`. The next OSV sync/upload repopulates from scratch;
    /// since `insert_malicious_findings` treats a fresh insert as "newly
    /// seen," clearing this can make previously-known `MAL-` hits re-fire
    /// `malicious.match_found` webhooks on the next sync. Returns rows
    /// deleted.
    pub async fn clear_malicious_findings_for_tenant(&self, tenant_id: Uuid) -> Result<u64, DbError> {
        let result = sqlx::query(
            "DELETE FROM malicious_component_findings \
             WHERE manifest_hash IN (SELECT manifest_hash FROM manifests WHERE tenant_id = $1)",
        )
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(map_query_error)?;
        Ok(result.rows_affected())
    }

    /// Clears this tenant's cached Dependency-Track data (`dtrack_findings`
    /// + `dtrack_projects`, both scoped via `manifests` the same way
    /// `clear_malicious_findings_for_tenant` is) — the next dtrack sync
    /// pass repopulates both from the live dtrack server; the actual
    /// project in Dependency-Track itself is untouched, only this app's
    /// record of having pushed/synced it. `dtrack_findings` cascades to
    /// `finding_comments` (`ON DELETE CASCADE`), so any manual triage
    /// comments on those findings are permanently lost, not just the
    /// findings themselves. Returns `(findings_deleted, projects_deleted)`.
    pub async fn clear_dtrack_cache_for_tenant(&self, tenant_id: Uuid) -> Result<(u64, u64), DbError> {
        let findings = sqlx::query(
            "DELETE FROM dtrack_findings \
             WHERE manifest_hash IN (SELECT manifest_hash FROM manifests WHERE tenant_id = $1)",
        )
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(map_query_error)?
        .rows_affected();
        let projects = sqlx::query(
            "DELETE FROM dtrack_projects \
             WHERE manifest_hash IN (SELECT manifest_hash FROM manifests WHERE tenant_id = $1)",
        )
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(map_query_error)?
        .rows_affected();
        Ok((findings, projects))
    }

    /// Exact-match existence check, used by `upload_sbom` when this tenant
    /// has `require_namespace_registration` set — deliberately not a
    /// prefix/scope match like the listing/read methods above: a namespace
    /// being registered doesn't implicitly register its children.
    pub async fn namespace_is_registered(&self, tenant_id: Uuid, namespace: &str) -> Result<bool, DbError> {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM registered_namespaces WHERE tenant_id = $1 AND namespace = $2)",
        )
        .bind(tenant_id)
        .bind(namespace)
        .fetch_one(&self.pool)
        .await
        .map_err(map_query_error)
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

    /// `None` when this tenant has never set a policy — callers treat that
    /// the same as an explicit `enforce_level = 'off'`, empty deny-list.
    pub async fn get_tenant_license_policy(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<TenantLicensePolicyRecord>, DbError> {
        sqlx::query_as::<_, TenantLicensePolicyRecord>(
            r#"
            SELECT tenant_id, denied_licenses, unknown_license_handling, enforce_level, updated_by, updated_at
            FROM tenant_license_policies
            WHERE tenant_id = $1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Upserts a tenant's license policy — always writes a row, same
    /// "off is a persisted state, not an absence" convention as
    /// `set_compliance_setting`. `unknown_license_handling` is validated by
    /// the caller (API layer) against "ignore"/"warn"/"flag" — this layer
    /// just persists whatever string it's given, same as `enforce_level`.
    pub async fn set_tenant_license_policy(
        &self,
        tenant_id: Uuid,
        denied_licenses: &[String],
        unknown_license_handling: &str,
        enforce_level: &str,
        updated_by: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO tenant_license_policies
                (tenant_id, denied_licenses, unknown_license_handling, enforce_level, updated_by, updated_at)
            VALUES ($1, $2, $3, $4, $5, now())
            ON CONFLICT (tenant_id)
            DO UPDATE SET denied_licenses = EXCLUDED.denied_licenses,
                           unknown_license_handling = EXCLUDED.unknown_license_handling,
                           enforce_level = EXCLUDED.enforce_level,
                           updated_by = EXCLUDED.updated_by,
                           updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(denied_licenses)
        .bind(unknown_license_handling)
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
            "INSERT INTO sbom_components \
             (manifest_hash, tenant_id, name, version, purl, cpe, is_primary, ecosystem, registry_name, license_expr) VALUES ",
        );
        let mut placeholders = Vec::with_capacity(components.len());
        for i in 0..components.len() {
            let base = i * 8;
            placeholders.push(format!(
                "($1, $2, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                base + 3,
                base + 4,
                base + 5,
                base + 6,
                base + 7,
                base + 8,
                base + 9,
                base + 10
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
                .bind(c.is_primary)
                .bind(&c.ecosystem)
                .bind(&c.registry_name)
                .bind(&c.license_expr);
        }
        q.execute(&self.pool).await.map_err(map_query_error)?;
        Ok(())
    }

    /// One manifest's full indexed component list, unfiltered — used by
    /// `manifest_diff` to compare exactly two manifests, unlike
    /// `search_sbom_components` below which searches across the archive.
    pub async fn list_sbom_components_for_manifest(
        &self,
        manifest_hash: &str,
    ) -> Result<Vec<SbomComponentRow>, DbError> {
        sqlx::query_as::<_, SbomComponentRow>(
            "SELECT name, version, purl, cpe, is_primary FROM sbom_components WHERE manifest_hash = $1",
        )
        .bind(manifest_hash)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Stores this manifest's malicious-component matches from the one-shot
    /// OSV batched query run at upload time (see `SUPPLY_CHAIN_SIGNALS_PLAN.md`).
    /// A no-op for an empty list — most manifests will have zero hits, and
    /// callers pass whatever they found without checking emptiness first.
    /// Returns only the findings genuinely new in this call (the
    /// `ON CONFLICT DO NOTHING ... RETURNING` rows) — a manifest re-checked
    /// by `malicious_sync`'s periodic rescan re-submits already-known
    /// matches every pass, and callers emitting a `malicious.match_found`
    /// webhook event need to fire on a first sighting, not every rescan.
    pub async fn insert_malicious_findings(
        &self,
        manifest_hash: &str,
        findings: &[NewMaliciousFinding],
    ) -> Result<Vec<MaliciousFindingRecord>, DbError> {
        if findings.is_empty() {
            return Ok(Vec::new());
        }
        let mut sql = String::from(
            "INSERT INTO malicious_component_findings \
             (manifest_hash, component_name, component_version, purl, osv_id, summary) VALUES ",
        );
        let mut placeholders = Vec::with_capacity(findings.len());
        for i in 0..findings.len() {
            let base = i * 5;
            placeholders.push(format!(
                "($1, ${}, ${}, ${}, ${}, ${})",
                base + 2,
                base + 3,
                base + 4,
                base + 5,
                base + 6
            ));
        }
        sql.push_str(&placeholders.join(", "));
        sql.push_str(
            " ON CONFLICT (manifest_hash, component_name, component_version, osv_id) DO NOTHING \
             RETURNING component_name, component_version, purl, osv_id, summary, detected_at",
        );

        let mut q = sqlx::query_as::<_, MaliciousFindingRecord>(&sql).bind(manifest_hash);
        for f in findings {
            q = q.bind(&f.component_name).bind(&f.component_version).bind(&f.purl).bind(&f.osv_id).bind(&f.summary);
        }
        q.fetch_all(&self.pool).await.map_err(map_query_error)
    }

    pub async fn list_malicious_findings(&self, manifest_hash: &str) -> Result<Vec<MaliciousFindingRecord>, DbError> {
        sqlx::query_as::<_, MaliciousFindingRecord>(
            "SELECT component_name, component_version, purl, osv_id, summary, detected_at
             FROM malicious_component_findings WHERE manifest_hash = $1
             ORDER BY component_name",
        )
        .bind(manifest_hash)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Manifest hashes needing a malicious-package (re)scan — either never
    /// checked (`malicious_checked_at IS NULL`, covering the whole archive
    /// uploaded before this column existed) or checked before
    /// `stale_before` — the malicious-sync background job's work queue.
    /// Only real SBOMs are candidates (`document_type IS NULL`, matching
    /// the "malicious package" panel's own gate) and only active ones
    /// (revoked manifests don't need rescanning). Oldest-checked-first
    /// (`NULLS FIRST`) so the never-checked backlog drains before anything
    /// already-checked gets re-checked.
    pub async fn list_manifests_needing_malicious_check(
        &self,
        stale_before: chrono::DateTime<chrono::Utc>,
        limit: i64,
    ) -> Result<Vec<String>, DbError> {
        sqlx::query_scalar(
            r#"
            SELECT manifest_hash FROM manifests
            WHERE document_type IS NULL
              AND revoked = FALSE
              AND (malicious_checked_at IS NULL OR malicious_checked_at < $1)
            ORDER BY malicious_checked_at ASC NULLS FIRST
            LIMIT $2
            "#,
        )
        .bind(stale_before)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Records that a malicious-package check (upload-time or a
    /// `malicious_sync` rescan pass) just completed for this manifest — see
    /// the `malicious_checked_at` migration comment.
    pub async fn touch_manifest_malicious_checked(&self, manifest_hash: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE manifests SET malicious_checked_at = now() WHERE manifest_hash = $1")
            .bind(manifest_hash)
            .execute(&self.pool)
            .await
            .map_err(map_query_error)?;
        Ok(())
    }

    /// Deployment-wide counts for the Settings UI's malicious-check status
    /// display — see `MaliciousCheckStatus`'s field docs. The `pending`
    /// subquery mirrors `list_manifests_needing_malicious_check`'s
    /// definition exactly (minus the `LIMIT`), so the two never disagree.
    pub async fn malicious_check_status(
        &self,
        stale_before: chrono::DateTime<chrono::Utc>,
    ) -> Result<MaliciousCheckStatus, DbError> {
        sqlx::query_as::<_, MaliciousCheckStatus>(
            r#"
            SELECT
                (SELECT COUNT(*) FROM manifests
                    WHERE document_type IS NULL AND revoked = FALSE
                      AND (malicious_checked_at IS NULL OR malicious_checked_at < $1)) AS pending,
                (SELECT COUNT(*) FROM manifests
                    WHERE document_type IS NULL AND revoked = FALSE
                      AND malicious_checked_at >= $1) AS checked
            "#,
        )
        .bind(stale_before)
        .fetch_one(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// `sbom_components` rows with a purl that were never run through
    /// `purl_to_depsdev_package` — the main case is a row inserted before
    /// the `ecosystem`/`registry_name` columns existed (they have no
    /// backfill in their own migration), but also covers any row inserted
    /// before this backfill phase shipped. `ecosystem IS NULL` unambiguously
    /// means "never attempted": a purl that *was* checked and had no
    /// deps.dev mapping is stored as `ecosystem = ''` (empty string, not
    /// NULL — see `index_manifest_components`), specifically so it's never
    /// re-selected here. `list_components_needing_reputation` and
    /// `manifest_reputation`/`reputation_status`'s own queries are
    /// unaffected either way, since they also require `registry_name IS NOT
    /// NULL`, which a no-mapping purl never gets regardless of which
    /// sentinel `ecosystem` uses.
    pub async fn list_sbom_components_missing_ecosystem(&self, limit: i64) -> Result<Vec<(i64, String)>, DbError> {
        sqlx::query_as::<_, (i64, String)>(
            "SELECT id, purl FROM sbom_components WHERE purl IS NOT NULL AND purl <> '' AND ecosystem IS NULL LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Records the result of (re)running `purl_to_depsdev_package` against
    /// one `sbom_components` row — see `list_sbom_components_missing_ecosystem`.
    pub async fn set_sbom_component_ecosystem(
        &self,
        id: i64,
        ecosystem: Option<&str>,
        registry_name: Option<&str>,
    ) -> Result<(), DbError> {
        sqlx::query("UPDATE sbom_components SET ecosystem = $1, registry_name = $2 WHERE id = $3")
            .bind(ecosystem)
            .bind(registry_name)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_query_error)?;
        Ok(())
    }

    /// Distinct (ecosystem, registry_name) pairs across the whole
    /// deployment's `sbom_components` that either have no `component_reputation`
    /// row yet, one older than `stale_before`, or one that previously failed
    /// (`fetch_error IS NOT NULL`) — the reputation background job's work
    /// queue. A failed row skips the `stale_before` wait entirely so a
    /// transient deps.dev error (network blip, rate limit) gets retried on
    /// the very next tick instead of sitting failed for up to
    /// `STALE_AFTER_DAYS`; a persistently-failing package just keeps costing
    /// one retry per tick; no separate backoff — the tick interval itself
    /// (an hour by default) is the rate limit. Deployment-global (no tenant
    /// filter): a package's score doesn't depend on which tenant uploaded
    /// it, so this is shared across every tenant's components.
    pub async fn list_components_needing_reputation(
        &self,
        stale_before: chrono::DateTime<chrono::Utc>,
        limit: i64,
    ) -> Result<Vec<ComponentIdentity>, DbError> {
        sqlx::query_as::<_, ComponentIdentity>(
            r#"
            SELECT DISTINCT ON (sc.ecosystem, sc.registry_name)
                   sc.ecosystem, sc.registry_name, sc.version AS sample_version
            FROM sbom_components sc
            LEFT JOIN component_reputation cr
                ON cr.ecosystem = sc.ecosystem AND cr.name = sc.registry_name
            WHERE sc.ecosystem IS NOT NULL
              AND sc.registry_name IS NOT NULL
              AND sc.version IS NOT NULL
              AND (cr.ecosystem IS NULL OR cr.checked_at < $1 OR cr.fetch_error IS NOT NULL)
            ORDER BY sc.ecosystem, sc.registry_name, sc.version DESC
            LIMIT $2
            "#,
        )
        .bind(stale_before)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Deployment-wide counts for the Settings UI's reputation status
    /// display — see `ReputationStatus`'s field docs. The `pending`
    /// subquery mirrors `list_components_needing_reputation`'s definition
    /// exactly (minus the `LIMIT`), so the two never disagree about what
    /// counts as "still needs checking."
    pub async fn reputation_status(
        &self,
        stale_before: chrono::DateTime<chrono::Utc>,
    ) -> Result<ReputationStatus, DbError> {
        sqlx::query_as::<_, ReputationStatus>(
            r#"
            SELECT
                (SELECT COUNT(*) FROM (
                    SELECT DISTINCT sc.ecosystem, sc.registry_name
                    FROM sbom_components sc
                    LEFT JOIN component_reputation cr
                        ON cr.ecosystem = sc.ecosystem AND cr.name = sc.registry_name
                    WHERE sc.ecosystem IS NOT NULL
                      AND sc.registry_name IS NOT NULL
                      AND (cr.ecosystem IS NULL OR cr.checked_at < $1 OR cr.fetch_error IS NOT NULL)
                ) pending_rows) AS pending,
                (SELECT COUNT(*) FROM component_reputation WHERE fetch_error IS NULL) AS checked,
                (SELECT COUNT(*) FROM component_reputation WHERE fetch_error IS NOT NULL) AS failed
            "#,
        )
        .bind(stale_before)
        .fetch_one(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Every package with a cached Scorecard score, deployment-wide,
    /// ascending by score (lowest/worst first) — backs the Settings page's
    /// aggregation modal. Excludes packages the job has checked but found no
    /// scorecard for (`scorecard_score IS NULL`) — nothing to rank those by.
    pub async fn list_all_reputation(&self) -> Result<Vec<ComponentReputationSummaryRow>, DbError> {
        sqlx::query_as::<_, ComponentReputationSummaryRow>(
            r#"
            SELECT ecosystem, name, scorecard_score, project_repo, checked_at
            FROM component_reputation
            WHERE scorecard_score IS NOT NULL
            ORDER BY scorecard_score ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Scored packages that actually appear in *this tenant's* SBOMs.
    ///
    /// `component_reputation` is deliberately not tenant-scoped — a
    /// package's Scorecard score is a property of the package, not of who
    /// uploaded it, so one row serves every tenant. That makes it cheap to
    /// cache but means it must never be listed raw to a tenant: doing so
    /// enumerates every dependency of every *other* tenant on the
    /// deployment. This joins through `sbom_components` so a tenant only
    /// ever sees packages it has itself uploaded.
    ///
    /// `DISTINCT` because one package typically appears in many of a
    /// tenant's manifests. The join key is
    /// `(ecosystem, registry_name)` — the same pair `reputation_sync`
    /// writes rows under (see `backfill_ecosystem_phase`).
    pub async fn list_reputation_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<ComponentReputationSummaryRow>, DbError> {
        sqlx::query_as::<_, ComponentReputationSummaryRow>(
            r#"
            SELECT DISTINCT cr.ecosystem, cr.name, cr.scorecard_score,
                   cr.project_repo, cr.checked_at
            FROM component_reputation cr
            JOIN sbom_components sc
              ON sc.ecosystem = cr.ecosystem
             AND sc.registry_name = cr.name
            WHERE cr.scorecard_score IS NOT NULL
              AND sc.tenant_id = $1
            ORDER BY cr.scorecard_score ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Records (or refreshes) one package's cached reputation result —
    /// `scorecard_score`/`project_repo` are `None` on a fetch failure
    /// (`fetch_error` set instead, matching `dtrack_push_failures`' pattern
    /// of recording *why* something is stale rather than silently retrying
    /// forever), and `None`/cleared on success when deps.dev genuinely has
    /// no scorecard for the package (not an error, just no data).
    pub async fn upsert_component_reputation(
        &self,
        ecosystem: &str,
        name: &str,
        scorecard_score: Option<f32>,
        project_repo: Option<&str>,
        fetch_error: Option<&str>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO component_reputation (ecosystem, name, scorecard_score, project_repo, checked_at, fetch_error)
            VALUES ($1, $2, $3, $4, now(), $5)
            ON CONFLICT (ecosystem, name)
            DO UPDATE SET scorecard_score = EXCLUDED.scorecard_score,
                           project_repo = EXCLUDED.project_repo,
                           checked_at = EXCLUDED.checked_at,
                           fetch_error = EXCLUDED.fetch_error
            "#,
        )
        .bind(ecosystem)
        .bind(name)
        .bind(scorecard_score)
        .bind(project_repo)
        .bind(fetch_error)
        .execute(&self.pool)
        .await
        .map_err(map_query_error)?;
        Ok(())
    }

    /// One manifest's components joined against their cached reputation, for
    /// `manifest()`'s response — components with no `ecosystem`/`registry_name`
    /// (no usable purl) or no `component_reputation` row yet (job hasn't
    /// reached them) are simply absent, not an error: the frontend reads
    /// "not in this list" as "not checked yet," same convention as
    /// `dtrack_synced_at: null` elsewhere.
    /// Every component of this manifest with a derivable registry identity
    /// (i.e. checkable at all), `LEFT JOIN`ed against its cached reputation —
    /// unlike an inner join, this means a component the background job
    /// hasn't reached yet still appears, with every `component_reputation`
    /// column `NULL` (surfaced as "pending" rather than silently omitted).
    /// Components with no purl / an untracked ecosystem are excluded
    /// entirely — there's nothing to ever check for them.
    pub async fn list_reputation_for_manifest(
        &self,
        manifest_hash: &str,
    ) -> Result<Vec<ComponentReputationRecord>, DbError> {
        sqlx::query_as::<_, ComponentReputationRecord>(
            r#"
            SELECT sc.name AS component_name, sc.version AS component_version,
                   sc.ecosystem, sc.registry_name, cr.scorecard_score,
                   cr.project_repo, cr.checked_at, cr.fetch_error
            FROM sbom_components sc
            LEFT JOIN component_reputation cr
                ON cr.ecosystem = sc.ecosystem AND cr.name = sc.registry_name
            WHERE sc.manifest_hash = $1
              AND sc.ecosystem IS NOT NULL
              AND sc.registry_name IS NOT NULL
            ORDER BY sc.name
            "#,
        )
        .bind(manifest_hash)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    // ---- Component freshness (EOL/staleness) ----

    /// Distinct (ecosystem, registry_name) pairs across the whole
    /// deployment's `sbom_components` that need a freshness (re)check —
    /// identical shape and staleness/failure-retry rules to
    /// `list_components_needing_reputation`, just against
    /// `component_freshness` instead of `component_reputation`.
    /// Deployment-global for the same reason: a package's latest version
    /// doesn't depend on which tenant uploaded it.
    pub async fn list_components_needing_freshness(
        &self,
        stale_before: chrono::DateTime<chrono::Utc>,
        limit: i64,
    ) -> Result<Vec<ComponentIdentity>, DbError> {
        sqlx::query_as::<_, ComponentIdentity>(
            r#"
            SELECT DISTINCT ON (sc.ecosystem, sc.registry_name)
                   sc.ecosystem, sc.registry_name, sc.version AS sample_version
            FROM sbom_components sc
            LEFT JOIN component_freshness cf
                ON cf.ecosystem = sc.ecosystem AND cf.name = sc.registry_name
            WHERE sc.ecosystem IS NOT NULL
              AND sc.registry_name IS NOT NULL
              AND sc.version IS NOT NULL
              AND (cf.ecosystem IS NULL OR cf.checked_at < $1 OR cf.fetch_error IS NOT NULL)
            ORDER BY sc.ecosystem, sc.registry_name, sc.version DESC
            LIMIT $2
            "#,
        )
        .bind(stale_before)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Deployment-wide counts for the Settings UI's freshness status
    /// display — the `pending` subquery mirrors
    /// `list_components_needing_freshness`'s definition exactly (minus the
    /// `LIMIT`), same "never disagree about what still needs checking"
    /// reasoning as `reputation_status`.
    pub async fn freshness_status(
        &self,
        stale_before: chrono::DateTime<chrono::Utc>,
    ) -> Result<ComponentFreshnessStatus, DbError> {
        sqlx::query_as::<_, ComponentFreshnessStatus>(
            r#"
            SELECT
                (SELECT COUNT(*) FROM (
                    SELECT DISTINCT sc.ecosystem, sc.registry_name
                    FROM sbom_components sc
                    LEFT JOIN component_freshness cf
                        ON cf.ecosystem = sc.ecosystem AND cf.name = sc.registry_name
                    WHERE sc.ecosystem IS NOT NULL
                      AND sc.registry_name IS NOT NULL
                      AND (cf.ecosystem IS NULL OR cf.checked_at < $1 OR cf.fetch_error IS NOT NULL)
                ) pending_rows) AS pending,
                (SELECT COUNT(*) FROM component_freshness WHERE fetch_error IS NULL) AS checked,
                (SELECT COUNT(*) FROM component_freshness WHERE fetch_error IS NOT NULL) AS failed
            "#,
        )
        .bind(stale_before)
        .fetch_one(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Records (or refreshes) one package's cached latest-version result —
    /// same `None`-on-failure/`fetch_error`-set convention as
    /// `upsert_component_reputation`.
    pub async fn upsert_component_freshness(
        &self,
        ecosystem: &str,
        name: &str,
        latest_version: Option<&str>,
        fetch_error: Option<&str>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO component_freshness (ecosystem, name, latest_version, checked_at, fetch_error)
            VALUES ($1, $2, $3, now(), $4)
            ON CONFLICT (ecosystem, name)
            DO UPDATE SET latest_version = EXCLUDED.latest_version,
                           checked_at = EXCLUDED.checked_at,
                           fetch_error = EXCLUDED.fetch_error
            "#,
        )
        .bind(ecosystem)
        .bind(name)
        .bind(latest_version)
        .bind(fetch_error)
        .execute(&self.pool)
        .await
        .map_err(map_query_error)?;
        Ok(())
    }

    /// One manifest's components joined against their cached freshness
    /// result, for `manifest()`'s response — same `LEFT JOIN`/"absent means
    /// not checkable at all, present-with-NULLs means pending" shape as
    /// `list_reputation_for_manifest`.
    pub async fn list_freshness_for_manifest(
        &self,
        manifest_hash: &str,
    ) -> Result<Vec<ComponentFreshnessRecord>, DbError> {
        sqlx::query_as::<_, ComponentFreshnessRecord>(
            r#"
            SELECT sc.name AS component_name, sc.version AS component_version,
                   sc.ecosystem, sc.registry_name, cf.latest_version,
                   cf.checked_at, cf.fetch_error
            FROM sbom_components sc
            LEFT JOIN component_freshness cf
                ON cf.ecosystem = sc.ecosystem AND cf.name = sc.registry_name
            WHERE sc.manifest_hash = $1
              AND sc.ecosystem IS NOT NULL
              AND sc.registry_name IS NOT NULL
            ORDER BY sc.name
            "#,
        )
        .bind(manifest_hash)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// A single package's cached latest-version, if any — a plain point
    /// lookup against the same `component_freshness` cache
    /// `list_freshness_for_manifest` joins against, used by `/verify`'s
    /// dry-run gate (no live deps.dev call in the request path, just
    /// reading whatever the background job already knows). `None` covers
    /// both "no row yet" and "row exists but deps.dev had no version info" —
    /// `/verify` doesn't need to tell those apart.
    pub async fn get_component_freshness(&self, ecosystem: &str, name: &str) -> Result<Option<String>, DbError> {
        let row: Option<Option<String>> =
            sqlx::query_scalar("SELECT latest_version FROM component_freshness WHERE ecosystem = $1 AND name = $2")
                .bind(ecosystem)
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_query_error)?;
        Ok(row.flatten())
    }

    /// A single package's cached OpenSSF Scorecard score, if any — same
    /// point-lookup shape as `get_component_freshness`, used by `/verify`'s
    /// dry-run gate (no live deps.dev call in the request path, just
    /// reading whatever the reputation background job already knows).
    /// `None` covers both "no row yet" and "row exists but deps.dev had no
    /// scorecard for it" — `/verify` doesn't need to tell those apart.
    pub async fn get_component_reputation(&self, ecosystem: &str, name: &str) -> Result<Option<f32>, DbError> {
        let row: Option<Option<f32>> =
            sqlx::query_scalar("SELECT scorecard_score FROM component_reputation WHERE ecosystem = $1 AND name = $2")
                .bind(ecosystem)
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_query_error)?;
        Ok(row.flatten())
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
        // Same "latest non-revoked upload per namespace, respecting the
        // admin-curated `namespace_current_hidden` exclusion" definition as
        // `list_findings_for_tenant`'s `current_only` — reuses the identical
        // DISTINCT ON subquery rather than duplicating a second definition
        // of "currently active." A namespace marked inactive in Settings →
        // Manage namespace visibility is excluded here too, matching what
        // "active"/"inactive" means everywhere else in the UI.
        current_only: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SbomComponentSearchRow>, DbError> {
        sqlx::query_as::<_, SbomComponentSearchRow>(
            r#"
            SELECT sc.name, sc.version, sc.purl, sc.cpe, sc.is_primary,
                   m.manifest_hash, m.namespace, m.version AS release_version, m.revoked, m.document_type,
                   sc.license_expr
            FROM sbom_components sc
            JOIN manifests m ON m.manifest_hash = sc.manifest_hash
            WHERE sc.tenant_id = $1
              AND ($2 = '/' OR m.namespace = $2 OR starts_with(m.namespace, $2 || '/'))
              AND ($3::text IS NULL OR m.namespace = $3 OR starts_with(m.namespace, $3 || '/'))
              AND ($4::text IS NULL OR lower(sc.name) LIKE '%' || lower($4) || '%')
              AND ($5::text IS NULL OR sc.version = $5)
              AND ($6::text IS NULL OR sc.purl = $6)
              AND (
                $7::bool IS NOT TRUE
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
            ORDER BY m.namespace, m.created_at DESC
            LIMIT $8 OFFSET $9
            "#,
        )
        .bind(tenant_id)
        .bind(namespace_scope)
        .bind(namespace_filter)
        .bind(name_contains)
        .bind(component_version)
        .bind(purl)
        .bind(current_only)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Every manifest containing a component, identified by exact `purl`
    /// or by `name` (optionally narrowed further by `component_version`) —
    /// the "which namespaces/manifests contain component X" side of
    /// blast-radius. `current_only` reuses the same "latest non-revoked
    /// upload per namespace, respecting namespace visibility" definition as
    /// `search_sbom_components`. Revoked manifests are still returned
    /// (flagged via `revoked`) even with `current_only` off — a revoked
    /// manifest having shipped a vulnerable component is exactly the kind
    /// of history incident response needs to see, not hide.
    pub async fn list_manifests_containing_component(
        &self,
        tenant_id: Uuid,
        namespace_scope: &str,
        purl: Option<&str>,
        name: Option<&str>,
        component_version: Option<&str>,
        current_only: bool,
    ) -> Result<Vec<AffectedManifestRow>, DbError> {
        sqlx::query_as::<_, AffectedManifestRow>(
            r#"
            SELECT DISTINCT m.manifest_hash, m.namespace, m.version AS release_version, m.revoked, m.created_at
            FROM sbom_components sc
            JOIN manifests m ON m.manifest_hash = sc.manifest_hash
            WHERE sc.tenant_id = $1
              AND ($2 = '/' OR m.namespace = $2 OR starts_with(m.namespace, $2 || '/'))
              AND ($3::text IS NULL OR sc.purl = $3)
              AND ($4::text IS NULL OR sc.name = $4)
              AND ($5::text IS NULL OR sc.version = $5)
              AND (
                $6::bool IS NOT TRUE
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
            ORDER BY m.namespace, m.created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(namespace_scope)
        .bind(purl)
        .bind(name)
        .bind(component_version)
        .bind(current_only)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Every manifest affected by a vulnerability or malicious-package
    /// advisory id — matched against `dtrack_findings.vulnerability_id`
    /// (e.g. a CVE/GHSA id) as well as `malicious_component_findings.osv_id`
    /// (e.g. an OSV `MAL-` id), so both signal sources answer the same
    /// "which manifests does CVE/advisory Y affect" question through one
    /// endpoint. Same `current_only` and revoked-manifest semantics as
    /// `list_manifests_containing_component`.
    pub async fn list_manifests_affected_by_vulnerability(
        &self,
        tenant_id: Uuid,
        namespace_scope: &str,
        vuln_id: &str,
        current_only: bool,
    ) -> Result<Vec<AffectedManifestRow>, DbError> {
        sqlx::query_as::<_, AffectedManifestRow>(
            r#"
            SELECT DISTINCT m.manifest_hash, m.namespace, m.version AS release_version, m.revoked, m.created_at
            FROM manifests m
            WHERE m.tenant_id = $1
              AND ($2 = '/' OR m.namespace = $2 OR starts_with(m.namespace, $2 || '/'))
              AND (
                EXISTS (
                  SELECT 1 FROM dtrack_findings df
                  WHERE df.manifest_hash = m.manifest_hash AND df.vulnerability_id = $3
                )
                OR EXISTS (
                  SELECT 1 FROM malicious_component_findings mf
                  WHERE mf.manifest_hash = m.manifest_hash AND mf.osv_id = $3
                )
              )
              AND (
                $4::bool IS NOT TRUE
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
            ORDER BY m.namespace, m.created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(namespace_scope)
        .bind(vuln_id)
        .bind(current_only)
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
    /// `vex_comment`/`triaged_by`/`triaged_at` on a still-present finding
    /// survives a routine sync pass instead of being silently wiped.
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
                     vulnerability_id, severity, description, analysis_state, synced_at,
                     component_uuid, vulnerability_uuid)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), $9, $10)
                ON CONFLICT (manifest_hash, finding_key)
                DO UPDATE SET component_name = EXCLUDED.component_name,
                               component_version = EXCLUDED.component_version,
                               vulnerability_id = EXCLUDED.vulnerability_id,
                               severity = EXCLUDED.severity,
                               description = EXCLUDED.description,
                               analysis_state = EXCLUDED.analysis_state,
                               synced_at = EXCLUDED.synced_at,
                               component_uuid = EXCLUDED.component_uuid,
                               vulnerability_uuid = EXCLUDED.vulnerability_uuid
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
            .bind(&f.component_uuid)
            .bind(&f.vulnerability_uuid)
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
                   vex_status, vex_justification, vex_comment, triaged_by, triaged_at,
                   component_uuid, vulnerability_uuid, triage_source
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
                   df.vex_status, df.vex_justification, df.vex_comment, df.triaged_by, df.triaged_at,
                   df.triage_source, m.namespace, m.version AS release_version, m.revoked,
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
    /// `triage_source` is `"manual"` (the `triage_finding` handler) or
    /// `"vex_import"` (an imported VEX document) — see the column's
    /// migration comment.
    pub async fn set_finding_triage(
        &self,
        manifest_hash: &str,
        finding_key: &str,
        vex_status: &str,
        justification: Option<&str>,
        comment: Option<&str>,
        triaged_by: &str,
        triage_source: &str,
    ) -> Result<Option<DtrackFindingRecord>, DbError> {
        sqlx::query_as::<_, DtrackFindingRecord>(
            r#"
            UPDATE dtrack_findings
            SET vex_status = $1, vex_justification = $2, vex_comment = $3, triaged_by = $4, triaged_at = now(),
                triage_source = $7
            WHERE manifest_hash = $5 AND finding_key = $6
            RETURNING manifest_hash, finding_key, component_name, component_version,
                      vulnerability_id, severity, description, analysis_state, synced_at,
                      vex_status, vex_justification, vex_comment, triaged_by, triaged_at,
                      component_uuid, vulnerability_uuid, triage_source
            "#,
        )
        .bind(vex_status)
        .bind(justification)
        .bind(comment)
        .bind(triaged_by)
        .bind(manifest_hash)
        .bind(finding_key)
        .bind(triage_source)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_query_error)
    }

    // ---- Webhooks ----

    pub async fn insert_webhook_endpoint(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        url: &str,
        secret: &str,
        event_types: &[String],
        created_by: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO webhook_endpoints (id, tenant_id, url, secret, event_types, enabled, created_by, created_at)
            VALUES ($1, $2, $3, $4, $5, TRUE, $6, now())
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(url)
        .bind(secret)
        .bind(event_types)
        .bind(created_by)
        .execute(&self.pool)
        .await
        .map_err(map_query_error)?;
        Ok(())
    }

    pub async fn list_webhook_endpoints(&self, tenant_id: Uuid) -> Result<Vec<WebhookEndpointRecord>, DbError> {
        sqlx::query_as::<_, WebhookEndpointRecord>(
            "SELECT id, tenant_id, url, secret, event_types, enabled, created_by, created_at \
             FROM webhook_endpoints WHERE tenant_id = $1 ORDER BY created_at",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    pub async fn get_webhook_endpoint(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<WebhookEndpointRecord>, DbError> {
        sqlx::query_as::<_, WebhookEndpointRecord>(
            "SELECT id, tenant_id, url, secret, event_types, enabled, created_by, created_at \
             FROM webhook_endpoints WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Returns `true` iff a row belonging to this tenant was updated — the
    /// tenant scope in the `WHERE` clause is load-bearing, not just a
    /// filter: it's what stops one tenant from updating another's endpoint
    /// by guessing/reusing a UUID.
    pub async fn update_webhook_endpoint(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        url: &str,
        event_types: &[String],
        enabled: bool,
    ) -> Result<bool, DbError> {
        let result = sqlx::query(
            "UPDATE webhook_endpoints SET url = $3, event_types = $4, enabled = $5 \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(url)
        .bind(event_types)
        .bind(enabled)
        .execute(&self.pool)
        .await
        .map_err(map_query_error)?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_webhook_endpoint(&self, tenant_id: Uuid, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM webhook_endpoints WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_query_error)?;
        Ok(result.rows_affected() > 0)
    }

    /// This tenant's enabled endpoints subscribed to `event_type` — what
    /// `webhooks::emit_event` fans a new event out to. Not tenant-scoped by
    /// the *caller's* namespace scope (events already carry the whole
    /// tenant's data, same "webhooks are tenant-wide infrastructure, not
    /// per-namespace" scope compliance settings/dtrack sync already use).
    pub async fn list_enabled_webhook_endpoints_for_event(
        &self,
        tenant_id: Uuid,
        event_type: &str,
    ) -> Result<Vec<WebhookEndpointRecord>, DbError> {
        sqlx::query_as::<_, WebhookEndpointRecord>(
            "SELECT id, tenant_id, url, secret, event_types, enabled, created_by, created_at \
             FROM webhook_endpoints WHERE tenant_id = $1 AND enabled = TRUE AND $2 = ANY(event_types)",
        )
        .bind(tenant_id)
        .bind(event_type)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    pub async fn insert_webhook_delivery(
        &self,
        endpoint_id: Uuid,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<i64, DbError> {
        sqlx::query_scalar(
            "INSERT INTO webhook_deliveries (endpoint_id, event_type, payload, status, attempts, next_attempt_at) \
             VALUES ($1, $2, $3, 'pending', 0, now()) RETURNING id",
        )
        .bind(endpoint_id)
        .bind(event_type)
        .bind(payload)
        .fetch_one(&self.pool)
        .await
        .map_err(map_query_error)
    }

    /// Outbox rows due for (re)delivery — `pending`, past their
    /// `next_attempt_at`, joined with their endpoint's current
    /// `url`/`secret`. Joining on `enabled = TRUE` here (rather than a
    /// separate cleanup pass) means disabling an endpoint immediately stops
    /// its pending deliveries from being attempted, without deleting the
    /// outbox rows themselves — they resume if the endpoint is re-enabled.
    pub async fn list_due_webhook_deliveries(&self, limit: i64) -> Result<Vec<DueWebhookDelivery>, DbError> {
        sqlx::query_as::<_, DueWebhookDelivery>(
            r#"
            SELECT wd.id, wd.endpoint_id, we.url, we.secret, wd.event_type, wd.payload, wd.attempts
            FROM webhook_deliveries wd
            JOIN webhook_endpoints we ON we.id = wd.endpoint_id
            WHERE wd.status = 'pending' AND wd.next_attempt_at <= now() AND we.enabled = TRUE
            ORDER BY wd.next_attempt_at
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }

    pub async fn mark_webhook_delivery_delivered(&self, id: i64) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE webhook_deliveries SET status = 'delivered', delivered_at = now(), last_error = NULL WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_query_error)?;
        Ok(())
    }

    /// Records one failed delivery attempt. `next_status` is `"pending"`
    /// (the backoff schedule has another attempt left — `next_attempt_at`
    /// is when) or `"failed"` (attempts exhausted, given up for good) —
    /// decided by the caller (`webhooks::next_backoff`), not here.
    pub async fn record_webhook_delivery_failure(
        &self,
        id: i64,
        attempts: i32,
        next_attempt_at: chrono::DateTime<chrono::Utc>,
        next_status: &str,
        error: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE webhook_deliveries SET attempts = $2, next_attempt_at = $3, status = $4, last_error = $5 \
             WHERE id = $1",
        )
        .bind(id)
        .bind(attempts)
        .bind(next_attempt_at)
        .bind(next_status)
        .bind(error)
        .execute(&self.pool)
        .await
        .map_err(map_query_error)?;
        Ok(())
    }

    pub async fn list_webhook_deliveries_for_endpoint(
        &self,
        tenant_id: Uuid,
        endpoint_id: Uuid,
        limit: i64,
    ) -> Result<Vec<WebhookDeliveryRecord>, DbError> {
        sqlx::query_as::<_, WebhookDeliveryRecord>(
            r#"
            SELECT wd.id, wd.endpoint_id, wd.event_type, wd.payload, wd.status, wd.attempts,
                   wd.next_attempt_at, wd.last_error, wd.created_at, wd.delivered_at
            FROM webhook_deliveries wd
            JOIN webhook_endpoints we ON we.id = wd.endpoint_id
            WHERE we.tenant_id = $1 AND wd.endpoint_id = $2
            ORDER BY wd.created_at DESC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(endpoint_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_query_error)
    }
}