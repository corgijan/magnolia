mod models;
mod errors;

pub use models::{
    ApiKeyRecord, AuditLogRecord, ManifestRecord, MerkleLeafRecord, MerkleNodeRecord,
    SignedTreeHeadRecord, TenantRecord,
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
            "SELECT id, domain, name, created_by, created_at, is_platform FROM tenants WHERE id = $1",
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
            "SELECT id, domain, name, created_by, created_at, is_platform FROM tenants WHERE domain = $1",
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
    }

    pub async fn list_tenants(&self) -> Result<Vec<TenantRecord>, DbError> {
        sqlx::query_as::<_, TenantRecord>(
            "SELECT id, domain, name, created_by, created_at, is_platform FROM tenants ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DbError::QueryError(e.to_string()))
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
                   COALESCE(m.revoked, FALSE) AS revoked, t.domain
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
                   COALESCE(m.revoked, FALSE) AS revoked, t.domain
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
        signature: &[u8],
        created_by: &str,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO manifests (manifest_hash, leaf_seq_id, tenant_id, version, sbom_hash, sbom_format,
                                   sbom_s3_key, namespace, previous_manifest_hash, signature, created_by, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
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
        .bind(signature)
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
                   sbom_s3_key, namespace, previous_manifest_hash, signature, created_by, created_at,
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
                   sbom_s3_key, namespace, previous_manifest_hash, signature, created_by, created_at,
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
}