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
}

#[derive(Debug, Clone, FromRow)]
pub struct TenantRecord {
    pub id: uuid::Uuid,
    pub domain: String,
    pub name: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub is_platform: bool,
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
    pub sbom_hash: String,
    pub sbom_format: String,
    pub sbom_s3_key: String,
    pub namespace: String,
    pub previous_manifest_hash: Option<String>,
    pub signature: Vec<u8>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
}
