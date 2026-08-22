use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub sbom_hash: String,
    pub sbom_format: SbomFormat,
    pub s3_key: String,
    pub previous_manifest_hash: Option<String>,
    pub signature: String,
    pub tenant_id: uuid::Uuid,
    pub namespace: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SbomFormat {
    #[serde(rename = "cyclonedx")]
    CycloneDx,
    #[serde(rename = "spdx")]
    Spdx,
}

impl Manifest {
    pub fn new(
        version: String,
        sbom_hash: String,
        sbom_format: SbomFormat,
        s3_key: String,
        tenant_id: uuid::Uuid,
        namespace: String,
        created_by: String,
    ) -> Self {
        Self {
            version,
            sbom_hash,
            sbom_format,
            s3_key,
            previous_manifest_hash: None,
            signature: String::new(),
            tenant_id,
            namespace,
            created_at: Utc::now(),
            created_by,
        }
    }

    pub fn with_previous(mut self, previous_hash: String) -> Self {
        self.previous_manifest_hash = Some(previous_hash);
        self
    }

    pub fn with_signature(mut self, signature: String) -> Self {
        self.signature = signature;
        self
    }
}
