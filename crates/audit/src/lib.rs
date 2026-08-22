mod errors;

pub use errors::AuditError;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditLogEntry {
    pub id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub result: AuditResult,
    pub reason: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuditResult {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "failure")]
    Failure,
}

impl AuditLogEntry {
    pub fn success(
        tenant_id: uuid::Uuid,
        principal: String,
        action: String,
        resource: String,
        reason: Option<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            tenant_id,
            principal,
            action,
            resource,
            result: AuditResult::Success,
            reason,
            created_at: chrono::Utc::now(),
        }
    }

    pub fn failure(
        tenant_id: uuid::Uuid,
        principal: String,
        action: String,
        resource: String,
        reason: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            tenant_id,
            principal,
            action,
            resource,
            result: AuditResult::Failure,
            reason: Some(reason),
            created_at: chrono::Utc::now(),
        }
    }
}

pub struct AuditLogger {
    entries: std::sync::RwLock<Vec<AuditLogEntry>>,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {
            entries: std::sync::RwLock::new(Vec::new()),
        }
    }

    pub fn log(&self, entry: AuditLogEntry) {
        self.entries.write().unwrap().push(entry);
    }

    pub fn entries(&self) -> Vec<AuditLogEntry> {
        self.entries.read().unwrap().clone()
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}
