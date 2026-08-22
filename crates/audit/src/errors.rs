#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("Log write failed: {0}")]
    LogWriteFailed(String),
}
