#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid API key")]
    InvalidApiKey,
    #[error("Access denied: {0}")]
    AccessDenied(String),
    #[error("Expired credentials")]
    ExpiredCredentials,
    #[error("Hashing error: {0}")]
    HashingError(String),
}
