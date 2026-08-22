#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
}
