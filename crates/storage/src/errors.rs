#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
}
