#[derive(Debug)]
pub enum CoreError {
    InvalidManifest(String),
    InvalidHash(String),
    TreeError(String),
    SerializationError(String),
    SchemaValidation(String),
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::InvalidManifest(msg) => write!(f, "Invalid manifest: {}", msg),
            CoreError::InvalidHash(msg) => write!(f, "Invalid hash: {}", msg),
            CoreError::TreeError(msg) => write!(f, "Tree error: {}", msg),
            CoreError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            CoreError::SchemaValidation(msg) => write!(f, "SBOM schema validation failed: {}", msg),
        }
    }
}

impl std::error::Error for CoreError {}
