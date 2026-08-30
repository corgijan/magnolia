mod errors;
mod api_key;
mod rbac;

pub use errors::AuthError;
pub use api_key::{
    generate_server_key, ApiKey, ApiKeyHash, ApiKeyToken, ApiKeyVerifier, GeneratedKey, KEY_PREFIX,
};
pub use rbac::{namespace_in_scope, Action, Grant, RbacEngine, Role};

#[derive(Debug, Clone)]
pub struct ApiKeyGrant {
    pub api_key_hash: String,
    pub domain: String,
    pub namespace_scope: String,
    pub role: Role,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked: bool,
}
