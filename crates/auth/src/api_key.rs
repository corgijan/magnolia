use argon2::{Argon2, PasswordHasher, PasswordHash, PasswordVerifier};
use argon2::password_hash::{SaltString, rand_core::OsRng};
use crate::AuthError;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ApiKey {
    pub key: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct ApiKeyHash {
    pub hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ApiKey {
    pub fn generate(prefix: &str) -> Self {
        let key = format!("{}-{}", prefix, Uuid::new_v4());
        Self {
            key,
            created_at: chrono::Utc::now(),
        }
    }

    pub fn hash(&self) -> Result<ApiKeyHash, AuthError> {
        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = argon2
            .hash_password(self.key.as_bytes(), &salt)
            .map_err(|e| AuthError::HashingError(e.to_string()))?
            .to_string();

        Ok(ApiKeyHash {
            hash: password_hash,
            created_at: chrono::Utc::now(),
        })
    }
}

pub struct ApiKeyVerifier;

impl ApiKeyVerifier {
    pub fn verify(key: &str, hash: &str) -> Result<bool, AuthError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AuthError::HashingError(e.to_string()))?;

        let argon2 = Argon2::default();
        match argon2.verify_password(key.as_bytes(), &parsed_hash) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Generates a server API key of the form `<key_id>:<secret>`.
///
/// `key_id` is public (used to look up the Argon2 hash); only `secret` is
/// hashed at rest. The full key is shown to the operator once.
pub fn generate_server_key() -> (Uuid, String, String) {
    let key_id = Uuid::new_v4();
    let secret = format!("{}{}", Uuid::new_v4(), Uuid::new_v4());
    let full_key = format!("{}:{}", key_id, secret);
    (key_id, secret, full_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let key = ApiKey::generate("test");
        let hashed = key.hash().unwrap();
        assert!(ApiKeyVerifier::verify(&key.key, &hashed.hash).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let key = ApiKey::generate("test");
        let hashed = key.hash().unwrap();
        assert!(!ApiKeyVerifier::verify("wrong-secret", &hashed.hash).unwrap());
    }

    #[test]
    fn verify_rejects_malformed_hash() {
        assert!(ApiKeyVerifier::verify("abc", "not-a-phc-string").is_err());
    }

    #[test]
    fn server_key_format_splits_correctly() {
        let (key_id, secret, full_key) = generate_server_key();
        assert_eq!(full_key, format!("{}:{}", key_id, secret));

        let (parsed_id, parsed_secret) = full_key
            .split_once(':')
            .expect("key splits on colon");
        assert_eq!(Uuid::parse_str(parsed_id).unwrap(), key_id);
        assert_eq!(parsed_secret, secret);
        assert_eq!(secret.len(), 72);
    }

    #[test]
    fn server_key_secret_hashes_and_verifies() {
        let (_, secret, full_key) = generate_server_key();
        let (_, parsed_secret) = full_key.split_once(':').unwrap();
        let hashed = ApiKey {
            key: parsed_secret.to_string(),
            created_at: chrono::Utc::now(),
        }
        .hash()
        .unwrap();
        assert!(ApiKeyVerifier::verify(&secret, &hashed.hash).unwrap());
    }
}
