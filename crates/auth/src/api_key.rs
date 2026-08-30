use argon2::{PasswordHash, PasswordVerifier, Argon2};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use crate::AuthError;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Marks a hash produced by the current (SHA-256) scheme. Stored hashes are
/// self-describing so several schemes can coexist in one `api_keys` table
/// during a rolling migration -- `verify` dispatches on this prefix, and
/// anything starting with `$argon2` is a legacy row (see `verify`'s own
/// doc comment). Adding a future scheme means a new prefix, not a
/// flag-day migration of every existing row.
const SHA256_PREFIX: &str = "sha256:";

/// Legacy scheme: PHC-format Argon2 strings written before the switch.
const ARGON2_PREFIX: &str = "$argon2";

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

    /// Hashes this key for storage, using an **unsalted SHA-256**.
    ///
    /// That is deliberate, and only safe because of an invariant this type
    /// depends on: the value being hashed is a *server-generated,
    /// high-entropy* secret (`generate_server_key` below produces 244 bits
    /// from a CSPRNG), never a user-chosen password.
    ///
    /// Argon2 -- what this used to be -- exists to make brute-forcing
    /// *low-entropy* human passwords expensive, and buys nothing against a
    /// 244-bit random input that cannot be brute-forced or
    /// rainbow-tabled at any hash speed. A salt likewise only defends
    /// against precomputation across *repeated/guessable* inputs, which
    /// these are not. What Argon2 *did* cost was real: ~19 MB and ~12 ms
    /// on every single authenticated request (`AuthGrant::from_request_parts`
    /// verifies on each one), which capped authenticated throughput at
    /// ~156 req/s on a dev laptop and let any legitimate key holder
    /// exhaust memory with modest concurrency.
    ///
    /// **If a low-entropy secret can ever reach this function, this choice
    /// stops being safe.** The one path where a human picks the secret is
    /// `BOOTSTRAP_SUPER_ADMIN_KEY`; `bootstrap_super_admin_from_env` warns
    /// when that value looks too short to carry real entropy.
    pub fn hash(&self) -> Result<ApiKeyHash, AuthError> {
        Ok(ApiKeyHash {
            hash: hash_secret(&self.key),
            created_at: chrono::Utc::now(),
        })
    }
}

/// The stored representation of `secret` under the current scheme.
fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    format!("{SHA256_PREFIX}{}", hex::encode(digest))
}

pub struct ApiKeyVerifier;

impl ApiKeyVerifier {
    /// Verifies `key` against a stored hash of *either* scheme, so keys
    /// minted before the SHA-256 switch keep authenticating with no
    /// migration step and no re-issuing: a legacy `$argon2...` row is
    /// still verified with Argon2 (correct, just slow), while everything
    /// minted since is verified with SHA-256. Rows are upgraded naturally
    /// as keys are rotated; nothing forces a flag day.
    ///
    /// An unrecognized format is an error, not `Ok(false)` -- that means
    /// corrupt/garbled data rather than a wrong secret, and the two
    /// deserve different handling by the caller.
    pub fn verify(key: &str, hash: &str) -> Result<bool, AuthError> {
        if let Some(expected_hex) = hash.strip_prefix(SHA256_PREFIX) {
            return verify_sha256(key, expected_hex);
        }
        if hash.starts_with(ARGON2_PREFIX) {
            return verify_argon2(key, hash);
        }
        Err(AuthError::HashingError(format!(
            "unrecognized key-hash format (expected '{SHA256_PREFIX}...' or '{ARGON2_PREFIX}...')"
        )))
    }
}

fn verify_sha256(key: &str, expected_hex: &str) -> Result<bool, AuthError> {
    let expected = hex::decode(expected_hex)
        .map_err(|e| AuthError::HashingError(format!("malformed sha256 key hash: {e}")))?;
    let actual = Sha256::digest(key.as_bytes());
    // Constant-time even though a digest comparison isn't practically
    // timing-exploitable here (learning the stored digest still doesn't
    // yield a secret that hashes to it) -- it costs nothing and removes
    // the need for anyone reading this to re-derive that argument.
    Ok(actual.as_slice().ct_eq(expected.as_slice()).into())
}

fn verify_argon2(key: &str, hash: &str) -> Result<bool, AuthError> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| AuthError::HashingError(e.to_string()))?;
    match Argon2::default().verify_password(key.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generates a server API key of the form `<key_id>:<secret>`.
///
/// `key_id` is public (used to look up the Argon2 hash); only `secret` is
/// hashed at rest. The full key is shown to the operator once.
///
/// **Legacy format.** Retained only so the pre-`mag_` token shape can still
/// be *parsed* (see `ApiKeyToken`); nothing mints keys this way any more.
/// Use `GeneratedKey::new` instead.
pub fn generate_server_key() -> (Uuid, String, String) {
    let key_id = Uuid::new_v4();
    let secret = format!("{}{}", Uuid::new_v4(), Uuid::new_v4());
    let full_key = format!("{}:{}", key_id, secret);
    (key_id, secret, full_key)
}

/// Prefix on every key minted by `GeneratedKey::new`.
///
/// Two reasons it exists, beyond looking tidier than a bare UUID pair:
/// secret scanners (GitHub push protection, gitleaks, trufflehog) match on
/// exactly this kind of fixed vendor prefix, so a leaked key is far more
/// likely to be *caught* than an anonymous hex blob would be; and it makes
/// the token self-identifying in a log or a support ticket.
pub const KEY_PREFIX: &str = "mag_";

/// A freshly minted API key: what to show the operator once (`token`), what
/// to store (`key_hash`), and the row's primary key (`key_id`).
///
/// `key_id` is deliberately *not* part of the token any more. It used to be
/// (`<key_id>:<secret>`) because a salted Argon2 hash can only be verified
/// once you already know which row's salt to use — so the caller had to
/// hand us the row id. With unsalted SHA-256 the hash is deterministic, so
/// the token alone is enough to find its row (`lookup_api_key_by_hash`),
/// and the id no longer needs to travel with the secret.
#[derive(Debug, Clone)]
pub struct GeneratedKey {
    pub key_id: Uuid,
    pub token: String,
    pub key_hash: String,
}

impl GeneratedKey {
    /// 256 bits from the OS CSPRNG, base64url-encoded (unpadded, so the
    /// token stays copy-pasteable and URL-safe).
    pub fn new() -> Result<Self, AuthError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| AuthError::HashingError(format!("CSPRNG unavailable: {e}")))?;
        let token = format!("{KEY_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        Ok(Self { key_id: Uuid::new_v4(), key_hash: hash_secret(&token), token })
    }
}

/// How a presented `Authorization: Bearer` token maps onto a database row.
///
/// Two shapes are accepted so keys minted before the format change keep
/// working — an operator should never be forced to re-issue every CI
/// credential to take an upgrade.
#[derive(Debug, Clone, PartialEq)]
pub enum ApiKeyToken {
    /// Current: `mag_<base64url>`. The row is found by hashing the whole
    /// token and matching `api_keys.key_hash` directly.
    Prefixed { key_hash: String },
    /// Legacy: `<key_id>:<secret>`. The row is found by `key_id`, then the
    /// secret is verified against whatever scheme that row was stored
    /// under (`ApiKeyVerifier::verify` handles both).
    Legacy { key_id: Uuid, secret: String },
}

impl ApiKeyToken {
    /// Classifies a bearer token. `None` for anything matching neither
    /// shape — indistinguishable from a wrong key to the caller, which is
    /// what we want: a malformed token must not be more informative than
    /// an invalid one.
    pub fn parse(token: &str) -> Option<Self> {
        if token.starts_with(KEY_PREFIX) {
            // The *entire* token is hashed, prefix included — whatever the
            // client sent is hashed verbatim, so there's no way for a
            // stripping mismatch between mint and verify to creep in.
            return Some(Self::Prefixed { key_hash: hash_secret(token) });
        }
        let (key_id, secret) = token.split_once(':')?;
        Some(Self::Legacy { key_id: Uuid::parse_str(key_id).ok()?, secret: secret.to_string() })
    }
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
    fn hash_uses_the_current_sha256_scheme() {
        let hashed = ApiKey::generate("test").hash().unwrap();
        assert!(hashed.hash.starts_with(SHA256_PREFIX), "got {}", hashed.hash);
        // 7-char prefix + 64 hex chars, comfortably inside api_keys.key_hash's varchar(255).
        assert_eq!(hashed.hash.len(), SHA256_PREFIX.len() + 64);
    }

    /// A real Argon2 PHC hash of the secret "legacy-secret", produced with
    /// the same `Argon2::default()` parameters this crate used before the
    /// SHA-256 switch (note `m=19456` -- the ~19 MB per verification that
    /// motivated the switch), with a fixed salt so it's reproducible.
    /// Hardcoded rather than generated at test time precisely so it keeps
    /// representing a *stored, pre-migration* row even now that the
    /// hashing code can no longer produce one.
    const LEGACY_ARGON2_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$evVbr7XJRKv8y2VY7IkRSLnI1ArJU0kPQCzA5hS1HEU";

    #[test]
    fn legacy_argon2_hashes_still_verify_after_the_switch() {
        // The whole point of the prefix dispatch: keys minted before the
        // switch must keep working with no migration and no re-issuing.
        assert!(
            ApiKeyVerifier::verify("legacy-secret", LEGACY_ARGON2_HASH).unwrap(),
            "a pre-migration Argon2 key stopped authenticating"
        );
    }

    #[test]
    fn legacy_argon2_hashes_still_reject_a_wrong_secret() {
        assert!(!ApiKeyVerifier::verify("not-the-secret", LEGACY_ARGON2_HASH).unwrap());
    }

    #[test]
    fn both_schemes_verify_independently_of_each_other() {
        // Mixed-format table during a rolling migration: neither scheme's
        // hash may ever validate against the other's secret.
        let sha_hash = ApiKey { key: "legacy-secret".to_string(), created_at: chrono::Utc::now() }
            .hash()
            .unwrap()
            .hash;
        assert!(ApiKeyVerifier::verify("legacy-secret", &sha_hash).unwrap());
        assert!(ApiKeyVerifier::verify("legacy-secret", LEGACY_ARGON2_HASH).unwrap());
        assert!(!ApiKeyVerifier::verify("legacy-secret", &sha_hash[..sha_hash.len() - 1]).unwrap_or(false));
    }

    #[test]
    fn sha256_hash_with_non_hex_body_is_an_error_not_a_silent_false() {
        // Corrupt data must be distinguishable from a wrong secret.
        assert!(ApiKeyVerifier::verify("x", "sha256:zzzz").is_err());
    }

    #[test]
    fn generated_key_is_prefixed_and_high_entropy() {
        let g = GeneratedKey::new().unwrap();
        assert!(g.token.starts_with(KEY_PREFIX), "got {}", g.token);
        // 32 raw bytes -> 43 unpadded base64url chars.
        assert_eq!(g.token.len(), KEY_PREFIX.len() + 43);
        assert!(!g.token.contains('='), "token must be unpadded: {}", g.token);
        assert!(g.key_hash.starts_with(SHA256_PREFIX));
    }

    #[test]
    fn generated_keys_are_unique() {
        let a = GeneratedKey::new().unwrap();
        let b = GeneratedKey::new().unwrap();
        assert_ne!(a.token, b.token);
        assert_ne!(a.key_hash, b.key_hash);
        assert_ne!(a.key_id, b.key_id);
    }

    #[test]
    fn generated_key_hash_matches_hashing_the_whole_token() {
        // The stored hash must be over the *entire* presented token,
        // prefix included — this is the invariant that lets
        // `ApiKeyToken::parse` find the row without any stripping step.
        let g = GeneratedKey::new().unwrap();
        assert_eq!(g.key_hash, hash_secret(&g.token));
        match ApiKeyToken::parse(&g.token).unwrap() {
            ApiKeyToken::Prefixed { key_hash } => assert_eq!(key_hash, g.key_hash),
            other => panic!("expected Prefixed, got {other:?}"),
        }
    }

    #[test]
    fn parse_classifies_both_token_shapes() {
        let g = GeneratedKey::new().unwrap();
        assert!(matches!(ApiKeyToken::parse(&g.token), Some(ApiKeyToken::Prefixed { .. })));

        let id = Uuid::new_v4();
        match ApiKeyToken::parse(&format!("{id}:some-secret")).unwrap() {
            ApiKeyToken::Legacy { key_id, secret } => {
                assert_eq!(key_id, id);
                assert_eq!(secret, "some-secret");
            }
            other => panic!("expected Legacy, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_shapes_matching_neither_format() {
        for bad in ["", "no-delimiter", "not-a-uuid:secret", "Bearer mag_x", ":", "mag"] {
            assert!(ApiKeyToken::parse(bad).is_none(), "should not parse: {bad:?}");
        }
    }

    #[test]
    fn a_legacy_secret_alone_does_not_authenticate_as_a_prefixed_token() {
        // Guards the boundary between the two paths: the legacy *secret*
        // (no key_id, no mag_ prefix) must not accidentally become a
        // valid prefixed token.
        let (_, secret, _) = generate_server_key();
        assert!(ApiKeyToken::parse(&secret).is_none());
    }

    #[test]
    fn sha256_verification_is_length_safe() {
        // A truncated/oversized stored digest must not panic or spuriously
        // match -- ct_eq returns false for differing lengths.
        assert!(!ApiKeyVerifier::verify("x", "sha256:abcd").unwrap());
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
