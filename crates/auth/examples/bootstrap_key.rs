use magnolia_auth::{generate_server_key, ApiKey};

fn main() {
    let (key_id, secret, full_key) = generate_server_key();
    let hashed = ApiKey {
        key: secret,
        created_at: chrono::Utc::now(),
    }
    .hash()
    .unwrap();
    println!("key_id={}", key_id);
    println!("full_key={}", full_key);
    println!("argon2_hash={}", hashed.hash);
}
