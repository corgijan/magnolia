//! Generate an Argon2 PHC hash for a key secret, for bootstrapping the very
//! first API key directly in the database.
//!
//! Usage: cargo run -p magnolia-auth --example keygen -- <secret>
//! Output: the PHC string to store in api_keys.key_hash

use magnolia_auth::{generate_server_key, ApiKey};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        let (key_id, secret, full_key) = generate_server_key();
        let hashed = ApiKey {
            key: secret,
            created_at: chrono::Utc::now(),
        }
        .hash()
        .expect("hashing failed");
        println!("Generated key:   {}", full_key);
        println!("key_id (column):  {}", key_id);
        println!("key_hash (column): {}", hashed.hash);
        return;
    }

    let secret = &args[1];
    let hashed = ApiKey {
        key: secret.clone(),
        created_at: chrono::Utc::now(),
    }
    .hash()
    .expect("hashing failed");
    println!("{}", hashed.hash);
}