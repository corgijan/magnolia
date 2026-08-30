//! Mint an API key, or hash a secret you already have, for bootstrapping the
//! very first key directly in the database.
//!
//! Usage:
//!   cargo run -p magnolia-auth --example keygen
//!       -> a fresh `mag_...` key plus the columns to insert
//!   cargo run -p magnolia-auth --example keygen -- <secret>
//!       -> just the key_hash column value for a secret you supply

use magnolia_auth::{ApiKey, GeneratedKey};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        let generated = GeneratedKey::new().expect("CSPRNG unavailable");
        println!("Generated key:     {}", generated.token);
        println!("key_id (column):   {}", generated.key_id);
        println!("key_hash (column): {}", generated.key_hash);
        return;
    }

    // Hash whatever was passed verbatim — authentication hashes the entire
    // presented token, so a secret supplied here must be the entire token.
    let hashed = ApiKey { key: args[1].clone(), created_at: chrono::Utc::now() }
        .hash()
        .expect("hashing failed");
    println!("{}", hashed.hash);
}
