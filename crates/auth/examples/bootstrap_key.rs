//! Prints a fresh API key and the `api_keys` column values it corresponds to.
//!
//! Usage: cargo run -p magnolia-auth --example bootstrap_key

use magnolia_auth::GeneratedKey;

fn main() {
    let generated = GeneratedKey::new().expect("CSPRNG unavailable");
    println!("key_id={}", generated.key_id);
    println!("full_key={}", generated.token);
    println!("key_hash={}", generated.key_hash);
}
