use sbomstash_api::{AppState, create_router};
use sbomstash_storage::InMemoryStore;
use sbomstash_signer::LocalFileSigner;
use std::sync::Arc;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Initialize storage (in-memory for MVP)
    let storage = Arc::new(InMemoryStore::new());

    // Initialize signer (local file for MVP)
    let signer_path = PathBuf::from("./.sbomstash_key");
    let signer = Arc::new(LocalFileSigner::new(signer_path));

    // Create app state
    let state = AppState { storage, signer };

    // Build router
    let router = create_router(state);

    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("Failed to bind to port 3000");

    tracing::info!("Server listening on http://127.0.0.1:3000");

    axum::serve(listener, router)
        .await
        .expect("Server error");
}
