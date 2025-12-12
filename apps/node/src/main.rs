//! Branch Messenger Mailbox Node
//!
//! A mailbox server that stores and forwards encrypted messages.
//!
//! ## Features
//! - Store and forward encrypted message envelopes
//! - Store and serve prekey bundles for X3DH key exchange
//! - Message TTL and automatic expiration
//! - P2P-ready architecture (future Iroh integration)
//!
//! ## API Endpoints
//! - POST /api/v1/enqueue - Submit a message
//! - GET /api/v1/fetch/:routing_key - Fetch messages
//! - POST /api/v1/prekeys/:routing_key - Upload prekeys
//! - GET /api/v1/prekeys/:routing_key - Fetch prekeys
//! - GET /api/v1/health - Health check
//! - GET /api/v1/stats - Store statistics

mod api;
mod store;

use api::AppState;
use std::sync::Arc;
use tracing::info;

/// Node configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to bind HTTP server
    pub bind_addr: String,

    /// Maximum messages per mailbox
    pub max_messages_per_mailbox: usize,

    /// Default message TTL in seconds
    pub default_ttl_secs: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:23003".to_string(), // REME -> (leetspeak) 23M3 -> Treat M as roman 1000 -> 23 * 1000 + 3 = 23003
            max_messages_per_mailbox: 1000,
            default_ttl_secs: 7 * 24 * 60 * 60, // 7 days
        }
    }
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let config = Config::default();

    info!("Starting Branch Messenger Node v{}", env!("CARGO_PKG_VERSION"));
    info!("Bind address: {}", config.bind_addr);
    info!("Max messages per mailbox: {}", config.max_messages_per_mailbox);
    info!("Default TTL: {} seconds", config.default_ttl_secs);

    // Create store
    let store = store::MailboxStore::new(
        config.max_messages_per_mailbox,
        config.default_ttl_secs,
    );

    // Create app state
    let state = Arc::new(AppState { store });

    // Create router
    let app = api::router(state);

    // Start server
    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .expect("Failed to bind address");

    info!("Node listening on {}", config.bind_addr);

    axum::serve(listener, app)
        .await
        .expect("Server failed");
}
