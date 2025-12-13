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
//! ## Configuration
//!
//! Configuration is loaded from multiple sources with the following priority
//! (highest to lowest):
//!
//! 1. **CLI arguments** - `-p`, `--port`, `--bind-addr`, etc.
//! 2. **Environment variables** - `REME_NODE_PORT`, `REME_NODE_BIND_ADDR`, etc.
//! 3. **Config file** - `~/.config/reme/node.toml`
//! 4. **Built-in defaults**
//!
//! See `--help` for all CLI options.
//!
//! ## API Endpoints
//! - POST /api/v1/enqueue - Submit a message
//! - GET /api/v1/fetch/:routing_key - Fetch messages
//! - POST /api/v1/prekeys/:routing_key - Upload prekeys
//! - GET /api/v1/prekeys/:routing_key - Fetch prekeys
//! - GET /api/v1/health - Health check
//! - GET /api/v1/stats - Store statistics

mod api;
mod cleanup;
mod config;
mod replication;
mod store;

use api::AppState;
use cleanup::run_cleanup_task;
use config::{load_config, NodeConfig};
use replication::ReplicationClient;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

/// Parse log level from string
fn parse_log_level(level: &str) -> Level {
    match level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" | "warning" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    }
}

#[tokio::main]
async fn main() {
    // Load configuration from all sources
    let config = match load_config() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            eprintln!("Using default configuration...");
            NodeConfig::default()
        }
    };

    // Initialize tracing with configured log level
    let log_level = parse_log_level(&config.log_level);
    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Starting Branch Messenger Node v{}", env!("CARGO_PKG_VERSION"));
    info!("Bind address: {}", config.bind_addr);
    info!("Max messages per mailbox: {}", config.max_messages);
    info!("Default TTL: {} seconds", config.default_ttl);

    // Create store with configured TTLs
    let mut store = store::MailboxStore::new(config.max_messages, config.default_ttl);
    store.set_tombstone_ttl(config.cleanup.tombstone_delay_secs);
    store.set_orphan_ttl(config.cleanup.orphan_delay_secs);
    let store = Arc::new(store);

    // Create replication client
    let replication = Arc::new(ReplicationClient::new(config.node_id, config.peers));
    replication.log_config();

    // Log cleanup configuration
    config.cleanup.log_config();

    // Spawn cleanup task
    let cleanup_store = Arc::clone(&store);
    let cleanup_config = config.cleanup.clone();
    tokio::spawn(async move {
        run_cleanup_task(cleanup_store, cleanup_config).await;
    });

    // Create app state
    let state = Arc::new(AppState { store, replication });

    // Create router
    let app = api::router(state);

    // Start server
    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .expect("Failed to bind address");

    info!("Node listening on {}", config.bind_addr);

    axum::serve(listener, app).await.expect("Server failed");
}
