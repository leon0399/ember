//! Branch Messenger Mailbox Node
//!
//! A mailbox server that stores and forwards encrypted messages.
//!
//! ## Features
//! - Store and forward encrypted message envelopes
//! - Message TTL and automatic expiration
//! - SQLite-based storage (file or in-memory)
//! - Optional TLS/HTTPS with native rustls support
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
//! ## TLS Configuration
//!
//! To enable HTTPS, set the following in your config or CLI:
//!
//! ```toml
//! [tls]
//! enabled = true
//! cert_path = "/path/to/cert.pem"
//! key_path = "/path/to/key.pem"
//! ```
//!
//! Or via CLI: `--tls-enabled --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem`
//!
//! ## API Endpoints
//! - POST /api/v1/submit - Submit a message
//! - GET /api/v1/fetch/:routing_key - Fetch messages
//! - GET /api/v1/health - Health check
//! - GET /api/v1/stats - Store statistics

mod api;
mod cleanup;
mod config;
mod persistent_store;
mod rate_limit;
mod replication;

use api::AppState;
use cleanup::run_cleanup_task;
use config::{load_config, NodeConfig};
use persistent_store::{PersistentMailboxStore, PersistentStoreConfig};
use rate_limit::RateLimiters;
use replication::ReplicationClient;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

/// Resolve bind address, supporting both IP:port and hostname:port formats.
///
/// Tries parsing as SocketAddr first (IP:port), then falls back to DNS resolution
/// for hostnames like "localhost:23003".
async fn resolve_bind_addr(addr_str: &str) -> Result<SocketAddr, String> {
    // Try direct parse first (IP:port)
    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
        return Ok(addr);
    }

    // Try DNS resolution (hostname:port)
    debug!("Resolving hostname for bind address: {}", addr_str);
    match tokio::net::lookup_host(addr_str).await {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                debug!("Resolved {} to {}", addr_str, addr);
                Ok(addr)
            } else {
                Err(format!(
                    "No addresses found for '{}'. Expected format: IP:port or hostname:port (e.g., '127.0.0.1:23003' or 'localhost:23003')",
                    addr_str
                ))
            }
        }
        Err(e) => Err(format!(
            "Failed to resolve bind address '{}': {}. Expected format: IP:port or hostname:port (e.g., '127.0.0.1:23003' or 'localhost:23003')",
            addr_str, e
        )),
    }
}

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

    // Determine storage path (default: :memory:)
    let storage_path = config.storage_path.clone().unwrap_or_else(|| ":memory:".to_string());

    if storage_path == ":memory:" {
        info!("Using in-memory storage (data will not persist across restarts)");
    } else {
        // Create parent directory if needed for file-based storage
        if let Some(parent) = std::path::Path::new(&storage_path).parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    error!("Failed to create storage directory: {}", e);
                    std::process::exit(1);
                }
            }
        }
        info!("Using persistent storage: {}", storage_path);
    }

    // Create store
    let store_config = PersistentStoreConfig {
        max_messages_per_mailbox: config.max_messages,
        default_ttl_secs: config.default_ttl as u64,
    };

    let store = match PersistentMailboxStore::open(&storage_path, store_config) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("Failed to create storage: {}", e);
            std::process::exit(1);
        }
    };

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

    // Build auth credentials if both username and password are provided
    let auth = match (&config.auth_username, &config.auth_password) {
        (Some(username), Some(password)) => {
            info!("Basic Auth: enabled");
            Some((username.clone(), password.clone()))
        }
        (Some(_), None) | (None, Some(_)) => {
            warn!("Basic Auth: DISABLED (both username and password required)");
            None
        }
        (None, None) => {
            info!("Basic Auth: disabled (no credentials configured)");
            None
        }
    };

    // Build rate limiters if any are configured
    let rate_limiters = if config.rate_limit.any_enabled() {
        info!("Rate limiting: enabled");
        config.rate_limit.log_config();
        Some(RateLimiters::new(&config.rate_limit))
    } else {
        info!("Rate limiting: disabled (all limits set to 0)");
        None
    };

    // Create app state (submit_key_limiter is moved out of rate_limiters for AppState)
    let submit_key_limiter = rate_limiters.as_ref().and_then(|r| r.submit_key.clone());

    let state = Arc::new(AppState {
        store,
        replication,
        auth,
        submit_key_limiter,
    });

    // Create router with rate limiting
    let app = api::router(state, rate_limiters.as_ref());

    // Start server with connect info for IP extraction
    if config.tls.enabled {
        // TLS mode - requires a single SocketAddr
        let addr = match resolve_bind_addr(&config.bind_addr).await {
            Ok(addr) => addr,
            Err(e) => {
                error!("{}", e);
                std::process::exit(1);
            }
        };

        let Some(cert_path) = config.tls.cert_path.as_ref() else {
            error!("TLS enabled but tls.cert_path not set. Provide --tls-cert or set tls.cert_path in config.");
            std::process::exit(1);
        };
        let Some(key_path) = config.tls.key_path.as_ref() else {
            error!("TLS enabled but tls.key_path not set. Provide --tls-key or set tls.key_path in config.");
            std::process::exit(1);
        };

        info!("TLS: enabled");
        info!("  Certificate: {}", cert_path.display());
        info!("  Private key: {}", key_path.display());

        let rustls_config =
            match axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await {
                Ok(config) => config,
                Err(e) => {
                    error!("Failed to load TLS certificate/key: {}", e);
                    std::process::exit(1);
                }
            };

        info!("Node listening on https://{}", addr);

        if let Err(e) = axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
        {
            error!("Server failed: {}", e);
            std::process::exit(1);
        }
    } else {
        // Plain HTTP mode - bind directly to the address string to allow
        // TcpListener to try all resolved addresses (e.g., both IPv4 and IPv6)
        info!("TLS: disabled (use --tls-enabled to enable HTTPS)");

        let listener = match tokio::net::TcpListener::bind(&config.bind_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind to '{}': {}", config.bind_addr, e);
                std::process::exit(1);
            }
        };

        let local_addr = listener.local_addr().unwrap_or_else(|_| {
            // Fallback: parse the config address for logging
            config.bind_addr.parse().unwrap_or_else(|_| {
                SocketAddr::from(([127, 0, 0, 1], 23003))
            })
        });
        info!("Node listening on http://{}", local_addr);

        if let Err(e) = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await {
            error!("Server failed: {}", e);
            std::process::exit(1);
        }
    }
}
