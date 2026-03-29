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
//! - GET /`api/v1/fetch/:routing_key` - Fetch messages
//! - GET /api/v1/health - Health check
//! - GET /api/v1/stats - Store statistics

mod api;
mod cleanup;
mod config;
mod export;
mod import;
mod mqtt_bridge;
mod node_identity;
mod rate_limit;
mod replication;
mod signed_headers;

use api::AppState;
use clap::Parser;
use cleanup::run_cleanup_task;
use config::{default_identity_path, load_config_from, Cli, Commands};
use mqtt_bridge::MqttBridge;
use node_identity::NodeIdentity;
use rate_limit::RateLimiters;
use reme_config::ParsedHttpPeer;
use reme_discovery::DiscoveryBackend as _;
use reme_node_core::{PersistentMailboxStore, PersistentStoreConfig};
use replication::ReplicationClient;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

/// Resolve bind address, supporting both IP:port and hostname:port formats.
///
/// Tries parsing as `SocketAddr` first (IP:port), then falls back to DNS resolution
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
                    "No addresses found for '{addr_str}'. Expected format: IP:port or hostname:port (e.g., '127.0.0.1:23003' or 'localhost:23003')"
                ))
            }
        }
        Err(e) => Err(format!(
            "Failed to resolve bind address '{addr_str}': {e}. Expected format: IP:port or hostname:port (e.g., '127.0.0.1:23003' or 'localhost:23003')"
        )),
    }
}

/// Parse log level from string
fn parse_log_level(level: &str) -> Level {
    match level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" | "warning" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO, // Default to INFO for unrecognized levels
    }
}

/// Wait for SIGINT or SIGTERM, then cancel the shared token.
async fn shutdown_signal(cancel: CancellationToken) {
    let signal_name = wait_for_signal().await;
    info!("Received {signal_name}, shutting down...");
    cancel.cancel();
}

/// Block until an OS termination signal arrives and return its name.
#[cfg(unix)]
async fn wait_for_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.expect("failed to listen for SIGINT");
            "SIGINT"
        }
        _ = sigterm.recv() => "SIGTERM",
    }
}

/// Block until an OS termination signal arrives and return its name.
#[cfg(not(unix))]
async fn wait_for_signal() -> &'static str {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for Ctrl+C");
    "Ctrl+C"
}

/// Open the persistent mailbox store from the current configuration.
///
/// Used by both the server startup and export/import subcommands.
fn open_store(config: &config::NodeConfig) -> PersistentMailboxStore {
    let storage_path = config
        .storage_path
        .clone()
        .unwrap_or_else(|| ":memory:".to_string());

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

    let store_config = PersistentStoreConfig {
        max_messages_per_mailbox: config.max_messages,
        default_ttl_secs: u64::from(config.default_ttl),
    };

    match PersistentMailboxStore::open(&storage_path, store_config) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create storage: {}", e);
            std::process::exit(1);
        }
    }
}

/// Start mDNS advertisement if enabled in config and identity is available.
///
/// Returns `Some(backend)` if advertising started successfully, `None` if disabled
/// or failed. The backend must be kept alive to maintain the advertisement.
async fn start_mdns_advertisement(
    config: &config::NodeConfig,
    identity: Option<&NodeIdentity>,
    port: u16,
) -> Option<reme_discovery::mdns_sd::MdnsSdBackend> {
    if !config.lan_discovery.enabled {
        return None;
    }

    let Some(identity) = identity else {
        warn!(
            "LAN discovery enabled but no node identity loaded — mDNS advertisement skipped. \
             Configure identity_path to enable advertisement."
        );
        return None;
    };

    let backend = match reme_discovery::mdns_sd::MdnsSdBackend::new() {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to initialize mDNS backend: {e}. Advertisement disabled.");
            return None;
        }
    };

    let routing_key: [u8; 16] = identity.routing_key().into();
    let caps = vec!["relay".to_owned(), "store".to_owned()];
    let txt = reme_discovery::encode_txt(&routing_key, port, Some(&caps));
    let spec = reme_discovery::AdvertisementSpec {
        txt_records: txt,
        ..reme_discovery::AdvertisementSpec::new(port, routing_key)
    };

    match backend.start_advertising(spec).await {
        Ok(()) => {
            info!(
                "mDNS advertisement started: _reme._tcp.local. on port {} (rk: {})",
                port,
                hex::encode(routing_key)
            );
            Some(backend)
        }
        Err(e) => {
            warn!("Failed to start mDNS advertising: {e}");
            None
        }
    }
}

/// Gracefully shutdown mDNS advertisement.
///
/// Logs a warning if shutdown fails but does not propagate the error,
/// as shutdown errors should not prevent application termination.
async fn shutdown_mdns(backend: Arc<reme_discovery::mdns_sd::MdnsSdBackend>) {
    if let Err(e) = backend.shutdown().await {
        warn!("mDNS shutdown failed: {e}");
    }
}

#[tokio::main]
#[allow(clippy::too_many_lines)] // Entry point, refactoring would reduce clarity
async fn main() {
    let cli = Cli::parse();

    // Extract serve args for config loading
    let serve_args = cli.serve_args();

    // Load configuration from all sources
    // Configuration errors are fatal - we don't fall back to defaults as that
    // could result in unexpected security settings or behavior.
    let config = match load_config_from(&cli, serve_args) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("ERROR: Failed to load configuration: {e}");
            eprintln!();
            eprintln!("The node cannot start with invalid configuration.");
            eprintln!("Please fix the configuration error above, or delete the config file");
            eprintln!("to start with default settings.");
            std::process::exit(1);
        }
    };

    // Initialize tracing with configured log level
    let log_level = parse_log_level(&config.log_level);
    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    // Dispatch export/import subcommands (these don't need the full server setup)
    match &cli.command {
        Some(Commands::Export(args)) => {
            let store = open_store(&config);
            if let Err(e) = export::run_export(&config, &store, args) {
                eprintln!("Export failed: {e}");
                std::process::exit(1);
            }
            return;
        }
        Some(Commands::Import(args)) => {
            let store = open_store(&config);
            if let Err(e) = import::run_import(&config, &store, args) {
                eprintln!("Import failed: {e}");
                std::process::exit(1);
            }
            return;
        }
        // None or Serve => continue to server startup
        _ => {}
    }

    info!(
        "Starting Branch Messenger Node v{}",
        env!("CARGO_PKG_VERSION")
    );

    // Load or generate node identity
    let identity_path = config.identity_path.clone().or_else(default_identity_path);
    let identity = if let Some(path) = identity_path {
        info!("Identity path: {}", path.display());
        match NodeIdentity::load_or_generate(&path) {
            Ok(id) => {
                info!("Node ID: {}", id.node_id());
                Some(Arc::new(id))
            }
            Err(e) => {
                error!("Failed to load/generate node identity: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        warn!("No identity path configured and default location unavailable");
        warn!("Node will run without cryptographic identity (signatures disabled)");
        None
    };

    // Enforce public_host when identity is present (destination binding)
    if let Some(ref host) = config.public_host {
        info!("Public host: {}", host);
        if !config.additional_hosts.is_empty() {
            info!("Additional hosts: {:?}", config.additional_hosts);
        }
    } else if identity.is_some() {
        if config.allow_insecure_destination {
            warn!(
                "public_host not configured — signature destination verification DISABLED. \
                 Signed requests will be accepted regardless of destination."
            );
        } else {
            error!(
                "Node has identity but public_host is not configured. \
                 Signature destination verification cannot work without it. \
                 Set public_host in config/CLI/env, or set allow_insecure_destination = true to override."
            );
            std::process::exit(1);
        }
    }

    info!("Bind address: {}", config.bind_addr);
    info!("Max messages per mailbox: {}", config.max_messages);
    info!("Default TTL: {} seconds", config.default_ttl);

    // Open persistent store (shared helper)
    let store = Arc::new(open_store(&config));

    // Create replication client with signing identity
    // Parse and validate HTTP peer configurations
    let parsed_peers: Vec<ParsedHttpPeer> = config
        .peers
        .http
        .iter()
        .map(|peer| ParsedHttpPeer::try_from(peer.clone()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| {
            error!("Failed to parse peer configuration: {}", e);
            std::process::exit(1);
        });

    // Clone config before partial moves so it can be stored in AppState.
    let config_for_state = config.clone();
    let config_for_mdns = config.clone();

    let replication = Arc::new(ReplicationClient::with_identity(
        config.node_id,
        parsed_peers,
        identity.clone(),
    ));
    replication.log_config();

    // Log cleanup configuration
    config.cleanup.log_config();

    // Create shared shutdown token
    let cancel = CancellationToken::new();

    // Spawn shutdown signal handler
    tokio::spawn(shutdown_signal(cancel.clone()));

    // Spawn cleanup task (retain handle for ordered shutdown)
    let cleanup_store = Arc::clone(&store);
    let cleanup_config = config.cleanup.clone();
    let cleanup_cancel = cancel.clone();
    let mut cleanup_handle = tokio::spawn(run_cleanup_task(
        cleanup_store,
        cleanup_config,
        cleanup_cancel,
    ));

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

    // Create MQTT bridge if configured
    let mqtt_bridge = match MqttBridge::new(&config.mqtt).await {
        Ok(Some(bridge)) => {
            info!("MQTT bridge: enabled");
            Some(Arc::new(bridge))
        }
        Ok(None) => {
            info!("MQTT bridge: disabled (no brokers configured)");
            None
        }
        Err(e) => {
            error!("Failed to create MQTT bridge: {}", e);
            std::process::exit(1);
        }
    };

    // Spawn MQTT subscriber task if bridge is configured
    if let Some(ref bridge) = mqtt_bridge {
        let bridge = bridge.clone();
        let subscriber_store = Arc::clone(&store);
        let mqtt_cancel = cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = bridge.run_subscriber(subscriber_store, mqtt_cancel).await {
                error!("MQTT subscriber error: {}", e);
            }
        });
    }

    // Create app state (submit_key_limiter is moved out of rate_limiters for AppState)
    let submit_key_limiter = rate_limiters.as_ref().and_then(|r| r.submit_key.clone());

    let state = Arc::new(AppState {
        store,
        replication,
        auth,
        submit_key_limiter,
        mqtt_bridge,
        identity,
        public_host: config.public_host.clone(),
        additional_hosts: config.additional_hosts.clone(),
        config: config_for_state,
    });

    // Create router with rate limiting
    // (clone: state is used after server shutdown for final WAL checkpoint)
    let app = api::router(state.clone(), rate_limiters.as_ref());

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

        // Start mDNS advertisement if enabled and the port is non-zero.
        // If the port is 0 (ephemeral), we skip advertising here to avoid
        // publishing an incorrect or unusable port before the listener is
        // actually bound and its real port is known.
        let mdns_backend = if addr.port() == 0 {
            warn!(
                "mDNS advertisement disabled: bind address uses port 0 (ephemeral); \
                 cannot determine actual listening port in TLS mode."
            );
            None
        } else {
            start_mdns_advertisement(&config_for_mdns, state.identity.as_deref(), addr.port())
                .await
                .map(Arc::new)
        };

        let handle = axum_server::Handle::new();

        // Spawn task to trigger graceful shutdown on cancel
        let tls_handle = handle.clone();
        let tls_cancel = cancel.clone();
        let mdns_shutdown = mdns_backend.clone();
        tokio::spawn(async move {
            tls_cancel.cancelled().await;
            // Shutdown mDNS advertising before server shutdown
            if let Some(backend) = mdns_shutdown {
                shutdown_mdns(backend).await;
            }
            tls_handle.graceful_shutdown(Some(Duration::from_secs(10)));
        });

        if let Err(e) = axum_server::bind_rustls(addr, rustls_config)
            .handle(handle)
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
            config
                .bind_addr
                .parse()
                .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 23003)))
        });
        info!("Node listening on http://{}", local_addr);

        // Start mDNS advertisement if enabled
        let mdns_backend = start_mdns_advertisement(
            &config_for_mdns,
            state.identity.as_deref(),
            local_addr.port(),
        )
        .await
        .map(Arc::new);

        let timeout_cancel = cancel.clone();
        let mdns_shutdown_cancel = cancel.clone();

        // Spawn task to shutdown mDNS when cancelled
        if let Some(backend) = mdns_backend {
            tokio::spawn(async move {
                mdns_shutdown_cancel.cancelled().await;
                shutdown_mdns(backend).await;
            });
        }

        let server = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(cancel.cancelled_owned());

        // Enforce 10s shutdown timeout to match TLS mode behavior
        tokio::select! {
            result = server => {
                if let Err(e) = result {
                    error!("Server failed: {}", e);
                    std::process::exit(1);
                }
            }
            () = async {
                timeout_cancel.cancelled().await;
                tokio::time::sleep(Duration::from_secs(10)).await;
            } => {
                warn!("Graceful shutdown timeout exceeded, forcing exit");
            }
        }
    }

    // Post-shutdown finalization
    info!("HTTP server stopped, running final cleanup...");

    // Wait for cleanup task to finish (with timeout); abort if it hangs
    match tokio::time::timeout(Duration::from_secs(5), &mut cleanup_handle).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("Cleanup task panicked: {e}"),
        Err(_) => {
            warn!("Cleanup task did not finish within 5s, aborting");
            cleanup_handle.abort();
        }
    }

    if let Err(e) = state.store.checkpoint() {
        warn!("Final WAL checkpoint failed: {}", e);
    }
    info!("Node shut down cleanly");
}
