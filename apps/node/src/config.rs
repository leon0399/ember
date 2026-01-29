//! Multi-layered configuration system for the node
//!
//! Configuration is loaded from multiple sources with the following priority
//! (highest to lowest):
//!
//! 1. **CLI arguments** - Explicit user input (highest priority)
//! 2. **Environment variables** - Prefixed with `REME_NODE_`
//! 3. **Config file** - TOML file at `~/.config/reme/node.toml` or custom path
//! 4. **Built-in defaults** - Hardcoded fallback values (lowest priority)
//!
//! ## Environment Variables
//!
//! All environment variables are prefixed with `REME_NODE_`:
//! - `REME_NODE_BIND_ADDR` - Address to bind HTTP server (e.g., "0.0.0.0:23003")
//! - `REME_NODE_MAX_MESSAGES` - Maximum messages per mailbox
//! - `REME_NODE_DEFAULT_TTL` - Default message TTL in seconds
//! - `REME_NODE_LOG_LEVEL` - Log level (trace, debug, info, warn, error)
//! - `REME_NODE_STORAGE_PATH` - Path to `SQLite` database file (`:memory:` for in-memory)
//! - `REME_NODE_TLS_ENABLED` - Enable TLS/HTTPS (true/false)
//! - `REME_NODE_TLS_CERT` - Path to PEM certificate file
//! - `REME_NODE_TLS_KEY` - Path to PEM private key file
//! - `REME_NODE_MQTT_BROKER` - Comma-separated MQTT broker URLs
//! - `REME_NODE_MQTT_CLIENT_ID` - Comma-separated client IDs (paired with broker URLs)
//! - `REME_NODE_MQTT_TOPIC_PREFIX` - MQTT topic prefix (default: "reme/v1")
//! - `REME_NODE_IDENTITY_PATH` - Path to node identity key file
//! - `REME_NODE_PUBLIC_HOST` - Canonical public hostname for signature verification
//! - `REME_NODE_ADDITIONAL_HOSTS` - Comma-separated additional valid hostnames
//!
//! ## Config File
//!
//! Default location: `~/.config/reme/node.toml` (Linux/macOS) or
//! `%APPDATA%\reme\node.toml` (Windows)
//!
//! ```toml
//! # Peer nodes for message replication
//! [[peers.http]]
//! url = "https://peer1.example.com:23003"
//! cert_pin = "spki//sha256/AAAA..."  # Optional SPKI pin
//! username = "replication"           # Optional Basic Auth
//! password = "secret"
//! tier = "quorum"
//! priority = 100
//! label = "Primary Peer"
//!
//! [[peers.http]]
//! url = "https://peer2.example.com:23003"
//! node_pubkey = "base64..."          # Optional identity verification
//! tier = "quorum"
//! priority = 90
//! label = "Backup Peer"
//!
//! bind_addr = "0.0.0.0:23003"
//! max_messages = 1000
//! default_ttl = 604800
//! log_level = "info"
//! storage_path = "/var/lib/reme/mailbox.db"  # Optional: enables persistent storage
//!
//! # Node identity for signed headers (auto-generated if not exists)
//! identity_path = "/etc/reme/node-identity.key"
//!
//! # Public hostname for signature verification (required for secure mode)
//! public_host = "node1.example.com:3000"
//! additional_hosts = ["192.168.1.5:3000", "localhost:3000"]  # Optional: for multi-homed/dev
//!
//! [tls]
//! enabled = true
//! cert_path = "/etc/reme/cert.pem"
//! key_path = "/etc/reme/key.pem"
//!
//! # MQTT bridge configuration (enabled when brokers are configured)
//! # Note: MQTT uses system root certificates (no certificate pinning support)
//! [mqtt]
//! topic_prefix = "reme/v1"  # Optional, defaults to "reme/v1"
//!
//! [[mqtt.brokers]]
//! url = "mqtts://broker.example.com:8883"
//! client_id = "node-1"  # Optional, auto-generated if not set
//! ```
//!

use crate::cleanup::CleanupConfig;
use clap::Parser;
use config::{Config, Environment, File, FileFormat};
use derivative::Derivative;
use directories::ProjectDirs;
use reme_config::{ConfiguredTier, HttpPeerConfig, PeerCommon, PeersConfig};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;

/// Rate limiting configuration
///
/// Each limit can be independently disabled by setting its `_rps` value to 0.
/// Limits are applied per-IP (using X-Forwarded-For if present) and per-routing-key.
#[derive(Debug, Clone, Deserialize, Serialize, Derivative)]
#[derivative(Default)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Submit endpoint: per-IP requests per second (0 = disabled)
    pub submit_ip_rps: u32,
    /// Submit endpoint: per-IP burst capacity
    #[derivative(Default(value = "10"))]
    pub submit_ip_burst: u32,
    /// Submit endpoint: per-routing-key requests per second (0 = disabled)
    pub submit_key_rps: u32,
    /// Submit endpoint: per-routing-key burst capacity
    #[derivative(Default(value = "20"))]
    pub submit_key_burst: u32,

    /// Fetch endpoint: per-IP requests per second (0 = disabled)
    pub fetch_ip_rps: u32,
    /// Fetch endpoint: per-IP burst capacity
    #[derivative(Default(value = "50"))]
    pub fetch_ip_burst: u32,
    /// Fetch endpoint: per-routing-key requests per second (0 = disabled)
    pub fetch_key_rps: u32,
    /// Fetch endpoint: per-routing-key burst capacity
    #[derivative(Default(value = "30"))]
    pub fetch_key_burst: u32,
}

/// TLS configuration for HTTPS server
///
/// When enabled, the node will serve HTTPS instead of HTTP.
/// Requires both `cert_path` and `key_path` to be set.
#[derive(Debug, Clone, Deserialize, Serialize, Derivative)]
#[derivative(Default)]
#[serde(default)]
pub struct TlsConfig {
    /// Enable TLS (requires `cert_path` and `key_path`)
    pub enabled: bool,
    /// Path to PEM-encoded certificate file
    pub cert_path: Option<PathBuf>,
    /// Path to PEM-encoded private key file
    pub key_path: Option<PathBuf>,
}

/// MQTT broker configuration for the bridge
///
/// Note: MQTT uses system root certificates for TLS verification.
/// Certificate pinning is not currently supported for MQTT connections.
///
/// ## Authentication
///
/// Credentials can be specified in two ways with the following precedence:
/// 1. **Explicit config fields** (highest priority) - `username` and `password`
/// 2. **URL-embedded credentials** - `mqtt://user:pass@broker:1883`
///
/// If both are provided, explicit config fields take precedence.
///
/// ## Examples
///
/// ```toml
/// # Explicit credentials (recommended)
/// [[mqtt.brokers]]
/// url = "mqtts://broker.example.com:8883"
/// username = "node-1"
/// password = "secret123"
///
/// # URL-embedded credentials
/// [[mqtt.brokers]]
/// url = "mqtt://user:pass@broker.local:1883"
///
/// # Mixed: explicit username overrides URL username
/// [[mqtt.brokers]]
/// url = "mqtt://wrong:pass@broker:1883"
/// username = "correct"  # This takes precedence
/// password = "secret"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MqttBrokerConfig {
    /// MQTT broker URL (e.g., "<mqtts://broker.example.com:8883>")
    pub url: String,
    /// Optional client ID (auto-generated if not specified)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Optional username for MQTT authentication
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Optional password for MQTT authentication
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// MQTT bridge configuration for nodes
///
/// The MQTT bridge is enabled automatically when brokers are configured.
/// When enabled, the node will:
/// - Subscribe to `{topic_prefix}/messages/#` to receive messages from MQTT
/// - Publish received HTTP messages to MQTT brokers
/// - Use message ID deduplication to prevent loops
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MqttBridgeConfig {
    /// MQTT brokers to connect to (bridge enabled if non-empty)
    #[serde(default)]
    pub brokers: Vec<MqttBrokerConfig>,
    /// Topic prefix (default: "reme/v1")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic_prefix: Option<String>,
}

impl MqttBridgeConfig {
    /// Returns true if MQTT bridge should be enabled (has brokers configured)
    pub fn is_enabled(&self) -> bool {
        !self.brokers.is_empty()
    }

    /// Get the topic prefix, using default if not specified
    pub fn topic_prefix(&self) -> &str {
        self.topic_prefix.as_deref().unwrap_or("reme/v1")
    }
}

impl RateLimitConfig {
    /// Check if any rate limiting is enabled
    pub fn any_enabled(&self) -> bool {
        self.submit_ip_rps > 0
            || self.submit_key_rps > 0
            || self.fetch_ip_rps > 0
            || self.fetch_key_rps > 0
    }

    /// Log which limiters are enabled
    pub fn log_config(&self) {
        if self.submit_ip_rps > 0 {
            info!(
                "  Submit per-IP: {} rps, burst {}",
                self.submit_ip_rps, self.submit_ip_burst
            );
        }
        if self.submit_key_rps > 0 {
            info!(
                "  Submit per-key: {} rps, burst {}",
                self.submit_key_rps, self.submit_key_burst
            );
        }
        if self.fetch_ip_rps > 0 {
            info!(
                "  Fetch per-IP: {} rps, burst {}",
                self.fetch_ip_rps, self.fetch_ip_burst
            );
        }
        if self.fetch_key_rps > 0 {
            info!(
                "  Fetch per-key: {} rps, burst {}",
                self.fetch_key_rps, self.fetch_key_burst
            );
        }
    }
}

/// CLI arguments for the node
#[derive(Parser, Debug, Clone)]
#[command(name = "reme-node")]
#[command(author, version, about = "Branch Messenger Mailbox Node")]
pub struct CliArgs {
    /// Address to bind HTTP server (e.g., "0.0.0.0:23003")
    #[arg(short = 'b', long, env = "REME_NODE_BIND_ADDR")]
    pub bind_addr: Option<String>,

    /// Port to bind (shorthand for `bind_addr` with 0.0.0.0)
    #[arg(short = 'p', long, env = "REME_NODE_PORT")]
    pub port: Option<u16>,

    /// Maximum messages per mailbox
    #[arg(short = 'm', long, env = "REME_NODE_MAX_MESSAGES")]
    pub max_messages: Option<usize>,

    /// Default message TTL in seconds
    #[arg(short = 't', long, env = "REME_NODE_DEFAULT_TTL")]
    pub default_ttl: Option<u32>,

    /// Path to config file (default: ~/.config/reme/node.toml)
    #[arg(short = 'c', long, env = "REME_NODE_CONFIG")]
    pub config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'l', long, env = "REME_NODE_LOG_LEVEL")]
    pub log_level: Option<String>,

    /// Unique node ID for replication (defaults to random UUID)
    #[arg(long, env = "REME_NODE_ID")]
    pub node_id: Option<String>,

    /// Peer node URLs for replication (comma-separated)
    #[arg(short = 'P', long, env = "REME_NODE_PEERS", value_delimiter = ',')]
    pub peers: Option<Vec<String>>,

    /// Disable background cleanup task
    #[arg(long, env = "REME_NODE_CLEANUP_DISABLED")]
    pub cleanup_disabled: bool,

    /// Cleanup task interval in seconds (default: 300)
    #[arg(long, env = "REME_NODE_CLEANUP_INTERVAL")]
    pub cleanup_interval: Option<u64>,

    /// Tombstone cleanup delay in seconds (default: 3600)
    #[arg(long, env = "REME_NODE_CLEANUP_TOMBSTONE_DELAY")]
    pub cleanup_tombstone_delay: Option<u64>,

    /// Orphan tombstone cleanup delay in seconds (default: 86400)
    #[arg(long, env = "REME_NODE_CLEANUP_ORPHAN_DELAY")]
    pub cleanup_orphan_delay: Option<u64>,

    /// Path to `SQLite` database file (default: :memory:)
    /// Use ":memory:" for in-memory storage, or a file path for persistence
    #[arg(long, env = "REME_NODE_STORAGE_PATH")]
    pub storage_path: Option<String>,

    /// Username for HTTP Basic Auth (optional)
    /// If set along with `auth_password`, incoming requests must authenticate
    #[arg(long, env = "REME_NODE_AUTH_USERNAME")]
    pub auth_username: Option<String>,

    /// Password for HTTP Basic Auth (optional)
    /// If set along with `auth_username`, incoming requests must authenticate
    #[arg(long, env = "REME_NODE_AUTH_PASSWORD")]
    pub auth_password: Option<String>,

    // Rate limiting: Submit endpoint
    /// Submit endpoint: per-IP requests per second (0 = disabled)
    #[arg(long, env = "REME_NODE_RATE_LIMIT_SUBMIT_IP_RPS")]
    pub rate_limit_submit_ip_rps: Option<u32>,
    /// Submit endpoint: per-IP burst capacity
    #[arg(long, env = "REME_NODE_RATE_LIMIT_SUBMIT_IP_BURST")]
    pub rate_limit_submit_ip_burst: Option<u32>,
    /// Submit endpoint: per-routing-key requests per second (0 = disabled)
    #[arg(long, env = "REME_NODE_RATE_LIMIT_SUBMIT_KEY_RPS")]
    pub rate_limit_submit_key_rps: Option<u32>,
    /// Submit endpoint: per-routing-key burst capacity
    #[arg(long, env = "REME_NODE_RATE_LIMIT_SUBMIT_KEY_BURST")]
    pub rate_limit_submit_key_burst: Option<u32>,

    // Rate limiting: Fetch endpoint
    /// Fetch endpoint: per-IP requests per second (0 = disabled)
    #[arg(long, env = "REME_NODE_RATE_LIMIT_FETCH_IP_RPS")]
    pub rate_limit_fetch_ip_rps: Option<u32>,
    /// Fetch endpoint: per-IP burst capacity
    #[arg(long, env = "REME_NODE_RATE_LIMIT_FETCH_IP_BURST")]
    pub rate_limit_fetch_ip_burst: Option<u32>,
    /// Fetch endpoint: per-routing-key requests per second (0 = disabled)
    #[arg(long, env = "REME_NODE_RATE_LIMIT_FETCH_KEY_RPS")]
    pub rate_limit_fetch_key_rps: Option<u32>,
    /// Fetch endpoint: per-routing-key burst capacity
    #[arg(long, env = "REME_NODE_RATE_LIMIT_FETCH_KEY_BURST")]
    pub rate_limit_fetch_key_burst: Option<u32>,

    // TLS configuration
    /// Enable TLS (HTTPS) for the server
    #[arg(long, env = "REME_NODE_TLS_ENABLED")]
    pub tls_enabled: Option<bool>,

    /// Path to PEM-encoded TLS certificate file
    #[arg(long, env = "REME_NODE_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,

    /// Path to PEM-encoded TLS private key file
    #[arg(long, env = "REME_NODE_TLS_KEY")]
    pub tls_key: Option<PathBuf>,

    // MQTT bridge configuration
    /// MQTT broker URLs (comma-separated, enables MQTT bridge)
    /// Example: mqtts://broker1:8883,mqtts://broker2:8883
    #[arg(long, env = "REME_NODE_MQTT_BROKER", value_delimiter = ',')]
    pub mqtt_broker: Option<Vec<String>>,

    /// MQTT client IDs (comma-separated, matched with `mqtt_broker`)
    /// If not specified, random client IDs will be generated
    #[arg(long, env = "REME_NODE_MQTT_CLIENT_ID", value_delimiter = ',')]
    pub mqtt_client_id: Option<Vec<String>>,

    /// MQTT topic prefix (default: reme/v1)
    #[arg(long, env = "REME_NODE_MQTT_TOPIC_PREFIX")]
    pub mqtt_topic_prefix: Option<String>,

    // Node identity configuration
    /// Path to node identity key file (32 bytes X25519 secret key)
    /// Auto-generated if not exists. Default: ~/.config/reme/node-identity.key
    #[arg(long, env = "REME_NODE_IDENTITY_PATH")]
    pub identity_path: Option<PathBuf>,

    /// Canonical public hostname for signature verification
    /// Required for secure signature verification. Example: "node1.example.com:3000"
    #[arg(long, env = "REME_NODE_PUBLIC_HOST")]
    pub public_host: Option<String>,

    /// Additional valid hostnames (comma-separated)
    /// For multi-homed servers, dev, or migration scenarios
    #[arg(long, env = "REME_NODE_ADDITIONAL_HOSTS", value_delimiter = ',')]
    pub additional_hosts: Option<Vec<String>>,
}

/// Final resolved configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeConfig {
    /// Address to bind HTTP server
    pub bind_addr: String,

    /// Maximum messages per mailbox
    pub max_messages: usize,

    /// Default message TTL in seconds
    pub default_ttl: u32,

    /// Log level
    pub log_level: String,

    /// Unique node ID for replication
    pub node_id: String,

    /// Peer node URLs for replication (structured configuration)
    #[serde(default)]
    pub peers: PeersConfig,

    /// Cleanup task configuration
    #[serde(default)]
    pub cleanup: CleanupConfig,

    /// Path to `SQLite` database file (default: :memory:)
    /// Use ":memory:" for in-memory storage, or a file path for persistence
    #[serde(default)]
    pub storage_path: Option<String>,

    /// Username for HTTP Basic Auth (optional)
    #[serde(default)]
    pub auth_username: Option<String>,

    /// Password for HTTP Basic Auth (optional)
    #[serde(default)]
    pub auth_password: Option<String>,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// TLS configuration
    #[serde(default)]
    pub tls: TlsConfig,

    /// MQTT bridge configuration
    #[serde(default)]
    pub mqtt: MqttBridgeConfig,

    /// Path to node identity key file
    #[serde(default)]
    pub identity_path: Option<PathBuf>,

    /// Canonical public hostname for signature verification
    /// Example: "node1.example.com:3000"
    #[serde(default)]
    pub public_host: Option<String>,

    /// Additional valid hostnames (for multi-homed servers, dev, migration)
    #[serde(default)]
    pub additional_hosts: Vec<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            // REME -> (leetspeak) 23M3 -> Treat M as roman 1000 -> 23 * 1000 + 3 = 23003
            bind_addr: "0.0.0.0:23003".to_string(),
            max_messages: 1000,
            default_ttl: 7 * 24 * 60 * 60, // 7 days
            log_level: "info".to_string(),
            node_id: uuid::Uuid::new_v4().to_string(),
            peers: PeersConfig::default(),
            cleanup: CleanupConfig::default(),
            storage_path: None, // None means :memory:
            auth_username: None,
            auth_password: None,
            rate_limit: RateLimitConfig::default(),
            tls: TlsConfig::default(),
            mqtt: MqttBridgeConfig::default(),
            identity_path: None, // None means use default location
            public_host: None,   // None means accept any (insecure mode)
            additional_hosts: Vec::new(),
        }
    }
}

/// Get the default config file path based on platform conventions
fn default_config_path() -> Option<PathBuf> {
    ProjectDirs::from("com", "branch", "reme").map(|dirs| dirs.config_dir().join("node.toml"))
}

/// Get the default identity file path based on platform conventions
pub fn default_identity_path() -> Option<PathBuf> {
    ProjectDirs::from("com", "branch", "reme")
        .map(|dirs| dirs.config_dir().join("node-identity.key"))
}

/// Safely convert i64 to u32, clamping negative values to 0.
/// Prevents negative config values from wrapping to huge u32 values.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // Intentional clamped conversion
fn i64_to_u32_clamped(v: i64) -> u32 {
    v.max(0) as u32
}

/// Safely convert i64 to u64, clamping negative values to 0.
#[allow(clippy::cast_sign_loss)] // max(0) ensures non-negative
fn i64_to_u64_clamped(v: i64) -> u64 {
    v.max(0) as u64
}

/// Safely convert i64 to usize, clamping negative values to 0.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // Intentional clamped conversion
fn i64_to_usize_clamped(v: i64) -> usize {
    v.max(0) as usize
}

/// Load configuration from all sources with proper layering
///
/// Priority (highest to lowest):
/// 1. CLI arguments
/// 2. Environment variables (`REME_NODE`_*)
/// 3. Config file
/// 4. Built-in defaults
#[allow(clippy::cast_possible_wrap, clippy::too_many_lines)] // Config loading requires many steps
pub fn load_config() -> Result<NodeConfig, config::ConfigError> {
    let cli = CliArgs::parse();

    // Start with defaults
    let defaults = NodeConfig::default();

    let mut builder = Config::builder()
        // Layer 1: Built-in defaults (lowest priority)
        .set_default("bind_addr", defaults.bind_addr.clone())?
        .set_default("max_messages", defaults.max_messages as i64)?
        .set_default("default_ttl", i64::from(defaults.default_ttl))?
        .set_default("log_level", defaults.log_level.clone())?
        .set_default("node_id", defaults.node_id.clone())?
        // Note: peers default is applied after config extraction (see below)
        // Cleanup defaults
        .set_default("cleanup.enabled", defaults.cleanup.enabled)?
        .set_default("cleanup.interval_secs", defaults.cleanup.interval_secs as i64)?
        .set_default("cleanup.tombstone_delay_secs", defaults.cleanup.tombstone_delay_secs as i64)?
        .set_default("cleanup.orphan_delay_secs", defaults.cleanup.orphan_delay_secs as i64)?
        .set_default("cleanup.rate_limit_delay_secs", defaults.cleanup.rate_limit_delay_secs as i64)?;

    // Layer 2: Config file
    let config_path = cli.config.clone().or_else(default_config_path);
    if let Some(path) = config_path {
        if path.exists() {
            builder = builder.add_source(File::from(path).format(FileFormat::Toml).required(false));
        }
    }

    // Layer 3: Environment variables (REME_NODE_*)
    builder = builder.add_source(
        Environment::with_prefix("REME_NODE")
            .separator("_")
            .try_parsing(true),
    );

    // Layer 4: CLI arguments (highest priority)
    if let Some(ref bind_addr) = cli.bind_addr {
        builder = builder.set_override("bind_addr", bind_addr.clone())?;
    }
    // Port is a shorthand for bind_addr
    if let Some(port) = cli.port {
        builder = builder.set_override("bind_addr", format!("0.0.0.0:{port}"))?;
    }
    if let Some(max_messages) = cli.max_messages {
        builder = builder.set_override("max_messages", max_messages as i64)?;
    }
    if let Some(default_ttl) = cli.default_ttl {
        builder = builder.set_override("default_ttl", i64::from(default_ttl))?;
    }
    if let Some(ref log_level) = cli.log_level {
        builder = builder.set_override("log_level", log_level.clone())?;
    }
    if let Some(ref node_id) = cli.node_id {
        builder = builder.set_override("node_id", node_id.clone())?;
    }
    // Note: CLI peers are applied after extraction (complex type incompatible with config crate)
    // Cleanup CLI overrides
    if cli.cleanup_disabled {
        builder = builder.set_override("cleanup.enabled", false)?;
    }
    if let Some(interval) = cli.cleanup_interval {
        builder = builder.set_override("cleanup.interval_secs", interval as i64)?;
    }
    if let Some(delay) = cli.cleanup_tombstone_delay {
        builder = builder.set_override("cleanup.tombstone_delay_secs", delay as i64)?;
    }
    if let Some(delay) = cli.cleanup_orphan_delay {
        builder = builder.set_override("cleanup.orphan_delay_secs", delay as i64)?;
    }

    let config = builder.build()?;

    // Extract values (using clamped conversions to prevent negative values wrapping)
    let bind_addr: String = config.get("bind_addr").unwrap_or(defaults.bind_addr);
    let max_messages: usize = config
        .get::<i64>("max_messages")
        .map(i64_to_usize_clamped)
        .unwrap_or(defaults.max_messages);
    let default_ttl: u32 = config
        .get::<i64>("default_ttl")
        .map(i64_to_u32_clamped)
        .unwrap_or(defaults.default_ttl);
    let log_level: String = config.get("log_level").unwrap_or(defaults.log_level);
    let node_id: String = config.get("node_id").unwrap_or(defaults.node_id);

    // Extract peers configuration
    let mut peers: PeersConfig = config.get::<PeersConfig>("peers").unwrap_or(defaults.peers);

    // Apply CLI peer overrides
    if let Some(ref peer_urls) = cli.peers {
        // CLI peers override all file/env config
        let http_peers: Vec<HttpPeerConfig> = peer_urls
            .iter()
            .enumerate()
            .map(|(i, url)| HttpPeerConfig {
                common: PeerCommon {
                    label: Some(format!("CLI Peer {}", i + 1)),
                    tier: ConfiguredTier::Quorum,
                    priority: 100,
                },
                url: url.clone(),
                cert_pin: None,
                node_pubkey: None,
                username: None,
                password: None,
            })
            .collect();

        peers = PeersConfig {
            http: http_peers,
            mqtt: vec![],
        };
    }

    // Extract cleanup config (using clamped conversions for safety)
    let cleanup = CleanupConfig {
        enabled: config
            .get::<bool>("cleanup.enabled")
            .unwrap_or(defaults.cleanup.enabled),
        interval_secs: config
            .get::<i64>("cleanup.interval_secs")
            .map(i64_to_u64_clamped)
            .unwrap_or(defaults.cleanup.interval_secs),
        tombstone_delay_secs: config
            .get::<i64>("cleanup.tombstone_delay_secs")
            .map(i64_to_u64_clamped)
            .unwrap_or(defaults.cleanup.tombstone_delay_secs),
        orphan_delay_secs: config
            .get::<i64>("cleanup.orphan_delay_secs")
            .map(i64_to_u64_clamped)
            .unwrap_or(defaults.cleanup.orphan_delay_secs),
        rate_limit_delay_secs: config
            .get::<i64>("cleanup.rate_limit_delay_secs")
            .map(i64_to_u64_clamped)
            .unwrap_or(defaults.cleanup.rate_limit_delay_secs),
    };

    // Extract storage config
    let storage_path: Option<String> = config.get("storage_path").ok();

    // Override from CLI if provided
    let storage_path = cli.storage_path.or(storage_path);

    // Extract auth config
    let auth_username: Option<String> = config.get("auth_username").ok();
    let auth_password: Option<String> = config.get("auth_password").ok();

    // Override from CLI if provided
    let auth_username = cli.auth_username.or(auth_username);
    let auth_password = cli.auth_password.or(auth_password);

    // Extract rate limit config (clamp negative values to 0)
    let mut rate_limit = RateLimitConfig {
        submit_ip_rps: config
            .get::<i64>("rate_limit.submit_ip_rps")
            .map(i64_to_u32_clamped)
            .unwrap_or(defaults.rate_limit.submit_ip_rps),
        submit_ip_burst: config
            .get::<i64>("rate_limit.submit_ip_burst")
            .map(i64_to_u32_clamped)
            .unwrap_or(defaults.rate_limit.submit_ip_burst),
        submit_key_rps: config
            .get::<i64>("rate_limit.submit_key_rps")
            .map(i64_to_u32_clamped)
            .unwrap_or(defaults.rate_limit.submit_key_rps),
        submit_key_burst: config
            .get::<i64>("rate_limit.submit_key_burst")
            .map(i64_to_u32_clamped)
            .unwrap_or(defaults.rate_limit.submit_key_burst),
        fetch_ip_rps: config
            .get::<i64>("rate_limit.fetch_ip_rps")
            .map(i64_to_u32_clamped)
            .unwrap_or(defaults.rate_limit.fetch_ip_rps),
        fetch_ip_burst: config
            .get::<i64>("rate_limit.fetch_ip_burst")
            .map(i64_to_u32_clamped)
            .unwrap_or(defaults.rate_limit.fetch_ip_burst),
        fetch_key_rps: config
            .get::<i64>("rate_limit.fetch_key_rps")
            .map(i64_to_u32_clamped)
            .unwrap_or(defaults.rate_limit.fetch_key_rps),
        fetch_key_burst: config
            .get::<i64>("rate_limit.fetch_key_burst")
            .map(i64_to_u32_clamped)
            .unwrap_or(defaults.rate_limit.fetch_key_burst),
    };

    // Apply CLI overrides for rate limiting
    if let Some(v) = cli.rate_limit_submit_ip_rps {
        rate_limit.submit_ip_rps = v;
    }
    if let Some(v) = cli.rate_limit_submit_ip_burst {
        rate_limit.submit_ip_burst = v;
    }
    if let Some(v) = cli.rate_limit_submit_key_rps {
        rate_limit.submit_key_rps = v;
    }
    if let Some(v) = cli.rate_limit_submit_key_burst {
        rate_limit.submit_key_burst = v;
    }
    if let Some(v) = cli.rate_limit_fetch_ip_rps {
        rate_limit.fetch_ip_rps = v;
    }
    if let Some(v) = cli.rate_limit_fetch_ip_burst {
        rate_limit.fetch_ip_burst = v;
    }
    if let Some(v) = cli.rate_limit_fetch_key_rps {
        rate_limit.fetch_key_rps = v;
    }
    if let Some(v) = cli.rate_limit_fetch_key_burst {
        rate_limit.fetch_key_burst = v;
    }

    // Extract TLS config
    let mut tls = TlsConfig {
        enabled: config
            .get::<bool>("tls.enabled")
            .unwrap_or(defaults.tls.enabled),
        cert_path: config
            .get::<String>("tls.cert_path")
            .ok()
            .map(PathBuf::from),
        key_path: config.get::<String>("tls.key_path").ok().map(PathBuf::from),
    };

    // Apply CLI overrides for TLS
    if let Some(v) = cli.tls_enabled {
        tls.enabled = v;
    }
    if let Some(ref path) = cli.tls_cert {
        tls.cert_path = Some(path.clone());
    }
    if let Some(ref path) = cli.tls_key {
        tls.key_path = Some(path.clone());
    }

    // Extract MQTT bridge config from file/env
    let mqtt_brokers_from_config: Vec<MqttBrokerConfig> = config
        .get::<Vec<MqttBrokerConfig>>("mqtt.brokers")
        .unwrap_or_default();
    let mqtt_topic_prefix_from_config: Option<String> = config.get("mqtt.topic_prefix").ok();

    // Build MQTT config, applying CLI overrides
    let mqtt = if let Some(ref broker_urls) = cli.mqtt_broker {
        // CLI brokers override file config entirely
        let client_ids = cli.mqtt_client_id.clone().unwrap_or_default();
        let brokers: Vec<MqttBrokerConfig> = broker_urls
            .iter()
            .enumerate()
            .map(|(i, url)| MqttBrokerConfig {
                url: url.clone(),
                client_id: client_ids.get(i).cloned(),
                username: None, // Auth via env vars not supported yet
                password: None,
            })
            .collect();
        MqttBridgeConfig {
            brokers,
            topic_prefix: cli
                .mqtt_topic_prefix
                .clone()
                .or(mqtt_topic_prefix_from_config),
        }
    } else {
        // Use file/env config
        MqttBridgeConfig {
            brokers: mqtt_brokers_from_config,
            topic_prefix: cli
                .mqtt_topic_prefix
                .clone()
                .or(mqtt_topic_prefix_from_config),
        }
    };

    // Extract identity config
    let identity_path_from_config: Option<PathBuf> = config
        .get::<String>("identity_path")
        .ok()
        .map(PathBuf::from);
    let public_host_from_config: Option<String> = config.get("public_host").ok();
    let additional_hosts_from_config: Vec<String> = config
        .get::<Vec<String>>("additional_hosts")
        .unwrap_or_default();

    // Apply CLI overrides for identity
    let identity_path = cli.identity_path.or(identity_path_from_config);
    let public_host = cli.public_host.or(public_host_from_config);
    let additional_hosts = cli.additional_hosts.unwrap_or(additional_hosts_from_config);

    Ok(NodeConfig {
        bind_addr,
        max_messages,
        default_ttl,
        log_level,
        node_id,
        peers,
        cleanup,
        storage_path,
        auth_username,
        auth_password,
        rate_limit,
        tls,
        mqtt,
        identity_path,
        public_host,
        additional_hosts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert_eq!(config.bind_addr, "0.0.0.0:23003");
        assert_eq!(config.max_messages, 1000);
        assert_eq!(config.default_ttl, 604_800); // 7 days
        assert_eq!(config.log_level, "info");
        assert!(!config.node_id.is_empty());
        assert!(config.peers.http.is_empty());
        assert!(config.peers.mqtt.is_empty());
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn test_peers_config_deserialization() {
        // Test new [[peers.http]] format deserialization
        let toml = r#"
[peers]
[[peers.http]]
url = "https://peer1.example.com:23003"
cert_pin = "spki//sha256/AAAA"
username = "user1"
password = "pass1"
tier = "quorum"
priority = 100
label = "Peer One"

[[peers.http]]
url = "https://peer2.example.com:23003"
node_pubkey = "BASE64KEY"
tier = "best_effort"
priority = 90
"#;

        // Parse into a wrapper type first to extract just the peers section
        #[derive(serde::Deserialize)]
        struct Wrapper {
            peers: PeersConfig,
        }

        let wrapper: Wrapper = toml::from_str(toml).expect("Failed to deserialize");
        let peers = wrapper.peers;

        assert_eq!(peers.http.len(), 2);

        // Check first peer
        assert_eq!(peers.http[0].url, "https://peer1.example.com:23003");
        assert_eq!(
            peers.http[0].cert_pin.as_ref().unwrap(),
            "spki//sha256/AAAA"
        );
        assert_eq!(peers.http[0].username.as_ref().unwrap(), "user1");
        assert_eq!(peers.http[0].password.as_ref().unwrap(), "pass1");
        assert_eq!(peers.http[0].common.tier, ConfiguredTier::Quorum);
        assert_eq!(peers.http[0].common.priority, 100);
        assert_eq!(peers.http[0].common.label.as_ref().unwrap(), "Peer One");

        // Check second peer
        assert_eq!(peers.http[1].url, "https://peer2.example.com:23003");
        assert_eq!(peers.http[1].node_pubkey.as_ref().unwrap(), "BASE64KEY");
        assert_eq!(peers.http[1].common.tier, ConfiguredTier::BestEffort);
        assert_eq!(peers.http[1].common.priority, 90);
        assert!(peers.http[1].cert_pin.is_none());
        assert!(peers.http[1].username.is_none());
    }

    #[test]
    fn test_cli_peer_override_format() {
        // Test that CLI peers get correct format (from lines 612-632)
        let peer_urls = [
            "https://cli-peer1.example.com:23003".to_string(),
            "https://cli-peer2.example.com:23003".to_string(),
        ];

        let http_peers: Vec<HttpPeerConfig> = peer_urls
            .iter()
            .enumerate()
            .map(|(i, url)| HttpPeerConfig {
                common: PeerCommon {
                    label: Some(format!("CLI Peer {}", i + 1)),
                    tier: ConfiguredTier::Quorum,
                    priority: 100,
                },
                url: url.clone(),
                cert_pin: None,
                node_pubkey: None,
                username: None,
                password: None,
            })
            .collect();

        let peers = PeersConfig {
            http: http_peers,
            mqtt: vec![],
        };

        assert_eq!(peers.http.len(), 2);
        assert_eq!(peers.http[0].url, "https://cli-peer1.example.com:23003");
        assert_eq!(peers.http[0].common.label.as_ref().unwrap(), "CLI Peer 1");
        assert_eq!(peers.http[1].url, "https://cli-peer2.example.com:23003");
        assert_eq!(peers.http[1].common.label.as_ref().unwrap(), "CLI Peer 2");
    }
}
