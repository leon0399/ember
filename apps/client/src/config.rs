//! Configuration management for the reme client.
//!
//! ## Configuration Sources (in priority order)
//!
//! 1. **CLI arguments** - Append to configured peers (highest priority for individual values)
//! 2. **Environment variables** - `REME_PEERS` (JSON)
//! 3. **Config file** - `~/.config/reme/config.toml` (default location)
//! 4. **Defaults** - Fallback values
//!
//! ## Config File Format
//!
//! ```toml
//! # Unified peers configuration
//! [[peers.http]]
//! url = "https://node1.example.com:23003"
//! cert_pin = "spki//sha256/AAAA..."  # Optional SPKI pin
//! tier = "quorum"                    # quorum | best_effort
//! priority = 100                     # Higher = preferred (0-255)
//! label = "Primary Mailbox"          # Optional display name
//!
//! [[peers.http]]
//! url = "https://node2.example.com:23003"
//! username = "alice"                 # Optional Basic Auth
//! password = "secret"
//! tier = "quorum"
//!
//! [[peers.mqtt]]
//! url = "mqtts://broker.example.com:8883"
//! client_id = "my-client"            # Optional
//! tier = "quorum"
//!
//! data_dir = "~/.local/share/reme"
//! log_level = "info"
//! ```
//!
//! converted to the new `[[peers.http]]` and `[[peers.mqtt]]` format.

use clap::Parser;
use config::{Config, Environment, File, FileFormat};
use derivative::Derivative;
use directories::ProjectDirs;
use reme_config::{ConfiguredTier, HttpPeerConfig, MqttPeerConfig, PeerCommon, PeersConfig};
use reme_transport::{QuorumStrategy, TieredDeliveryConfig};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{warn, Level};

/// CLI arguments for the client
#[derive(Parser, Debug, Clone, Serialize)]
#[command(name = "reme-client")]
#[command(author, version, about = "Branch Messenger Client")]
pub struct CliArgs {
    /// HTTP endpoint URLs (pair with --http-cert-pin by order)
    ///
    /// Example: --http-url https://node1:23003,https://node2:23003
    #[arg(long, value_delimiter = ',')]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_url: Option<Vec<String>>,

    /// Certificate pins for HTTP endpoints (pair with --http-url by order)
    ///
    /// Format: spki//sha256/<base64> or cert//sha256/<base64>
    /// Example: --http-cert-pin spki//sha256/aaa=,spki//sha256/bbb=
    #[arg(long, value_delimiter = ',')]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_cert_pin: Option<Vec<String>>,

    /// MQTT broker URLs (pair with --mqtt-client-id by order)
    ///
    /// Example: --mqtt-url mqtts://broker1:8883,mqtts://broker2:8883
    #[arg(long, value_delimiter = ',')]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mqtt_url: Option<Vec<String>>,

    /// Client IDs for MQTT brokers (pair with --mqtt-url by order)
    ///
    /// If not specified, random client IDs will be generated
    #[arg(long, value_delimiter = ',')]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mqtt_client_id: Option<Vec<String>>,

    /// Directory for storing identity, keys, and messages
    #[arg(short = 'd', long, env = "REME_DATA_DIR")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<PathBuf>,

    /// Path to config file (default: ~/.config/reme/config.toml)
    #[arg(short = 'c', long, env = "REME_CONFIG")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'l', long, env = "REME_LOG_LEVEL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,

    /// Outbox retry check interval in seconds
    #[arg(long, env = "REME_OUTBOX_TICK_INTERVAL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbox_tick_interval: Option<u64>,

    /// Message TTL in days (0 = never expire)
    #[arg(long, env = "REME_OUTBOX_TTL_DAYS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbox_ttl_days: Option<u64>,

    /// Attempt timeout in seconds (how long before retry)
    #[arg(long, env = "REME_OUTBOX_ATTEMPT_TIMEOUT")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbox_attempt_timeout: Option<u64>,

    /// Initial retry delay in seconds
    #[arg(long, env = "REME_OUTBOX_RETRY_INITIAL_DELAY")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbox_retry_initial_delay: Option<u64>,

    /// Maximum retry delay in seconds
    #[arg(long, env = "REME_OUTBOX_RETRY_MAX_DELAY")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbox_retry_max_delay: Option<u64>,

    /// Enable the embedded node for LAN P2P messaging
    ///
    /// When enabled, the client runs an in-process mailbox node
    #[arg(long, env = "REME_EMBEDDED_NODE")]
    pub embedded_node: bool,

    /// Disable the embedded node (overrides config file)
    #[arg(long, conflicts_with = "embedded_node")]
    pub no_embedded_node: bool,

    /// HTTP bind address for embedded node (enables HTTP server)
    ///
    /// Example: --embedded-http-bind 0.0.0.0:23004
    #[arg(long, env = "REME_EMBEDDED_HTTP_BIND")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded_http_bind: Option<String>,
}

// =============================================================================
// Outbox default value helpers (for serde and derivative Default)
// =============================================================================

fn default_outbox_tick_interval() -> u64 {
    5
}
fn default_outbox_ttl_days() -> u64 {
    7
}
/// 1 minute - attempt timeout
fn default_outbox_attempt_timeout() -> u64 {
    60
}
fn default_outbox_retry_initial_delay() -> u64 {
    5
}
/// 5 minutes - max retry delay
fn default_outbox_retry_max_delay() -> u64 {
    300
}

/// Outbox configuration
#[derive(Debug, Clone, Deserialize, Serialize, Derivative)]
#[derivative(Default)]
pub struct OutboxAppConfig {
    /// How often to check for pending retries (seconds)
    #[serde(default = "default_outbox_tick_interval")]
    #[derivative(Default(value = "default_outbox_tick_interval()"))]
    pub tick_interval_secs: u64,

    /// Default message TTL in days (0 = never expire)
    #[serde(default = "default_outbox_ttl_days")]
    #[derivative(Default(value = "default_outbox_ttl_days()"))]
    pub ttl_days: u64,

    /// How long a "sent" attempt stays in-flight before timing out (seconds)
    #[serde(default = "default_outbox_attempt_timeout")]
    #[derivative(Default(value = "default_outbox_attempt_timeout()"))]
    pub attempt_timeout_secs: u64,

    /// Initial retry delay (seconds)
    #[serde(default = "default_outbox_retry_initial_delay")]
    #[derivative(Default(value = "default_outbox_retry_initial_delay()"))]
    pub retry_initial_delay_secs: u64,

    /// Maximum retry delay (seconds)
    #[serde(default = "default_outbox_retry_max_delay")]
    #[derivative(Default(value = "default_outbox_retry_max_delay()"))]
    pub retry_max_delay_secs: u64,
}

/// Quorum strategy configuration.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum QuorumStrategyConfig {
    /// Any single transport success (legacy behavior).
    #[default]
    Any,
    /// Fixed count: at least N transports must succeed.
    Count(u32),
    /// Fraction of configured stable transports (e.g., 0.5 = majority).
    Fraction(f32),
    /// All configured stable transports must succeed.
    All,
}

impl QuorumStrategyConfig {
    /// Validate the quorum strategy configuration.
    ///
    /// Returns an error message if the configuration is invalid.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            QuorumStrategyConfig::Count(n) if *n == 0 => {
                Err("Quorum count must be > 0".to_string())
            }
            QuorumStrategyConfig::Fraction(f) if f.is_nan() || f.is_infinite() => Err(format!(
                "Invalid quorum fraction {f}: must be a finite number"
            )),
            QuorumStrategyConfig::Fraction(f) if *f <= 0.0 || *f > 1.0 => Err(format!(
                "Quorum fraction {f} out of range: must be in (0.0, 1.0]"
            )),
            QuorumStrategyConfig::Any
            | QuorumStrategyConfig::All
            | QuorumStrategyConfig::Count(_)
            | QuorumStrategyConfig::Fraction(_) => Ok(()),
        }
    }
}

// =============================================================================
// Delivery default value helpers (for serde and derivative Default)
// =============================================================================

fn default_urgent_initial_delay() -> u64 {
    5
}
/// 1 minute - max urgent delay
fn default_urgent_max_delay() -> u64 {
    60
}
fn default_urgent_backoff_multiplier() -> f32 {
    2.0
}
/// 4 hours - maintenance interval
fn default_maintenance_interval_hours() -> u64 {
    4
}
fn default_maintenance_enabled() -> bool {
    true
}
/// 500ms - direct tier timeout
fn default_direct_tier_timeout_ms() -> u64 {
    500
}
fn default_quorum_tier_timeout_secs() -> u64 {
    5
}

/// Tiered delivery configuration for quorum semantics.
///
/// This controls how messages flow through delivery tiers:
/// - Tier 1 (Direct): Race all ephemeral targets, exit on any success
/// - Tier 2 (Quorum): Broadcast to all stable targets, require quorum
/// - Tier 3 (Best-Effort): Fire-and-forget delivery (future)
#[derive(Debug, Clone, Deserialize, Serialize, Derivative)]
#[derivative(Default)]
pub struct DeliveryAppConfig {
    /// Quorum strategy for Quorum tier.
    #[serde(default)]
    pub quorum: QuorumStrategyConfig,

    // Phase 1 (Urgent) retry settings
    /// Initial retry delay in seconds for urgent phase.
    #[serde(default = "default_urgent_initial_delay")]
    #[derivative(Default(value = "default_urgent_initial_delay()"))]
    pub urgent_initial_delay_secs: u64,

    /// Maximum retry delay in seconds for urgent phase.
    #[serde(default = "default_urgent_max_delay")]
    #[derivative(Default(value = "default_urgent_max_delay()"))]
    pub urgent_max_delay_secs: u64,

    /// Backoff multiplier for urgent phase retries.
    #[serde(default = "default_urgent_backoff_multiplier")]
    #[derivative(Default(value = "default_urgent_backoff_multiplier()"))]
    pub urgent_backoff_multiplier: f32,

    // Phase 2 (Maintenance) settings
    /// Maintenance refresh interval in hours for distributed phase.
    #[serde(default = "default_maintenance_interval_hours")]
    #[derivative(Default(value = "default_maintenance_interval_hours()"))]
    pub maintenance_interval_hours: u64,

    /// Enable maintenance refreshes (default: true).
    #[serde(default = "default_maintenance_enabled")]
    #[derivative(Default(value = "true"))]
    pub maintenance_enabled: bool,

    // Tier timeouts
    /// Direct tier timeout in milliseconds.
    #[serde(default = "default_direct_tier_timeout_ms")]
    #[derivative(Default(value = "default_direct_tier_timeout_ms()"))]
    pub direct_tier_timeout_ms: u64,

    /// Quorum tier timeout in seconds.
    #[serde(default = "default_quorum_tier_timeout_secs")]
    #[derivative(Default(value = "default_quorum_tier_timeout_secs()"))]
    pub quorum_tier_timeout_secs: u64,
}

impl DeliveryAppConfig {
    /// Validate all delivery configuration values.
    ///
    /// Returns a list of validation errors (empty if valid).
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Validate quorum strategy
        if let Err(e) = self.quorum.validate() {
            errors.push(e);
        }

        // Validate backoff multiplier
        if self.urgent_backoff_multiplier <= 1.0 {
            errors.push(format!(
                "Backoff multiplier {} should be > 1.0 for exponential backoff",
                self.urgent_backoff_multiplier
            ));
        }

        // Validate delay ordering
        if self.urgent_initial_delay_secs > self.urgent_max_delay_secs {
            errors.push(format!(
                "Initial delay {}s exceeds max delay {}s",
                self.urgent_initial_delay_secs, self.urgent_max_delay_secs
            ));
        }

        // Validate timeouts are non-zero
        if self.direct_tier_timeout_ms == 0 {
            errors.push("Direct tier timeout must be > 0".to_string());
        }
        if self.quorum_tier_timeout_secs == 0 {
            errors.push("Quorum tier timeout must be > 0".to_string());
        }

        errors
    }
}

/// Convert config quorum strategy to transport quorum strategy.
impl From<QuorumStrategyConfig> for QuorumStrategy {
    fn from(config: QuorumStrategyConfig) -> Self {
        // Validate and log warnings for invalid values
        if let Err(e) = config.validate() {
            tracing::warn!("Invalid quorum strategy config: {} - using default", e);
            return QuorumStrategy::Any;
        }

        match config {
            QuorumStrategyConfig::Any => QuorumStrategy::Any,
            QuorumStrategyConfig::Count(n) => QuorumStrategy::Count(n),
            QuorumStrategyConfig::Fraction(f) => QuorumStrategy::Fraction(f),
            QuorumStrategyConfig::All => QuorumStrategy::All,
        }
    }
}

/// Convert config delivery settings to transport tiered delivery config.
impl From<DeliveryAppConfig> for TieredDeliveryConfig {
    fn from(config: DeliveryAppConfig) -> Self {
        // Validate and log warnings
        let validation_errors = config.validate();
        for error in &validation_errors {
            tracing::warn!("Delivery config warning: {}", error);
        }

        TieredDeliveryConfig {
            quorum: config.quorum.into(),
            urgent_initial_delay: Duration::from_secs(config.urgent_initial_delay_secs),
            urgent_max_delay: Duration::from_secs(config.urgent_max_delay_secs),
            urgent_backoff_multiplier: config.urgent_backoff_multiplier,
            maintenance_interval: Duration::from_secs(config.maintenance_interval_hours * 60 * 60),
            maintenance_enabled: config.maintenance_enabled,
            direct_tier_timeout: Duration::from_millis(config.direct_tier_timeout_ms),
            quorum_tier_timeout: Duration::from_secs(config.quorum_tier_timeout_secs),
            excluded_targets: std::collections::HashSet::new(),
        }
    }
}

// =============================================================================
// Embedded node default value helpers (for serde and derivative Default)
// =============================================================================

fn default_embedded_max_messages() -> u32 {
    1000
}
/// 24 hours - default TTL for embedded node
fn default_embedded_ttl_secs() -> u64 {
    86400
}

/// Embedded node configuration for in-process mailbox.
///
/// When enabled, the client runs an embedded mailbox node that can:
/// - Store messages locally for direct LAN P2P delivery
/// - Optionally expose an HTTP server for peers on the same network
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Derivative)]
#[derivative(Default)]
pub struct EmbeddedNodeConfig {
    /// Enable the embedded node (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// HTTP bind address for LAN peers (e.g., "0.0.0.0:23004").
    /// If not set, no HTTP server is started.
    /// Reserved for Phase 6: HTTP server integration.
    #[allow(unused)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_bind: Option<String>,

    /// Maximum number of messages to store (default: 1000).
    #[serde(default = "default_embedded_max_messages")]
    #[derivative(Default(value = "default_embedded_max_messages()"))]
    pub max_messages: u32,

    /// Default message TTL in seconds (default: 86400 = 24 hours).
    #[serde(default = "default_embedded_ttl_secs")]
    #[derivative(Default(value = "default_embedded_ttl_secs()"))]
    pub default_ttl_secs: u64,
}

/// Direct peer configuration for LAN P2P messaging.
///
/// Peers configured here are added as ephemeral targets with high priority,
/// enabling direct message delivery without going through quorum nodes.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DirectPeerConfig {
    /// The peer's public ID (base64-encoded 32-byte public key).
    /// Optional - reserved for Phase 6: routing messages to specific peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_id: Option<String>,

    /// HTTP address of the peer's embedded node (e.g., "<http://192.168.1.101:23004>").
    pub address: String,

    /// Human-readable name for the peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Final resolved configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    /// Unified peer configuration (replaces http and mqtt fields)
    #[serde(default)]
    pub peers: PeersConfig,

    /// Embedded node configuration for in-process mailbox
    #[serde(default)]
    pub embedded_node: EmbeddedNodeConfig,

    /// Direct peers for LAN P2P messaging
    #[serde(default)]
    pub direct_peers: Vec<DirectPeerConfig>,

    /// Directory for storing identity, keys, and messages
    pub data_dir: PathBuf,

    /// Log level
    pub log_level: String,

    /// Outbox configuration
    #[serde(default)]
    pub outbox: OutboxAppConfig,

    /// Tiered delivery configuration
    #[serde(default)]
    pub delivery: DeliveryAppConfig,
}

fn default_peers() -> PeersConfig {
    PeersConfig {
        http: vec![HttpPeerConfig {
            common: PeerCommon {
                label: Some("Default Local Node".to_string()),
                tier: ConfiguredTier::Quorum,
                priority: 100,
            },
            url: "http://localhost:23004".to_string(),
            cert_pin: None,
            node_pubkey: None,
            username: None,
            password: None,
        }],
        mqtt: Vec::new(),
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            peers: default_peers(),
            embedded_node: EmbeddedNodeConfig::default(),
            direct_peers: Vec::new(),
            data_dir: default_data_dir(),
            log_level: "info".to_string(),
            outbox: OutboxAppConfig::default(),
            delivery: DeliveryAppConfig::default(),
        }
    }
}

/// Get the default data directory based on platform conventions
fn default_data_dir() -> PathBuf {
    if let Some(proj_dirs) = ProjectDirs::from("com", "branch", "reme") {
        proj_dirs.data_dir().to_path_buf()
    } else {
        PathBuf::from("./reme_data")
    }
}

/// Get the default config file path based on platform conventions
fn default_config_path() -> Option<PathBuf> {
    ProjectDirs::from("com", "branch", "reme").map(|dirs| dirs.config_dir().join("config.toml"))
}

/// Intermediate config for deserializing from file
#[allow(deprecated)] // Legacy fields for backward compatibility
#[derive(Debug, Clone, Deserialize, Default)]
struct RawConfig {
    /// Unified peer configuration (new format)
    peers: Option<PeersConfig>,
    /// Embedded node configuration
    embedded_node: Option<EmbeddedNodeConfig>,
    /// Direct peers for LAN P2P
    direct_peers: Option<Vec<DirectPeerConfig>>,
    /// Outbox config section
    #[serde(default)]
    outbox: RawOutboxConfig,
    /// Delivery config section
    #[serde(default)]
    delivery: RawDeliveryConfig,
}

/// Raw outbox config from file/env
#[derive(Debug, Clone, Deserialize, Default)]
struct RawOutboxConfig {
    tick_interval_secs: Option<u64>,
    ttl_days: Option<u64>,
    attempt_timeout_secs: Option<u64>,
    retry_initial_delay_secs: Option<u64>,
    retry_max_delay_secs: Option<u64>,
}

/// Raw delivery config from file/env
#[derive(Debug, Clone, Deserialize, Default)]
struct RawDeliveryConfig {
    quorum: Option<QuorumStrategyConfig>,
    urgent_initial_delay_secs: Option<u64>,
    urgent_max_delay_secs: Option<u64>,
    urgent_backoff_multiplier: Option<f32>,
    maintenance_interval_hours: Option<u64>,
    maintenance_enabled: Option<bool>,
    direct_tier_timeout_ms: Option<u64>,
    quorum_tier_timeout_secs: Option<u64>,
}

/// Load configuration from all sources with proper layering
///
/// Priority (highest to lowest):
/// 1. CLI arguments
/// 2. Environment variables (REME_*)
/// 3. Config file
/// 4. Built-in defaults
#[allow(clippy::too_many_lines)] // Config loading requires many steps
pub fn load_config() -> Result<AppConfig, config::ConfigError> {
    let cli = CliArgs::parse();

    // Start with defaults
    let defaults = AppConfig::default();

    let mut builder = Config::builder()
        // Layer 1: Built-in defaults (lowest priority)
        .set_default("data_dir", defaults.data_dir.to_string_lossy().to_string())?
        .set_default("log_level", defaults.log_level)?;

    // Layer 2: Config file
    // Try custom config path from CLI, then default location
    let config_path = cli.config.clone().or_else(default_config_path);
    if let Some(path) = config_path {
        if path.exists() {
            builder = builder.add_source(File::from(path).format(FileFormat::Toml).required(false));
        }
    }

    // Layer 3: Environment variables (REME_*)
    builder = builder.add_source(
        Environment::with_prefix("REME")
            .separator("_")
            .try_parsing(true),
    );

    // Layer 4: CLI arguments (highest priority)
    // Only override if explicitly provided (skip None values)
    if let Some(ref data_dir) = cli.data_dir {
        builder = builder.set_override("data_dir", data_dir.to_string_lossy().to_string())?;
    }
    if let Some(ref log_level) = cli.log_level {
        builder = builder.set_override("log_level", log_level.clone())?;
    }

    let config = builder.build()?;

    // Get other config values first (before consuming config)
    let data_dir_str: String = config
        .get("data_dir")
        .unwrap_or_else(|_| defaults.data_dir.to_string_lossy().to_string());
    let log_level: String = config
        .get("log_level")
        .unwrap_or_else(|_| "info".to_string());

    // Deserialize raw config for file-based settings
    let raw: RawConfig = config.try_deserialize().unwrap_or_default();

    // Build PeersConfig from multiple sources (evaluated in order):
    // 1. Config file [peers] section or REME_PEERS env (primary source)
    // 3. CLI args (--http-url, --mqtt-url) - ADDITIVE (appended to above)
    // 4. Default if none of the above
    let mut peers = if let Some(peers_config) = raw.peers {
        peers_config
    } else if let Ok(peers_json) = std::env::var("REME_PEERS") {
        // Parse REME_PEERS if present
        match serde_json::from_str(&peers_json) {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to parse REME_PEERS as JSON: {} - using defaults", e);
                default_peers()
            }
        }
    } else {
        // Use default
        default_peers()
    };

    // Apply CLI arguments on top of all other sources
    // Handle HTTP URLs with cert pins
    if let Some(urls) = &cli.http_url {
        // TODO: Add --http-username and --http-password CLI flags for HTTP authentication
        // Currently only config-based HTTP peers support authentication
        let cert_pins = cli.http_cert_pin.as_deref();
        let (http_peers, warnings) = HttpPeerConfig::from_cli_urls(urls, cert_pins, None, None);

        for warning in warnings {
            warn!("{}", warning);
        }

        peers.http.extend(http_peers);
    }

    // Handle MQTT URLs with client IDs
    if let Some(urls) = &cli.mqtt_url {
        // TODO: Add --mqtt-username and --mqtt-password CLI flags for MQTT authentication
        // Currently only config-based MQTT peers support authentication
        let client_ids = cli.mqtt_client_id.as_deref();
        let (mqtt_peers, warnings) = MqttPeerConfig::from_cli_urls(urls, client_ids, None, None);

        for warning in warnings {
            warn!("{}", warning);
        }

        peers.mqtt.extend(mqtt_peers);
    }

    // Expand ~ in data_dir path
    let data_dir = expand_tilde(&data_dir_str);

    // Build outbox config with priority: CLI > config file > defaults
    let outbox = OutboxAppConfig {
        tick_interval_secs: cli
            .outbox_tick_interval
            .or(raw.outbox.tick_interval_secs)
            .unwrap_or_else(default_outbox_tick_interval),
        ttl_days: cli
            .outbox_ttl_days
            .or(raw.outbox.ttl_days)
            .unwrap_or_else(default_outbox_ttl_days),
        attempt_timeout_secs: cli
            .outbox_attempt_timeout
            .or(raw.outbox.attempt_timeout_secs)
            .unwrap_or_else(default_outbox_attempt_timeout),
        retry_initial_delay_secs: cli
            .outbox_retry_initial_delay
            .or(raw.outbox.retry_initial_delay_secs)
            .unwrap_or_else(default_outbox_retry_initial_delay),
        retry_max_delay_secs: cli
            .outbox_retry_max_delay
            .or(raw.outbox.retry_max_delay_secs)
            .unwrap_or_else(default_outbox_retry_max_delay),
    };

    // Build delivery config from config file > defaults (no CLI args for delivery)
    let delivery = DeliveryAppConfig {
        quorum: raw.delivery.quorum.unwrap_or_default(),
        urgent_initial_delay_secs: raw
            .delivery
            .urgent_initial_delay_secs
            .unwrap_or_else(default_urgent_initial_delay),
        urgent_max_delay_secs: raw
            .delivery
            .urgent_max_delay_secs
            .unwrap_or_else(default_urgent_max_delay),
        urgent_backoff_multiplier: raw
            .delivery
            .urgent_backoff_multiplier
            .unwrap_or_else(default_urgent_backoff_multiplier),
        maintenance_interval_hours: raw
            .delivery
            .maintenance_interval_hours
            .unwrap_or_else(default_maintenance_interval_hours),
        maintenance_enabled: raw
            .delivery
            .maintenance_enabled
            .unwrap_or_else(default_maintenance_enabled),
        direct_tier_timeout_ms: raw
            .delivery
            .direct_tier_timeout_ms
            .unwrap_or_else(default_direct_tier_timeout_ms),
        quorum_tier_timeout_secs: raw
            .delivery
            .quorum_tier_timeout_secs
            .unwrap_or_else(default_quorum_tier_timeout_secs),
    };

    // Resolve embedded node config with priority: CLI > config file > defaults
    let embedded_node_file = raw.embedded_node.unwrap_or_default();
    let embedded_node = EmbeddedNodeConfig {
        // CLI flags take priority: --embedded-node enables, --no-embedded-node disables
        enabled: match (cli.embedded_node, cli.no_embedded_node) {
            (true, _) => true,
            (_, true) => false,
            _ => embedded_node_file.enabled,
        },
        http_bind: cli.embedded_http_bind.or(embedded_node_file.http_bind),
        max_messages: embedded_node_file.max_messages,
        default_ttl_secs: embedded_node_file.default_ttl_secs,
    };

    // Resolve direct peers from config file > defaults (empty)
    let direct_peers = raw.direct_peers.unwrap_or_default();

    Ok(AppConfig {
        peers,
        embedded_node,
        direct_peers,
        data_dir,
        log_level,
        outbox,
        delivery,
    })
}

/// Expand ~ to home directory in paths
fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") || path == "~" {
        if let Some(home) = dirs_home() {
            return home.join(path.strip_prefix("~/").unwrap_or(""));
        }
    }
    PathBuf::from(path)
}

/// Get the user's home directory
fn dirs_home() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf())
}

/// Generate a default config file content
#[allow(clippy::too_many_lines, dead_code)] // Template generation, may be used for init command
pub fn default_config_toml() -> String {
    let defaults = AppConfig::default();
    let quorum_str = match &defaults.delivery.quorum {
        QuorumStrategyConfig::Any => "\"any\"".to_string(),
        QuorumStrategyConfig::Count(n) => format!("{{ count = {n} }}"),
        QuorumStrategyConfig::Fraction(f) => format!("{{ fraction = {f} }}"),
        QuorumStrategyConfig::All => "\"all\"".to_string(),
    };
    format!(
        r#"# Resilient Messenger Client Configuration
#
# This file is loaded from:
#   Linux/macOS: ~/.config/reme/config.toml
#   Windows: %APPDATA%\reme\config.toml
#
# All settings can be overridden by:
#   1. Environment variables: REME_HTTP='[{{"url":"...", "cert_pin":"..."}}]'
#   2. CLI arguments: --http-url <url> --http-cert-pin <pin>

# HTTP endpoint configuration with optional certificate pinning
# For TLS with pinning:
# [[http]]
# url = "https://node1.example.com:23003"
# cert_pin = "spki//sha256/AAAA..."  # SPKI hash
#
# [[http]]
# url = "https://node2.example.com:23003"
# cert_pin = "cert//sha256/BBBB..."  # Certificate hash
#
# Without pinning (will warn):
[[http]]
url = "{url}"

# MQTT broker configuration (optional)
# Messages can be exchanged via MQTT in addition to or instead of HTTP.
# Note: MQTT uses system root certificates (no certificate pinning support)
#
# [[mqtt]]
# url = "mqtts://broker.example.com:8883"
# client_id = "my-client"  # Optional, auto-generated if not set

# Directory for storing identity, keys, and messages
# Use ~ for home directory
data_dir = "{data_dir}"

# Log level: trace, debug, info, warn, error
log_level = "{log_level}"

# Outbox configuration for message delivery tracking and retries
[outbox]
# How often to check for pending retries (seconds)
tick_interval_secs = {tick_interval}

# Message TTL in days (0 = never expire)
ttl_days = {ttl_days}

# How long a "sent" attempt stays in-flight before timing out (seconds)
attempt_timeout_secs = {attempt_timeout}

# Retry backoff settings
retry_initial_delay_secs = {retry_initial}
retry_max_delay_secs = {retry_max}

# Tiered delivery configuration
# Messages flow through delivery tiers: Direct -> Quorum -> Best-Effort
# with configurable quorum requirements for the Quorum tier.
[delivery]
# Quorum strategy for Quorum tier:
# - "any" = any single transport success (legacy behavior)
# - {{ count = N }} = at least N transports must succeed
# - {{ fraction = F }} = fraction of stable transports (e.g., 0.5 = majority)
# - "all" = all configured stable transports must succeed
quorum = {quorum}

# Phase 1 (Urgent) retry settings
# Aggressive retry until quorum is reached
urgent_initial_delay_secs = {urgent_initial}
urgent_max_delay_secs = {urgent_max}
urgent_backoff_multiplier = {urgent_multiplier}

# Phase 2 (Maintenance) settings
# Periodic refresh of distributed messages awaiting ACK
maintenance_interval_hours = {maintenance_interval}
maintenance_enabled = {maintenance_enabled}

# Tier timeouts
direct_tier_timeout_ms = {direct_timeout}
quorum_tier_timeout_secs = {quorum_timeout}

# Embedded node configuration for LAN P2P messaging
# When enabled, runs an in-process mailbox node for direct peer delivery.
[embedded_node]
# Enable the embedded node (default: false)
enabled = false
# HTTP bind address for accepting messages from LAN peers
# Uncomment to enable: http_bind = "0.0.0.0:23004"
# Maximum messages to store locally
max_messages = {embedded_max_messages}
# Default message TTL in seconds (24 hours)
default_ttl_secs = {embedded_ttl_secs}

# Direct peers for LAN P2P messaging (optional)
# Messages to these peers will be delivered directly via their embedded node.
#
# [[direct_peers]]
# address = "http://192.168.1.101:23004"
# name = "Bob (LAN)"                          # Optional
# public_id = "BASE64_ENCODED_PUBLIC_ID"      # Optional, reserved for future
"#,
        url = defaults.peers.http[0].url,
        data_dir = defaults.data_dir.to_string_lossy(),
        log_level = defaults.log_level,
        tick_interval = defaults.outbox.tick_interval_secs,
        ttl_days = defaults.outbox.ttl_days,
        attempt_timeout = defaults.outbox.attempt_timeout_secs,
        retry_initial = defaults.outbox.retry_initial_delay_secs,
        retry_max = defaults.outbox.retry_max_delay_secs,
        quorum = quorum_str,
        urgent_initial = defaults.delivery.urgent_initial_delay_secs,
        urgent_max = defaults.delivery.urgent_max_delay_secs,
        urgent_multiplier = defaults.delivery.urgent_backoff_multiplier,
        maintenance_interval = defaults.delivery.maintenance_interval_hours,
        maintenance_enabled = defaults.delivery.maintenance_enabled,
        direct_timeout = defaults.delivery.direct_tier_timeout_ms,
        quorum_timeout = defaults.delivery.quorum_tier_timeout_secs,
        embedded_max_messages = defaults.embedded_node.max_messages,
        embedded_ttl_secs = defaults.embedded_node.default_ttl_secs,
    )
}

/// Parse log level from string
pub(crate) fn parse_log_level(level: &str) -> Level {
    match level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" | "warning" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO, // Default to INFO for "info" and unrecognized levels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.peers.http.len(), 1);
        assert_eq!(config.peers.http[0].url, "http://localhost:23004");
        assert_eq!(config.peers.http[0].cert_pin, None);
        assert!(config.peers.mqtt.is_empty());
        assert!(!config.embedded_node.enabled);
        assert!(config.direct_peers.is_empty());
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn test_expand_tilde() {
        // Test that non-tilde paths are unchanged
        let path = expand_tilde("/absolute/path");
        assert_eq!(path, PathBuf::from("/absolute/path"));

        let path = expand_tilde("relative/path");
        assert_eq!(path, PathBuf::from("relative/path"));
    }

    #[test]
    fn test_default_config_toml() {
        let toml = default_config_toml();
        assert!(toml.contains("[[http]]"));
        assert!(toml.contains("url ="));
        assert!(toml.contains("data_dir"));
        assert!(toml.contains("log_level"));
        assert!(toml.contains("[outbox]"));
        assert!(toml.contains("tick_interval_secs"));
        assert!(toml.contains("ttl_days"));
        assert!(toml.contains("[[mqtt]]")); // Documentation for MQTT
        assert!(toml.contains("[delivery]"));
        assert!(toml.contains("quorum"));
        assert!(toml.contains("urgent_initial_delay_secs"));
        assert!(toml.contains("maintenance_interval_hours"));
    }

    #[test]
    fn test_default_peers() {
        let peers = default_peers();
        assert_eq!(peers.http.len(), 1);
        assert_eq!(peers.http[0].url, "http://localhost:23004");
        assert_eq!(peers.http[0].cert_pin, None);
        assert!(peers.mqtt.is_empty());
    }

    #[test]
    #[allow(clippy::float_cmp)] // Comparing default constants, exact equality is valid
    fn test_delivery_config_defaults() {
        let config = DeliveryAppConfig::default();
        assert_eq!(config.quorum, QuorumStrategyConfig::Any);
        assert_eq!(config.urgent_initial_delay_secs, 5);
        assert_eq!(config.urgent_max_delay_secs, 60);
        assert_eq!(config.urgent_backoff_multiplier, 2.0);
        assert_eq!(config.maintenance_interval_hours, 4);
        assert!(config.maintenance_enabled);
        assert_eq!(config.direct_tier_timeout_ms, 500);
        assert_eq!(config.quorum_tier_timeout_secs, 5);
    }

    #[test]
    fn test_quorum_strategy_deserialize() {
        // Test "any"
        let json = r#""any""#;
        let quorum: QuorumStrategyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(quorum, QuorumStrategyConfig::Any);

        // Test count
        let json = r#"{"count": 2}"#;
        let quorum: QuorumStrategyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(quorum, QuorumStrategyConfig::Count(2));

        // Test fraction
        let json = r#"{"fraction": 0.5}"#;
        let quorum: QuorumStrategyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(quorum, QuorumStrategyConfig::Fraction(0.5));

        // Test "all"
        let json = r#""all""#;
        let quorum: QuorumStrategyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(quorum, QuorumStrategyConfig::All);
    }

    #[test]
    fn test_delivery_config_deserialize() {
        let json = r#"{
            "quorum": {"count": 3},
            "urgent_initial_delay_secs": 10,
            "maintenance_interval_hours": 8
        }"#;
        let config: DeliveryAppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.quorum, QuorumStrategyConfig::Count(3));
        assert_eq!(config.urgent_initial_delay_secs, 10);
        assert_eq!(config.maintenance_interval_hours, 8);
        // Unspecified fields should get defaults
        assert_eq!(config.urgent_max_delay_secs, 60);
        assert!(config.maintenance_enabled);
    }

    #[test]
    fn test_quorum_strategy_conversion() {
        // Test Any
        let config = QuorumStrategyConfig::Any;
        let transport: QuorumStrategy = config.into();
        assert!(matches!(transport, QuorumStrategy::Any));

        // Test Count
        let config = QuorumStrategyConfig::Count(5);
        let transport: QuorumStrategy = config.into();
        assert!(matches!(transport, QuorumStrategy::Count(5)));

        // Test Fraction
        let config = QuorumStrategyConfig::Fraction(0.75);
        let transport: QuorumStrategy = config.into();
        match transport {
            QuorumStrategy::Fraction(f) => assert!((f - 0.75).abs() < 0.001),
            _ => panic!("Expected Fraction"),
        }

        // Test All
        let config = QuorumStrategyConfig::All;
        let transport: QuorumStrategy = config.into();
        assert!(matches!(transport, QuorumStrategy::All));
    }

    #[test]
    fn test_delivery_config_conversion() {
        let config = DeliveryAppConfig {
            quorum: QuorumStrategyConfig::Count(2),
            urgent_initial_delay_secs: 10,
            urgent_max_delay_secs: 120,
            urgent_backoff_multiplier: 1.5,
            maintenance_interval_hours: 6,
            maintenance_enabled: false,
            direct_tier_timeout_ms: 1000,
            quorum_tier_timeout_secs: 10,
        };

        let transport: TieredDeliveryConfig = config.into();

        assert!(matches!(transport.quorum, QuorumStrategy::Count(2)));
        assert_eq!(transport.urgent_initial_delay, Duration::from_secs(10));
        assert_eq!(transport.urgent_max_delay, Duration::from_secs(120));
        assert!((transport.urgent_backoff_multiplier - 1.5).abs() < 0.001);
        assert_eq!(
            transport.maintenance_interval,
            Duration::from_secs(6 * 60 * 60)
        );
        assert!(!transport.maintenance_enabled);
        assert_eq!(transport.direct_tier_timeout, Duration::from_millis(1000));
        assert_eq!(transport.quorum_tier_timeout, Duration::from_secs(10));
        assert!(transport.excluded_targets.is_empty());
    }

    #[test]
    fn test_embedded_node_config_defaults() {
        let config = EmbeddedNodeConfig::default();
        assert!(!config.enabled);
        assert!(config.http_bind.is_none());
        assert_eq!(config.max_messages, 1000);
        assert_eq!(config.default_ttl_secs, 86400);
    }

    #[test]
    fn test_embedded_node_config_deserialize_full() {
        let json = r#"{
            "enabled": true,
            "http_bind": "0.0.0.0:23004",
            "max_messages": 500,
            "default_ttl_secs": 3600
        }"#;
        let config: EmbeddedNodeConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.http_bind, Some("0.0.0.0:23004".to_string()));
        assert_eq!(config.max_messages, 500);
        assert_eq!(config.default_ttl_secs, 3600);
    }

    #[test]
    fn test_embedded_node_config_deserialize_minimal() {
        // Only enabled flag, rest should use defaults
        let json = r#"{"enabled": true}"#;
        let config: EmbeddedNodeConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert!(config.http_bind.is_none());
        assert_eq!(config.max_messages, 1000);
        assert_eq!(config.default_ttl_secs, 86400);
    }

    #[test]
    fn test_direct_peer_config_deserialize() {
        let json = r#"{
            "public_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "address": "http://192.168.1.101:23004",
            "name": "Bob (LAN)"
        }"#;
        let config: DirectPeerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.public_id,
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string())
        );
        assert_eq!(config.address, "http://192.168.1.101:23004");
        assert_eq!(config.name, Some("Bob (LAN)".to_string()));
    }

    #[test]
    fn test_direct_peer_config_deserialize_without_public_id() {
        // public_id is optional - minimal config with just address
        let json = r#"{
            "address": "http://192.168.1.101:23004"
        }"#;
        let config: DirectPeerConfig = serde_json::from_str(json).unwrap();
        assert!(config.public_id.is_none());
        assert_eq!(config.address, "http://192.168.1.101:23004");
        assert!(config.name.is_none());
    }

    #[test]
    fn test_direct_peer_config_deserialize_with_name_only() {
        let json = r#"{
            "address": "http://192.168.1.101:23004",
            "name": "Bob (LAN)"
        }"#;
        let config: DirectPeerConfig = serde_json::from_str(json).unwrap();
        assert!(config.public_id.is_none());
        assert_eq!(config.address, "http://192.168.1.101:23004");
        assert_eq!(config.name, Some("Bob (LAN)".to_string()));
    }

    #[test]
    fn test_direct_peers_in_app_config() {
        let toml = r#"
            data_dir = "/tmp/test"
            log_level = "info"

            [[http]]
            url = "http://localhost:23003"

            [[direct_peers]]
            public_id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            address = "http://192.168.1.101:23004"
            name = "Alice"

            [[direct_peers]]
            address = "http://192.168.1.102:23004"
        "#;
        let config: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.direct_peers.len(), 2);
        assert_eq!(
            config.direct_peers[0].public_id,
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string())
        );
        assert_eq!(config.direct_peers[0].name, Some("Alice".to_string()));
        assert!(config.direct_peers[1].public_id.is_none());
        assert!(config.direct_peers[1].name.is_none());
    }
}
