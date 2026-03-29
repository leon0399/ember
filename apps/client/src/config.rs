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
//!
//! # LAN Discovery — automatic peer detection on local network
//! [lan_discovery]
//! enabled = true              # Enable mDNS advertisement (browsing requires auto_direct_known_contacts)
//! # auto_direct_known_contacts = true   # Verify and register discovered peers for direct delivery
//! # max_peers = 256           # Maximum number of tracked LAN peers
//! ```
//!
//! Prefer `[[peers.http]]` and `[[peers.mqtt]]` for current configs.
//! Legacy examples may still appear in older templates while migration work is completed.

use clap::{Parser, Subcommand};
use config::{Config, Environment, File, FileFormat};
use derivative::Derivative;
use directories::ProjectDirs;
use reme_config::{ConfiguredTier, HttpPeerConfig, MqttPeerConfig, PeerCommon, PeersConfig};
use reme_transport::{QuorumStrategy, TieredDeliveryConfig};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use tracing::warn;

/// Top-level CLI parser with optional subcommand
#[derive(Parser, Debug, Clone)]
#[command(name = "reme")]
#[command(author, version, about = "Resilient Messenger")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Directory for storing identity, keys, and messages
    #[arg(short = 'd', long, env = "REME_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// Path to config file (default: ~/.config/reme/config.toml)
    #[arg(short = 'c', long, env = "REME_CONFIG")]
    pub config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'l', long, env = "REME_LOG_LEVEL")]
    pub log_level: Option<String>,
}

impl Cli {
    /// Returns the TUI args if the command is `Tui` (or `None` when no subcommand).
    pub const fn tui_args(&self) -> Option<&TuiArgs> {
        match &self.command {
            Some(Commands::Tui(args)) => Some(args),
            _ => None,
        }
    }
}

/// Available subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Launch the interactive TUI (default when no subcommand given)
    Tui(TuiArgs),
    /// Export pending messages to a .reme bundle file
    Export(ExportArgs),
    /// Import messages from a .reme bundle file
    Import(ImportArgs),
}

/// TUI-specific CLI arguments
#[derive(Parser, Debug, Clone)]
pub struct TuiArgs {
    /// HTTP endpoint URLs (pair with --http-cert-pin by order)
    ///
    /// Example: --http-url https://node1:23003,https://node2:23003
    #[arg(long, value_delimiter = ',')]
    pub http_url: Option<Vec<String>>,

    /// Certificate pins for HTTP endpoints (pair with --http-url by order)
    ///
    /// Format: spki//sha256/<base64> or cert//sha256/<base64>
    /// Example: --http-cert-pin spki//sha256/aaa=,spki//sha256/bbb=
    #[arg(long, value_delimiter = ',')]
    pub http_cert_pin: Option<Vec<String>>,

    /// MQTT broker URLs (pair with --mqtt-client-id by order)
    ///
    /// Example: --mqtt-url mqtts://broker1:8883,mqtts://broker2:8883
    #[arg(long, value_delimiter = ',')]
    pub mqtt_url: Option<Vec<String>>,

    /// Client IDs for MQTT brokers (pair with --mqtt-url by order)
    ///
    /// If not specified, random client IDs will be generated
    #[arg(long, value_delimiter = ',')]
    pub mqtt_client_id: Option<Vec<String>>,

    /// Outbox retry check interval in seconds
    #[arg(long, env = "REME_OUTBOX_TICK_INTERVAL")]
    pub outbox_tick_interval: Option<u64>,

    /// Message TTL in days (0 = never expire)
    #[arg(long, env = "REME_OUTBOX_TTL_DAYS")]
    pub outbox_ttl_days: Option<u64>,

    /// Attempt timeout in seconds (how long before retry)
    #[arg(long, env = "REME_OUTBOX_ATTEMPT_TIMEOUT")]
    pub outbox_attempt_timeout: Option<u64>,

    /// Initial retry delay in seconds
    #[arg(long, env = "REME_OUTBOX_RETRY_INITIAL_DELAY")]
    pub outbox_retry_initial_delay: Option<u64>,

    /// Maximum retry delay in seconds
    #[arg(long, env = "REME_OUTBOX_RETRY_MAX_DELAY")]
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
    pub embedded_http_bind: Option<String>,
}

/// Arguments for the export subcommand
#[derive(Parser, Debug, Clone)]
pub struct ExportArgs {
    /// Output path for the .reme bundle
    pub file: PathBuf,

    /// Export only messages for this recipient (hex-encoded public ID)
    #[arg(long)]
    pub to: Option<String>,

    /// Include already-confirmed messages (re-export)
    #[arg(long)]
    pub include_sent: bool,

    /// Overwrite existing output file
    #[arg(long)]
    pub force: bool,

    /// Export at most N messages
    #[arg(long)]
    pub limit: Option<usize>,

    /// Only export messages created within this duration (e.g. 24h, 7d)
    #[arg(long)]
    pub since: Option<String>,
}

/// Arguments for the import subcommand
#[derive(Parser, Debug, Clone)]
pub struct ImportArgs {
    /// Path to a .reme bundle file to import
    pub file: PathBuf,
}

// =============================================================================
// Outbox default value helpers (for serde and derivative Default)
// =============================================================================

const fn default_outbox_tick_interval() -> u64 {
    5
}
const fn default_outbox_ttl_days() -> u64 {
    7
}
/// 1 minute - attempt timeout
const fn default_outbox_attempt_timeout() -> u64 {
    60
}
const fn default_outbox_retry_initial_delay() -> u64 {
    5
}
/// 5 minutes - max retry delay
const fn default_outbox_retry_max_delay() -> u64 {
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
            Self::Count(n) if *n == 0 => Err("Quorum count must be > 0".to_string()),
            Self::Fraction(f) if f.is_nan() || f.is_infinite() => Err(format!(
                "Invalid quorum fraction {f}: must be a finite number"
            )),
            Self::Fraction(f) if *f <= 0.0 || *f > 1.0 => Err(format!(
                "Quorum fraction {f} out of range: must be in (0.0, 1.0]"
            )),
            Self::Any | Self::All | Self::Count(_) | Self::Fraction(_) => Ok(()),
        }
    }
}

// =============================================================================
// Delivery default value helpers (for serde and derivative Default)
// =============================================================================

const fn default_urgent_initial_delay() -> u64 {
    5
}
/// 1 minute - max urgent delay
const fn default_urgent_max_delay() -> u64 {
    60
}
const fn default_urgent_backoff_multiplier() -> f32 {
    2.0
}
/// 4 hours - maintenance interval
const fn default_maintenance_interval_hours() -> u64 {
    4
}
const fn default_maintenance_enabled() -> bool {
    true
}
/// 500ms - direct tier timeout
const fn default_direct_tier_timeout_ms() -> u64 {
    500
}
const fn default_quorum_tier_timeout_secs() -> u64 {
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
            return Self::Any;
        }

        match config {
            QuorumStrategyConfig::Any => Self::Any,
            QuorumStrategyConfig::Count(n) => Self::Count(n),
            QuorumStrategyConfig::Fraction(f) => Self::Fraction(f),
            QuorumStrategyConfig::All => Self::All,
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

        Self {
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

const fn default_embedded_max_messages() -> u32 {
    1000
}
/// 24 hours - default TTL for embedded node
const fn default_embedded_ttl_secs() -> u64 {
    86400
}

/// Embedded node configuration for in-process mailbox.
///
/// When enabled, the client runs an embedded mailbox node that can:
/// - Store messages locally for direct LAN P2P delivery
/// - Optionally expose an HTTP server for peers on the same network
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Derivative)]
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

/// LAN discovery configuration for mDNS-based peer discovery.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct LanDiscoveryConfig {
    /// Enable mDNS/LAN peer discovery (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// Automatically verify and register discovered peers that match known
    /// contacts for direct LAN delivery (default: true when enabled).
    /// When false, the discovery controller is not spawned — the node is
    /// advertise-only (no browsing or peer verification).
    #[serde(
        default = "default_auto_direct_known_contacts",
        alias = "allow_direct_lan"
    )]
    pub auto_direct_known_contacts: bool,

    /// Max discovered peers to track (default: 256).
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,

    /// Interval in seconds between periodic re-verification of tracked peers
    /// (default: 300). On each tick, all peers in the index are re-verified;
    /// peers that fail verification are subject to the stale-peer circuit breaker.
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_secs: u64,
}

const DEFAULT_LAN_ALLOW_DIRECT: bool = true;
const DEFAULT_LAN_MAX_PEERS: usize = 256;
const DEFAULT_LAN_REFRESH_INTERVAL_SECS: u64 = 300;

impl Default for LanDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_direct_known_contacts: DEFAULT_LAN_ALLOW_DIRECT,
            max_peers: DEFAULT_LAN_MAX_PEERS,
            refresh_interval_secs: DEFAULT_LAN_REFRESH_INTERVAL_SECS,
        }
    }
}

const fn default_auto_direct_known_contacts() -> bool {
    DEFAULT_LAN_ALLOW_DIRECT
}

const fn default_max_peers() -> usize {
    DEFAULT_LAN_MAX_PEERS
}

const fn default_refresh_interval() -> u64 {
    DEFAULT_LAN_REFRESH_INTERVAL_SECS
}

/// Direct peer configuration for LAN P2P messaging.
///
/// Peers configured here are added as ephemeral targets with high priority,
/// enabling direct message delivery without going through quorum nodes.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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

    /// LAN discovery configuration
    #[serde(default)]
    pub lan_discovery: LanDiscoveryConfig,
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
            lan_discovery: LanDiscoveryConfig::default(),
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
    /// LAN discovery config section
    #[serde(default)]
    lan_discovery: Option<LanDiscoveryConfig>,
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

/// Load configuration from pre-parsed CLI args.
///
/// `tui_args` should be `Some` only when running the `tui` subcommand.
/// When `None` (including bare `reme` with no subcommand), TUI-specific
/// CLI overrides (transport URLs, outbox tuning, embedded node flags) are
/// skipped — config file and env vars still apply.
///
/// Priority (highest to lowest):
/// 1. CLI arguments
/// 2. Environment variables (REME_*)
/// 3. Config file
/// 4. Built-in defaults
#[allow(clippy::too_many_lines)] // Config loading requires many steps
pub fn load_config_from(
    cli: &Cli,
    tui_args: Option<&TuiArgs>,
) -> Result<AppConfig, config::ConfigError> {
    let defaults = AppConfig::default();
    let config = build_layered_config(cli, &defaults)?;

    let data_dir_str: String = config
        .get("data_dir")
        .unwrap_or_else(|_| defaults.data_dir.to_string_lossy().to_string());
    let log_level: String = config
        .get("log_level")
        .unwrap_or_else(|_| "info".to_string());

    let raw: RawConfig = config.try_deserialize().unwrap_or_default();
    let mut peers = resolve_peers(&raw);
    apply_tui_peer_overrides(&mut peers, tui_args);

    let data_dir = expand_tilde(&data_dir_str);
    let outbox = build_outbox_config(tui_args, &raw.outbox);
    let delivery = build_delivery_config(&raw.delivery);
    let embedded_node = resolve_embedded_node(tui_args, raw.embedded_node);
    let direct_peers = raw.direct_peers.unwrap_or_default();
    let lan_discovery = raw.lan_discovery.unwrap_or_default();

    Ok(AppConfig {
        peers,
        embedded_node,
        direct_peers,
        data_dir,
        log_level,
        outbox,
        delivery,
        lan_discovery,
    })
}

/// Build the layered config (defaults < file < env < CLI).
fn build_layered_config(cli: &Cli, defaults: &AppConfig) -> Result<Config, config::ConfigError> {
    let mut builder = Config::builder()
        .set_default("data_dir", defaults.data_dir.to_string_lossy().to_string())?
        .set_default("log_level", defaults.log_level.clone())?;

    let config_path = cli.config.clone().or_else(default_config_path);
    if let Some(path) = config_path {
        if path.exists() {
            builder = builder.add_source(File::from(path).format(FileFormat::Toml).required(false));
        }
    }

    builder = builder.add_source(
        Environment::with_prefix("REME")
            .separator("_")
            .try_parsing(true),
    );

    if let Some(ref data_dir) = cli.data_dir {
        builder = builder.set_override("data_dir", data_dir.to_string_lossy().to_string())?;
    }
    if let Some(ref log_level) = cli.log_level {
        builder = builder.set_override("log_level", log_level.clone())?;
    }

    builder.build()
}

/// Resolve peers from config file or `REME_PEERS` env, falling back to defaults.
fn resolve_peers(raw: &RawConfig) -> PeersConfig {
    if let Some(ref peers_config) = raw.peers {
        return peers_config.clone();
    }
    if let Ok(peers_json) = std::env::var("REME_PEERS") {
        match serde_json::from_str(&peers_json) {
            Ok(p) => return p,
            Err(e) => {
                warn!("Failed to parse REME_PEERS as JSON: {} - using defaults", e);
            }
        }
    }
    default_peers()
}

/// Apply TUI-specific CLI peer arguments (HTTP and MQTT URLs).
fn apply_tui_peer_overrides(peers: &mut PeersConfig, tui_args: Option<&TuiArgs>) {
    let Some(tui) = tui_args else { return };
    apply_http_cli_peers(peers, tui);
    apply_mqtt_cli_peers(peers, tui);
}

fn apply_http_cli_peers(peers: &mut PeersConfig, tui: &TuiArgs) {
    let Some(urls) = &tui.http_url else { return };
    let cert_pins = tui.http_cert_pin.as_deref();
    let (http_peers, warnings) = HttpPeerConfig::from_cli_urls(urls, cert_pins, None, None);
    for warning in warnings {
        warn!("{}", warning);
    }
    peers.http.extend(http_peers);
}

fn apply_mqtt_cli_peers(peers: &mut PeersConfig, tui: &TuiArgs) {
    let Some(urls) = &tui.mqtt_url else { return };
    let client_ids = tui.mqtt_client_id.as_deref();
    let (mqtt_peers, warnings) = MqttPeerConfig::from_cli_urls(urls, client_ids, None, None);
    for warning in warnings {
        warn!("{}", warning);
    }
    peers.mqtt.extend(mqtt_peers);
}

/// Build outbox config with priority: CLI > config file > defaults.
fn build_outbox_config(tui_args: Option<&TuiArgs>, raw: &RawOutboxConfig) -> OutboxAppConfig {
    OutboxAppConfig {
        tick_interval_secs: tui_args
            .and_then(|t| t.outbox_tick_interval)
            .or(raw.tick_interval_secs)
            .unwrap_or_else(default_outbox_tick_interval),
        ttl_days: tui_args
            .and_then(|t| t.outbox_ttl_days)
            .or(raw.ttl_days)
            .unwrap_or_else(default_outbox_ttl_days),
        attempt_timeout_secs: tui_args
            .and_then(|t| t.outbox_attempt_timeout)
            .or(raw.attempt_timeout_secs)
            .unwrap_or_else(default_outbox_attempt_timeout),
        retry_initial_delay_secs: tui_args
            .and_then(|t| t.outbox_retry_initial_delay)
            .or(raw.retry_initial_delay_secs)
            .unwrap_or_else(default_outbox_retry_initial_delay),
        retry_max_delay_secs: tui_args
            .and_then(|t| t.outbox_retry_max_delay)
            .or(raw.retry_max_delay_secs)
            .unwrap_or_else(default_outbox_retry_max_delay),
    }
}

/// Build delivery config from config file values with defaults.
fn build_delivery_config(raw: &RawDeliveryConfig) -> DeliveryAppConfig {
    DeliveryAppConfig {
        quorum: raw.quorum.clone().unwrap_or_default(),
        urgent_initial_delay_secs: raw
            .urgent_initial_delay_secs
            .unwrap_or_else(default_urgent_initial_delay),
        urgent_max_delay_secs: raw
            .urgent_max_delay_secs
            .unwrap_or_else(default_urgent_max_delay),
        urgent_backoff_multiplier: raw
            .urgent_backoff_multiplier
            .unwrap_or_else(default_urgent_backoff_multiplier),
        maintenance_interval_hours: raw
            .maintenance_interval_hours
            .unwrap_or_else(default_maintenance_interval_hours),
        maintenance_enabled: raw
            .maintenance_enabled
            .unwrap_or_else(default_maintenance_enabled),
        direct_tier_timeout_ms: raw
            .direct_tier_timeout_ms
            .unwrap_or_else(default_direct_tier_timeout_ms),
        quorum_tier_timeout_secs: raw
            .quorum_tier_timeout_secs
            .unwrap_or_else(default_quorum_tier_timeout_secs),
    }
}

/// Resolve embedded node config with priority: CLI > config file > defaults.
fn resolve_embedded_node(
    tui_args: Option<&TuiArgs>,
    raw: Option<EmbeddedNodeConfig>,
) -> EmbeddedNodeConfig {
    let file_config = raw.unwrap_or_default();
    let Some(tui) = tui_args else {
        return file_config;
    };
    EmbeddedNodeConfig {
        enabled: match (tui.embedded_node, tui.no_embedded_node) {
            (true, _) => true,
            (_, true) => false,
            _ => file_config.enabled,
        },
        http_bind: tui.embedded_http_bind.clone().or(file_config.http_bind),
        max_messages: file_config.max_messages,
        default_ttl_secs: file_config.default_ttl_secs,
    }
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

# LAN discovery via mDNS (automatic peer discovery on local network)
# When enabled, discovers peers via mDNS-SD and registers them as ephemeral targets.
# Requires embedded_node with http_bind to advertise our own presence.
# [lan_discovery]
# enabled = true
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
        assert!(!config.lan_discovery.enabled);
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

    #[test]
    fn test_lan_discovery_config_default() {
        let config = LanDiscoveryConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.auto_direct_known_contacts, DEFAULT_LAN_ALLOW_DIRECT);
        assert_eq!(config.max_peers, DEFAULT_LAN_MAX_PEERS);
        assert_eq!(
            config.refresh_interval_secs,
            DEFAULT_LAN_REFRESH_INTERVAL_SECS
        );
    }

    #[test]
    fn test_lan_discovery_config_enabled() {
        let toml = r"
            [lan_discovery]
            enabled = true
        ";
        let config: LanDiscoveryConfig = toml::from_str::<RawConfig>(toml)
            .unwrap()
            .lan_discovery
            .unwrap();
        assert!(config.enabled);
        // Defaults should apply for unset fields
        assert_eq!(config.auto_direct_known_contacts, DEFAULT_LAN_ALLOW_DIRECT);
        assert_eq!(config.max_peers, DEFAULT_LAN_MAX_PEERS);
        assert_eq!(
            config.refresh_interval_secs,
            DEFAULT_LAN_REFRESH_INTERVAL_SECS
        );
    }

    #[test]
    fn test_lan_discovery_config_disabled_by_default_in_toml() {
        let toml = "";
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = raw.lan_discovery.unwrap_or_default();
        assert!(!config.enabled);
    }

    #[test]
    fn test_lan_discovery_policy_fields() {
        let toml = r"
            [lan_discovery]
            enabled = true
            auto_direct_known_contacts = false
            max_peers = 64
            refresh_interval_secs = 120
        ";
        let config: LanDiscoveryConfig = toml::from_str::<RawConfig>(toml)
            .unwrap()
            .lan_discovery
            .unwrap();
        assert!(config.enabled);
        assert!(!config.auto_direct_known_contacts);
        assert_eq!(config.max_peers, 64);
        assert_eq!(config.refresh_interval_secs, 120);
    }

    #[test]
    fn test_cli_no_subcommand_defaults_to_none() {
        let cli = Cli::try_parse_from(["reme"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_cli_tui_subcommand() {
        let cli = Cli::try_parse_from(["reme", "tui"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Tui(_))));
    }

    #[test]
    fn test_cli_export_subcommand_stub() {
        let cli = Cli::try_parse_from(["reme", "export", "out.reme"]).unwrap();
        match cli.command {
            Some(Commands::Export(ref args)) => {
                assert_eq!(args.file, PathBuf::from("out.reme"));
            }
            _ => panic!("Expected Export subcommand"),
        }
    }

    #[test]
    fn test_export_args_full() {
        let cli = Cli::try_parse_from([
            "reme",
            "export",
            "--to",
            "abcd1234",
            "--force",
            "--include-sent",
            "--limit",
            "50",
            "--since",
            "24h",
            "out.reme",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Export(ref args)) => {
                assert_eq!(args.file, PathBuf::from("out.reme"));
                assert_eq!(args.to, Some("abcd1234".to_string()));
                assert!(args.force);
                assert!(args.include_sent);
                assert_eq!(args.limit, Some(50));
                assert_eq!(args.since, Some("24h".to_string()));
            }
            _ => panic!("Expected Export subcommand"),
        }
    }

    #[test]
    fn test_export_args_defaults() {
        let cli = Cli::try_parse_from(["reme", "export", "out.reme"]).unwrap();
        match cli.command {
            Some(Commands::Export(ref args)) => {
                assert_eq!(args.file, PathBuf::from("out.reme"));
                assert!(args.to.is_none());
                assert!(!args.force);
                assert!(!args.include_sent);
                assert!(args.limit.is_none());
                assert!(args.since.is_none());
            }
            _ => panic!("Expected Export subcommand"),
        }
    }

    #[test]
    fn test_cli_import_subcommand_stub() {
        let cli = Cli::try_parse_from(["reme", "import", "in.reme"]).unwrap();
        match cli.command {
            Some(Commands::Import(ref args)) => {
                assert_eq!(args.file, PathBuf::from("in.reme"));
            }
            _ => panic!("Expected Import subcommand"),
        }
    }

    #[test]
    fn test_cli_global_args_with_subcommand() {
        let cli = Cli::try_parse_from([
            "reme",
            "--data-dir",
            "/tmp/test",
            "--log-level",
            "debug",
            "tui",
        ])
        .unwrap();
        assert_eq!(cli.data_dir, Some(PathBuf::from("/tmp/test")));
        assert_eq!(cli.log_level, Some("debug".to_string()));
        assert!(matches!(cli.command, Some(Commands::Tui(_))));
    }

    #[test]
    fn test_cli_global_args_without_subcommand() {
        let cli = Cli::try_parse_from(["reme", "--data-dir", "/tmp/test"]).unwrap();
        assert_eq!(cli.data_dir, Some(PathBuf::from("/tmp/test")));
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_cli_tui_specific_args() {
        let cli = Cli::try_parse_from([
            "reme",
            "tui",
            "--http-url",
            "https://node:23003",
            "--embedded-node",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Tui(ref args)) => {
                assert_eq!(args.http_url, Some(vec!["https://node:23003".to_string()]));
                assert!(args.embedded_node);
            }
            _ => panic!("Expected Tui subcommand"),
        }
    }

    #[test]
    fn test_load_config_from_global_only() {
        let cli = Cli::try_parse_from(["reme", "--data-dir", "/tmp/reme-test"]).unwrap();
        let config = load_config_from(&cli, None).unwrap();
        assert_eq!(config.data_dir, PathBuf::from("/tmp/reme-test"));
    }

    #[test]
    fn test_load_config_from_with_tui_args() {
        let cli = Cli::try_parse_from(["reme", "tui", "--embedded-node"]).unwrap();
        let Some(Commands::Tui(ref tui_args)) = &cli.command else {
            panic!("Expected Tui")
        };
        let config = load_config_from(&cli, Some(tui_args)).unwrap();
        assert!(config.embedded_node.enabled);
    }
}
