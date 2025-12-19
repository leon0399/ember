//! Multi-layered configuration system for the client
//!
//! Configuration is loaded from multiple sources with the following priority
//! (highest to lowest):
//!
//! 1. **CLI arguments** - Explicit user input (highest priority)
//! 2. **Environment variables** - Prefixed with `REME_`
//! 3. **Config file** - TOML file at `~/.config/reme/config.toml` or custom path
//! 4. **Built-in defaults** - Hardcoded fallback values (lowest priority)
//!
//! ## Environment Variables
//!
//! All environment variables are prefixed with `REME_` and use `_` as separator:
//! - `REME_HTTP` - JSON array of HTTP endpoint configs: `[{"url":"...", "cert_pin":"..."}]`
//! - `REME_MQTT` - JSON array of MQTT broker configs: `[{"url":"...", "cert_pin":"..."}]`
//! - `REME_DATA_DIR` - Directory for storing identity, keys, and messages
//! - `REME_LOG_LEVEL` - Log level (trace, debug, info, warn, error)
//!
//! ## Config File
//!
//! Default location: `~/.config/reme/config.toml` (Linux/macOS) or
//! `%APPDATA%\reme\config.toml` (Windows)
//!
//! ```toml
//! # HTTP endpoint configuration with optional certificate pinning
//! [[http]]
//! url = "https://node1.example.com:23003"
//! cert_pin = "spki//sha256/AAAA..."  # Optional
//!
//! [[http]]
//! url = "https://node2.example.com:23003"
//! # No pin - will connect but warn
//!
//! # MQTT broker configuration (optional)
//! [[mqtt]]
//! url = "mqtts://broker.example.com:8883"
//! cert_pin = "spki//sha256/BBBB..."  # Optional
//!
//! data_dir = "~/.local/share/reme"
//! log_level = "info"
//! ```

use clap::Parser;
use config::{Config, Environment, File, FileFormat};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
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

    /// MQTT broker URLs (pair with --mqtt-cert-pin by order)
    ///
    /// Example: --mqtt-url mqtts://broker1:8883,mqtts://broker2:8883
    #[arg(long, value_delimiter = ',')]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mqtt_url: Option<Vec<String>>,

    /// Certificate pins for MQTT brokers (pair with --mqtt-url by order)
    ///
    /// Format: spki//sha256/<base64> or cert//sha256/<base64>
    #[arg(long, value_delimiter = ',')]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mqtt_cert_pin: Option<Vec<String>>,

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
}

/// Outbox configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OutboxAppConfig {
    /// How often to check for pending retries (seconds)
    #[serde(default = "default_outbox_tick_interval")]
    pub tick_interval_secs: u64,

    /// Default message TTL in days (0 = never expire)
    #[serde(default = "default_outbox_ttl_days")]
    pub ttl_days: u64,

    /// How long a "sent" attempt stays in-flight before timing out (seconds)
    #[serde(default = "default_outbox_attempt_timeout")]
    pub attempt_timeout_secs: u64,

    /// Initial retry delay (seconds)
    #[serde(default = "default_outbox_retry_initial_delay")]
    pub retry_initial_delay_secs: u64,

    /// Maximum retry delay (seconds)
    #[serde(default = "default_outbox_retry_max_delay")]
    pub retry_max_delay_secs: u64,
}

fn default_outbox_tick_interval() -> u64 { 5 }
fn default_outbox_ttl_days() -> u64 { 7 }
fn default_outbox_attempt_timeout() -> u64 { 60 }
fn default_outbox_retry_initial_delay() -> u64 { 5 }
fn default_outbox_retry_max_delay() -> u64 { 300 }

impl Default for OutboxAppConfig {
    fn default() -> Self {
        Self {
            tick_interval_secs: default_outbox_tick_interval(),
            ttl_days: default_outbox_ttl_days(),
            attempt_timeout_secs: default_outbox_attempt_timeout(),
            retry_initial_delay_secs: default_outbox_retry_initial_delay(),
            retry_max_delay_secs: default_outbox_retry_max_delay(),
        }
    }
}

/// HTTP endpoint configuration with optional certificate pinning
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct HttpEndpoint {
    /// Endpoint URL (http:// or https://)
    pub url: String,
    /// Optional certificate pin for TLS verification
    ///
    /// Format: `spki//sha256/<base64>` or `cert//sha256/<base64>`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_pin: Option<String>,
}

impl HttpEndpoint {
    /// Create a new HTTP endpoint with just a URL (no pinning)
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            cert_pin: None,
        }
    }

    /// Create a new HTTP endpoint with URL and certificate pin
    pub fn with_pin(url: impl Into<String>, cert_pin: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            cert_pin: Some(cert_pin.into()),
        }
    }
}

/// MQTT broker configuration with optional certificate pinning
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct MqttBroker {
    /// Broker URL (mqtt:// or mqtts://)
    pub url: String,
    /// Optional certificate pin for TLS verification
    ///
    /// Format: `spki//sha256/<base64>` or `cert//sha256/<base64>`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_pin: Option<String>,
    /// Optional custom client ID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

impl MqttBroker {
    /// Create a new MQTT broker with just a URL (no pinning)
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            cert_pin: None,
            client_id: None,
        }
    }

    /// Create a new MQTT broker with URL and certificate pin
    pub fn with_pin(url: impl Into<String>, cert_pin: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            cert_pin: Some(cert_pin.into()),
            client_id: None,
        }
    }
}

/// Final resolved configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    /// HTTP endpoint configurations with optional certificate pinning
    #[serde(default = "default_http")]
    pub http: Vec<HttpEndpoint>,

    /// MQTT broker configurations with optional certificate pinning
    #[serde(default)]
    pub mqtt: Vec<MqttBroker>,

    /// Directory for storing identity, keys, and messages
    pub data_dir: PathBuf,

    /// Log level
    pub log_level: String,

    /// Outbox configuration
    #[serde(default)]
    pub outbox: OutboxAppConfig,
}

fn default_http() -> Vec<HttpEndpoint> {
    vec![HttpEndpoint::new("http://localhost:23003")]
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            http: default_http(),
            mqtt: Vec::new(),
            data_dir: default_data_dir(),
            log_level: "info".to_string(),
            outbox: OutboxAppConfig::default(),
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
    /// HTTP endpoint configurations (new format)
    http: Option<Vec<HttpEndpoint>>,
    /// MQTT broker configurations
    mqtt: Option<Vec<MqttBroker>>,
    /// Outbox config section
    #[serde(default)]
    outbox: RawOutboxConfig,
}

/// Parse HTTP endpoints from REME_HTTP environment variable (JSON format)
fn parse_http_from_env() -> Option<Vec<HttpEndpoint>> {
    let json = std::env::var("REME_HTTP").ok()?;
    match serde_json::from_str(&json) {
        Ok(endpoints) => Some(endpoints),
        Err(e) => {
            warn!(
                "Failed to parse REME_HTTP as JSON: {} - falling back to config file or defaults",
                e
            );
            None
        }
    }
}

/// Parse MQTT brokers from REME_MQTT environment variable (JSON format)
fn parse_mqtt_from_env() -> Option<Vec<MqttBroker>> {
    let json = std::env::var("REME_MQTT").ok()?;
    match serde_json::from_str(&json) {
        Ok(brokers) => Some(brokers),
        Err(e) => {
            warn!(
                "Failed to parse REME_MQTT as JSON: {} - falling back to config file or defaults",
                e
            );
            None
        }
    }
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

/// Load configuration from all sources with proper layering
///
/// Priority (highest to lowest):
/// 1. CLI arguments
/// 2. Environment variables (REME_*)
/// 3. Config file
/// 4. Built-in defaults
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
    let data_dir_str: String = config.get("data_dir").unwrap_or_else(|_| {
        defaults.data_dir.to_string_lossy().to_string()
    });
    let log_level: String = config.get("log_level").unwrap_or_else(|_| "info".to_string());

    // Deserialize raw config for file-based settings
    let raw: RawConfig = config.try_deserialize().unwrap_or_default();

    // Resolve HTTP endpoints with priority:
    // 1. CLI --http-url and --http-cert-pin (paired by order)
    // 2. REME_HTTP environment variable (JSON format)
    // 3. Config file [[http]] array
    // 4. Default
    let http = if let Some(urls) = cli.http_url {
        // Pair URLs with pins by order
        let pins = cli.http_cert_pin.unwrap_or_default();

        // Warn if counts don't match
        if !pins.is_empty() && pins.len() != urls.len() {
            warn!(
                "Mismatched --http-url ({}) and --http-cert-pin ({}) counts - some endpoints may be unpinned",
                urls.len(),
                pins.len()
            );
        }

        urls.into_iter()
            .enumerate()
            .map(|(i, url)| HttpEndpoint {
                url,
                cert_pin: pins.get(i).cloned(),
            })
            .collect()
    } else if let Some(env_http) = parse_http_from_env() {
        env_http
    } else if let Some(file_http) = raw.http {
        file_http
    } else {
        defaults.http
    };

    // Resolve MQTT brokers with priority:
    // 1. CLI --mqtt-url and --mqtt-cert-pin (paired by order)
    // 2. REME_MQTT environment variable (JSON format)
    // 3. Config file [[mqtt]] array
    // 4. Default (empty)
    let mqtt = if let Some(urls) = cli.mqtt_url {
        // Pair URLs with pins by order
        let pins = cli.mqtt_cert_pin.unwrap_or_default();

        // Warn if counts don't match
        if !pins.is_empty() && pins.len() != urls.len() {
            warn!(
                "Mismatched --mqtt-url ({}) and --mqtt-cert-pin ({}) counts - some brokers may be unpinned",
                urls.len(),
                pins.len()
            );
        }

        urls.into_iter()
            .enumerate()
            .map(|(i, url)| MqttBroker {
                url,
                cert_pin: pins.get(i).cloned(),
                client_id: None,
            })
            .collect()
    } else if let Some(env_mqtt) = parse_mqtt_from_env() {
        env_mqtt
    } else if let Some(file_mqtt) = raw.mqtt {
        file_mqtt
    } else {
        Vec::new() // MQTT is optional
    };

    // Expand ~ in data_dir path
    let data_dir = expand_tilde(&data_dir_str);

    // Build outbox config with priority: CLI > config file > defaults
    let outbox_defaults = OutboxAppConfig::default();
    let outbox = OutboxAppConfig {
        tick_interval_secs: cli.outbox_tick_interval
            .or(raw.outbox.tick_interval_secs)
            .unwrap_or(outbox_defaults.tick_interval_secs),
        ttl_days: cli.outbox_ttl_days
            .or(raw.outbox.ttl_days)
            .unwrap_or(outbox_defaults.ttl_days),
        attempt_timeout_secs: cli.outbox_attempt_timeout
            .or(raw.outbox.attempt_timeout_secs)
            .unwrap_or(outbox_defaults.attempt_timeout_secs),
        retry_initial_delay_secs: cli.outbox_retry_initial_delay
            .or(raw.outbox.retry_initial_delay_secs)
            .unwrap_or(outbox_defaults.retry_initial_delay_secs),
        retry_max_delay_secs: cli.outbox_retry_max_delay
            .or(raw.outbox.retry_max_delay_secs)
            .unwrap_or(outbox_defaults.retry_max_delay_secs),
    };

    Ok(AppConfig {
        http,
        mqtt,
        data_dir,
        log_level,
        outbox,
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
pub fn default_config_toml() -> String {
    let defaults = AppConfig::default();
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
url = "{}"

# MQTT broker configuration (optional)
# Messages can be exchanged via MQTT in addition to or instead of HTTP.
#
# [[mqtt]]
# url = "mqtts://broker.example.com:8883"
# cert_pin = "spki//sha256/CCCC..."  # Optional
# client_id = "my-client"            # Optional, auto-generated if not set

# Directory for storing identity, keys, and messages
# Use ~ for home directory
data_dir = "{}"

# Log level: trace, debug, info, warn, error
log_level = "{}"

# Outbox configuration for message delivery tracking and retries
[outbox]
# How often to check for pending retries (seconds)
tick_interval_secs = {}

# Message TTL in days (0 = never expire)
ttl_days = {}

# How long a "sent" attempt stays in-flight before timing out (seconds)
attempt_timeout_secs = {}

# Retry backoff settings
retry_initial_delay_secs = {}
retry_max_delay_secs = {}
"#,
        defaults.http[0].url,
        defaults.data_dir.to_string_lossy(),
        defaults.log_level,
        defaults.outbox.tick_interval_secs,
        defaults.outbox.ttl_days,
        defaults.outbox.attempt_timeout_secs,
        defaults.outbox.retry_initial_delay_secs,
        defaults.outbox.retry_max_delay_secs,
    )
}

/// Parse log level from string
pub(crate) fn parse_log_level(level: &str) -> Level {
    match level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" | "warning" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.http.len(), 1);
        assert_eq!(config.http[0].url, "http://localhost:23003");
        assert_eq!(config.http[0].cert_pin, None);
        assert!(config.mqtt.is_empty());
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
    }

    #[test]
    fn test_default_http() {
        let endpoints = default_http();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].url, "http://localhost:23003");
        assert_eq!(endpoints[0].cert_pin, None);
    }

    #[test]
    fn test_http_endpoint_constructors() {
        let endpoint = HttpEndpoint::new("https://example.com");
        assert_eq!(endpoint.url, "https://example.com");
        assert_eq!(endpoint.cert_pin, None);

        let endpoint = HttpEndpoint::with_pin("https://example.com", "spki//sha256/abc=");
        assert_eq!(endpoint.url, "https://example.com");
        assert_eq!(endpoint.cert_pin, Some("spki//sha256/abc=".to_string()));
    }

    #[test]
    fn test_mqtt_broker_constructors() {
        let broker = MqttBroker::new("mqtts://example.com:8883");
        assert_eq!(broker.url, "mqtts://example.com:8883");
        assert_eq!(broker.cert_pin, None);
        assert_eq!(broker.client_id, None);

        let broker = MqttBroker::with_pin("mqtts://example.com:8883", "spki//sha256/abc=");
        assert_eq!(broker.url, "mqtts://example.com:8883");
        assert_eq!(broker.cert_pin, Some("spki//sha256/abc=".to_string()));
    }

    #[test]
    fn test_http_endpoint_deserialize() {
        let json = r#"{"url":"https://example.com","cert_pin":"spki//sha256/test="}"#;
        let endpoint: HttpEndpoint = serde_json::from_str(json).unwrap();
        assert_eq!(endpoint.url, "https://example.com");
        assert_eq!(endpoint.cert_pin, Some("spki//sha256/test=".to_string()));

        // Without cert_pin
        let json = r#"{"url":"https://example.com"}"#;
        let endpoint: HttpEndpoint = serde_json::from_str(json).unwrap();
        assert_eq!(endpoint.url, "https://example.com");
        assert_eq!(endpoint.cert_pin, None);
    }

    #[test]
    fn test_mqtt_broker_deserialize() {
        let json = r#"{"url":"mqtts://example.com:8883","cert_pin":"spki//sha256/test=","client_id":"my-client"}"#;
        let broker: MqttBroker = serde_json::from_str(json).unwrap();
        assert_eq!(broker.url, "mqtts://example.com:8883");
        assert_eq!(broker.cert_pin, Some("spki//sha256/test=".to_string()));
        assert_eq!(broker.client_id, Some("my-client".to_string()));

        // Without optional fields
        let json = r#"{"url":"mqtts://example.com:8883"}"#;
        let broker: MqttBroker = serde_json::from_str(json).unwrap();
        assert_eq!(broker.url, "mqtts://example.com:8883");
        assert_eq!(broker.cert_pin, None);
        assert_eq!(broker.client_id, None);
    }

    #[test]
    fn test_parse_http_from_env_json() {
        std::env::set_var(
            "REME_HTTP",
            r#"[{"url":"https://node1.example.com","cert_pin":"spki//sha256/abc="},{"url":"https://node2.example.com"}]"#,
        );
        let endpoints = parse_http_from_env().expect("Should parse JSON");
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].url, "https://node1.example.com");
        assert_eq!(endpoints[0].cert_pin, Some("spki//sha256/abc=".to_string()));
        assert_eq!(endpoints[1].url, "https://node2.example.com");
        assert_eq!(endpoints[1].cert_pin, None);
        std::env::remove_var("REME_HTTP");
    }

    #[test]
    fn test_parse_mqtt_from_env_json() {
        std::env::set_var(
            "REME_MQTT",
            r#"[{"url":"mqtts://broker.example.com:8883","cert_pin":"spki//sha256/def="}]"#,
        );
        let brokers = parse_mqtt_from_env().expect("Should parse JSON");
        assert_eq!(brokers.len(), 1);
        assert_eq!(brokers[0].url, "mqtts://broker.example.com:8883");
        assert_eq!(brokers[0].cert_pin, Some("spki//sha256/def=".to_string()));
        std::env::remove_var("REME_MQTT");
    }
}
