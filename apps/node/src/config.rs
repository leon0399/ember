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
//! - `REME_NODE_STORAGE_PATH` - Path to SQLite database file (`:memory:` for in-memory)
//!
//! ## Config File
//!
//! Default location: `~/.config/reme/node.toml` (Linux/macOS) or
//! `%APPDATA%\reme\node.toml` (Windows)
//!
//! ```toml
//! bind_addr = "0.0.0.0:23003"
//! max_messages = 1000
//! default_ttl = 604800
//! log_level = "info"
//! storage_path = "/var/lib/reme/mailbox.db"  # Optional: enables persistent storage
//! ```

use crate::cleanup::CleanupConfig;
use clap::Parser;
use config::{Config, Environment, File, FileFormat};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// CLI arguments for the node
#[derive(Parser, Debug, Clone)]
#[command(name = "reme-node")]
#[command(author, version, about = "Branch Messenger Mailbox Node")]
pub struct CliArgs {
    /// Address to bind HTTP server (e.g., "0.0.0.0:23003")
    #[arg(short = 'b', long, env = "REME_NODE_BIND_ADDR")]
    pub bind_addr: Option<String>,

    /// Port to bind (shorthand for bind_addr with 0.0.0.0)
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

    /// Path to SQLite database file (default: :memory:)
    /// Use ":memory:" for in-memory storage, or a file path for persistence
    #[arg(long, env = "REME_NODE_STORAGE_PATH")]
    pub storage_path: Option<String>,

    /// Username for HTTP Basic Auth (optional)
    /// If set along with auth_password, incoming requests must authenticate
    #[arg(long, env = "REME_NODE_AUTH_USERNAME")]
    pub auth_username: Option<String>,

    /// Password for HTTP Basic Auth (optional)
    /// If set along with auth_username, incoming requests must authenticate
    #[arg(long, env = "REME_NODE_AUTH_PASSWORD")]
    pub auth_password: Option<String>,
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

    /// Peer node URLs for replication
    #[serde(default)]
    pub peers: Vec<String>,

    /// Cleanup task configuration
    #[serde(default)]
    pub cleanup: CleanupConfig,

    /// Path to SQLite database file (default: :memory:)
    /// Use ":memory:" for in-memory storage, or a file path for persistence
    #[serde(default)]
    pub storage_path: Option<String>,

    /// Username for HTTP Basic Auth (optional)
    #[serde(default)]
    pub auth_username: Option<String>,

    /// Password for HTTP Basic Auth (optional)
    #[serde(default)]
    pub auth_password: Option<String>,
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
            peers: Vec::new(),
            cleanup: CleanupConfig::default(),
            storage_path: None, // None means :memory:
            auth_username: None,
            auth_password: None,
        }
    }
}

/// Get the default config file path based on platform conventions
fn default_config_path() -> Option<PathBuf> {
    ProjectDirs::from("com", "branch", "reme").map(|dirs| dirs.config_dir().join("node.toml"))
}

/// Load configuration from all sources with proper layering
///
/// Priority (highest to lowest):
/// 1. CLI arguments
/// 2. Environment variables (REME_NODE_*)
/// 3. Config file
/// 4. Built-in defaults
pub fn load_config() -> Result<NodeConfig, config::ConfigError> {
    let cli = CliArgs::parse();

    // Start with defaults
    let defaults = NodeConfig::default();

    let mut builder = Config::builder()
        // Layer 1: Built-in defaults (lowest priority)
        .set_default("bind_addr", defaults.bind_addr.clone())?
        .set_default("max_messages", defaults.max_messages as i64)?
        .set_default("default_ttl", defaults.default_ttl as i64)?
        .set_default("log_level", defaults.log_level.clone())?
        .set_default("node_id", defaults.node_id.clone())?
        .set_default::<_, Vec<String>>("peers", defaults.peers.clone())?
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
        builder = builder.set_override("bind_addr", format!("0.0.0.0:{}", port))?;
    }
    if let Some(max_messages) = cli.max_messages {
        builder = builder.set_override("max_messages", max_messages as i64)?;
    }
    if let Some(default_ttl) = cli.default_ttl {
        builder = builder.set_override("default_ttl", default_ttl as i64)?;
    }
    if let Some(ref log_level) = cli.log_level {
        builder = builder.set_override("log_level", log_level.clone())?;
    }
    if let Some(ref node_id) = cli.node_id {
        builder = builder.set_override("node_id", node_id.clone())?;
    }
    if let Some(ref peers) = cli.peers {
        builder = builder.set_override("peers", peers.clone())?;
    }
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

    // Extract values
    let bind_addr: String = config.get("bind_addr").unwrap_or(defaults.bind_addr);
    let max_messages: usize = config
        .get::<i64>("max_messages")
        .map(|v| v as usize)
        .unwrap_or(defaults.max_messages);
    let default_ttl: u32 = config
        .get::<i64>("default_ttl")
        .map(|v| v as u32)
        .unwrap_or(defaults.default_ttl);
    let log_level: String = config.get("log_level").unwrap_or(defaults.log_level);
    let node_id: String = config.get("node_id").unwrap_or(defaults.node_id);
    let peers: Vec<String> = config
        .get::<Vec<String>>("peers")
        .unwrap_or(defaults.peers);

    // Extract cleanup config
    let cleanup = CleanupConfig {
        enabled: config
            .get::<bool>("cleanup.enabled")
            .unwrap_or(defaults.cleanup.enabled),
        interval_secs: config
            .get::<i64>("cleanup.interval_secs")
            .map(|v| v as u64)
            .unwrap_or(defaults.cleanup.interval_secs),
        tombstone_delay_secs: config
            .get::<i64>("cleanup.tombstone_delay_secs")
            .map(|v| v as u64)
            .unwrap_or(defaults.cleanup.tombstone_delay_secs),
        orphan_delay_secs: config
            .get::<i64>("cleanup.orphan_delay_secs")
            .map(|v| v as u64)
            .unwrap_or(defaults.cleanup.orphan_delay_secs),
        rate_limit_delay_secs: config
            .get::<i64>("cleanup.rate_limit_delay_secs")
            .map(|v| v as u64)
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
        assert_eq!(config.default_ttl, 604800); // 7 days
        assert_eq!(config.log_level, "info");
        assert!(!config.node_id.is_empty());
        assert!(config.peers.is_empty());
    }
}
