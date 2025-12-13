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
//! ```

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
        .set_default::<_, Vec<String>>("peers", defaults.peers.clone())?;

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

    Ok(NodeConfig {
        bind_addr,
        max_messages,
        default_ttl,
        log_level,
        node_id,
        peers,
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
