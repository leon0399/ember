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
//! - `REME_NODE_URLS` - Comma-separated list of node URLs
//! - `REME_DATA_DIR` - Directory for storing identity, keys, and messages
//! - `REME_LOG_LEVEL` - Log level (trace, debug, info, warn, error)
//! - `REME_NUM_PREKEYS` - Number of one-time prekeys to generate
//!
//! ## Config File
//!
//! Default location: `~/.config/reme/config.toml` (Linux/macOS) or
//! `%APPDATA%\reme\config.toml` (Windows)
//!
//! ```toml
//! # Single node (backward compatible)
//! node_url = "http://localhost:23003"
//!
//! # OR multiple nodes for redundancy
//! node_urls = [
//!     "http://localhost:23003",
//!     "http://localhost:23004",
//! ]
//!
//! data_dir = "~/.local/share/reme"
//! log_level = "info"
//! num_prekeys = 10
//! ```

use clap::Parser;
use config::{Config, Environment, File, FileFormat};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// CLI arguments for the client
#[derive(Parser, Debug, Clone, Serialize)]
#[command(name = "reme-client")]
#[command(author, version, about = "Branch Messenger Client")]
pub struct CliArgs {
    /// URLs of the mailbox nodes (comma-separated for multiple nodes)
    ///
    /// Example: -n http://node1:23003,http://node2:23003
    #[arg(short = 'n', long, env = "REME_NODE_URLS", value_delimiter = ',')]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_urls: Option<Vec<String>>,

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

    /// Number of one-time prekeys to generate
    #[arg(long, env = "REME_NUM_PREKEYS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_prekeys: Option<u32>,
}

/// Final resolved configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    /// URLs of the mailbox nodes
    #[serde(default = "default_node_urls")]
    pub node_urls: Vec<String>,

    /// Directory for storing identity, keys, and messages
    pub data_dir: PathBuf,

    /// Log level
    pub log_level: String,

    /// Number of one-time prekeys to generate
    pub num_prekeys: u32,
}

fn default_node_urls() -> Vec<String> {
    vec!["http://localhost:23003".to_string()]
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            node_urls: default_node_urls(),
            data_dir: default_data_dir(),
            log_level: "info".to_string(),
            num_prekeys: 10,
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

/// Intermediate config for deserializing node URLs from file/env
/// Supports both `node_url` (single, backward compat) and `node_urls` (multiple)
#[derive(Debug, Clone, Deserialize, Default)]
struct RawConfig {
    /// Single node URL (backward compatible)
    node_url: Option<String>,
    /// Multiple node URLs
    node_urls: Option<Vec<String>>,
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
        .set_default("log_level", defaults.log_level)?
        .set_default("num_prekeys", defaults.num_prekeys as i64)?;

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
    if let Some(num_prekeys) = cli.num_prekeys {
        builder = builder.set_override("num_prekeys", num_prekeys as i64)?;
    }

    let config = builder.build()?;

    // Get other config values first (before consuming config)
    let data_dir_str: String = config.get("data_dir").unwrap_or_else(|_| {
        defaults.data_dir.to_string_lossy().to_string()
    });
    let log_level: String = config.get("log_level").unwrap_or_else(|_| "info".to_string());
    let num_prekeys: u32 = config
        .get::<i64>("num_prekeys")
        .map(|v| v as u32)
        .unwrap_or(defaults.num_prekeys);

    // Deserialize raw config to handle node_url vs node_urls
    let raw: RawConfig = config.try_deserialize().unwrap_or_default();

    // Resolve node URLs with priority:
    // 1. CLI --node-urls (multiple)
    // 2. Config file node_urls (array)
    // 3. Config file node_url (single, backward compat)
    // 4. Default
    let node_urls = if let Some(urls) = cli.node_urls {
        urls
    } else if let Some(urls) = raw.node_urls {
        urls
    } else if let Some(url) = raw.node_url {
        vec![url]
    } else {
        defaults.node_urls
    };

    // Expand ~ in data_dir path
    let data_dir = expand_tilde(&data_dir_str);

    Ok(AppConfig {
        node_urls,
        data_dir,
        log_level,
        num_prekeys,
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
        r#"# Branch Messenger Client Configuration
#
# This file is loaded from:
#   Linux/macOS: ~/.config/reme/config.toml
#   Windows: %APPDATA%\reme\config.toml
#
# All settings can be overridden by:
#   1. Environment variables (REME_NODE_URLS, REME_DATA_DIR, etc.)
#   2. CLI arguments (--node-urls, --data-dir, etc.)

# URLs of the mailbox nodes
# For redundancy, you can specify multiple nodes:
# node_urls = [
#     "http://node1.example.com:23003",
#     "http://node2.example.com:23003",
# ]
node_urls = ["{}"]

# Directory for storing identity, keys, and messages
# Use ~ for home directory
data_dir = "{}"

# Log level: trace, debug, info, warn, error
log_level = "{}"

# Number of one-time prekeys to generate
num_prekeys = {}
"#,
        defaults.node_urls[0],
        defaults.data_dir.to_string_lossy(),
        defaults.log_level,
        defaults.num_prekeys
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.node_urls, vec!["http://localhost:23003"]);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.num_prekeys, 10);
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
        assert!(toml.contains("node_urls"));
        assert!(toml.contains("data_dir"));
        assert!(toml.contains("log_level"));
        assert!(toml.contains("num_prekeys"));
    }

    #[test]
    fn test_default_node_urls() {
        let urls = default_node_urls();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "http://localhost:23003");
    }
}
