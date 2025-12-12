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
//! - `REME_NODE_URL` - URL of the mailbox node
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
//! node_url = "http://localhost:23003"
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
#[command(author, version, about = "Branch Messenger CLI Client")]
pub struct CliArgs {
    /// URL of the mailbox node
    #[arg(short = 'n', long, env = "REME_NODE_URL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_url: Option<String>,

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
    /// URL of the mailbox node
    pub node_url: String,

    /// Directory for storing identity, keys, and messages
    pub data_dir: PathBuf,

    /// Log level
    pub log_level: String,

    /// Number of one-time prekeys to generate
    pub num_prekeys: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            node_url: "http://localhost:23003".to_string(),
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
        .set_default("node_url", defaults.node_url)?
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
    if let Some(ref node_url) = cli.node_url {
        builder = builder.set_override("node_url", node_url.clone())?;
    }
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

    // Deserialize into AppConfig, handling PathBuf specially
    let node_url: String = config.get("node_url")?;
    let data_dir_str: String = config.get("data_dir")?;
    let log_level: String = config.get("log_level")?;
    let num_prekeys: u32 = config.get::<i64>("num_prekeys")? as u32;

    // Expand ~ in data_dir path
    let data_dir = expand_tilde(&data_dir_str);

    Ok(AppConfig {
        node_url,
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
#   1. Environment variables (REME_NODE_URL, REME_DATA_DIR, etc.)
#   2. CLI arguments (--node-url, --data-dir, etc.)

# URL of the mailbox node
node_url = "{}"

# Directory for storing identity, keys, and messages
# Use ~ for home directory
data_dir = "{}"

# Log level: trace, debug, info, warn, error
log_level = "{}"

# Number of one-time prekeys to generate
num_prekeys = {}
"#,
        defaults.node_url,
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
        assert_eq!(config.node_url, "http://localhost:23003");
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
        assert!(toml.contains("node_url"));
        assert!(toml.contains("data_dir"));
        assert!(toml.contains("log_level"));
        assert!(toml.contains("num_prekeys"));
    }
}
