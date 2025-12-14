//! Branch Messenger Client
//!
//! A terminal-based messenger client with a Telegram/WhatsApp-style interface.
//!
//! ## Configuration
//!
//! Configuration is loaded from multiple sources with the following priority
//! (highest to lowest):
//!
//! 1. **CLI arguments** - `--node-url`, `--data-dir`, etc.
//! 2. **Environment variables** - `REME_NODE_URL`, `REME_DATA_DIR`, etc.
//! 3. **Config file** - `~/.config/reme/config.toml`
//! 4. **Built-in defaults**
//!
//! See `--help` for all CLI options.
//!
//! ## Keyboard Shortcuts
//!
//! - `Tab` / `Shift+Tab` - Switch between panels
//! - `j` / `k` or Arrow keys - Navigate
//! - `Enter` - Select conversation / Send message
//! - `i` - Initialize prekeys
//! - `u` - Upload prekeys
//! - `h` - Show help
//! - `Esc` / `Ctrl+C` - Quit

mod config;
mod tui;

use crate::config::load_config;
use std::fs::{self, File};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = match load_config() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            eprintln!("Using default configuration...");
            config::AppConfig::default()
        }
    };

    // Ensure data directory exists for log file
    fs::create_dir_all(&config.data_dir)?;

    // Initialize tracing - write to file to avoid breaking TUI
    let log_level = parse_log_level(&config.log_level);
    let log_file = File::create(config.data_dir.join("client.log"))?;
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_writer(log_file)
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    // Run TUI
    tui::run(config).await
}
