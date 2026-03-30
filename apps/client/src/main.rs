#![allow(clippy::print_stdout, clippy::print_stderr)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! Resilient Messenger Client
//!
//! A terminal-based messenger client with a Telegram/WhatsApp-style interface.
//! Uses MIK-only stateless encryption (no session establishment needed).
//!
//! ## Subcommands
//!
//! - `ember` or `ember tui` -- Launch the interactive TUI (default)
//! - `ember export <FILE>` -- Export pending messages to a .ember bundle
//! - `ember import <FILE>` -- Import messages from a .ember bundle

mod config;
mod discovery;
mod export;
mod identity;
mod import;
mod tui;

use crate::config::{load_config_from, Cli, Commands};
use clap::Parser;
use std::fs::{self, File};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let config = load_config_from(&cli, cli.tui_args()).unwrap_or_else(|e| {
        eprintln!("Failed to load configuration: {e}");
        eprintln!("Using default configuration...");
        config::AppConfig::default()
    });

    match cli.command {
        None | Some(Commands::Tui(_)) => {
            fs::create_dir_all(&config.data_dir)?;
            let env_filter = EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&config.log_level));
            let log_file = File::create(config.data_dir.join("client.log"))?;
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_writer(log_file)
                .with_ansi(false)
                .finish();
            if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
                eprintln!("Warning: failed to set tracing subscriber: {e}");
            }

            tui::run(config).await
        }
        Some(Commands::Export(ref args)) => export::run_export(&config, args),
        Some(Commands::Import(ref args)) => import::run_import(&config, args),
    }
}
