//! Resilient Messenger Client
//!
//! A terminal-based messenger client with a Telegram/WhatsApp-style interface.
//! Uses MIK-only stateless encryption (no session establishment needed).
//!
//! ## Subcommands
//!
//! - `reme` or `reme tui` -- Launch the interactive TUI (default)
//! - `reme export <FILE>` -- Export pending messages to a .reme bundle
//! - `reme import <FILE>` -- Import messages from a .reme bundle

mod config;
mod discovery;
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
            tracing::subscriber::set_global_default(subscriber)
                .expect("setting default subscriber failed");

            tui::run(config).await
        }
        Some(Commands::Export(ref args)) => Err(format!(
            "Export not yet implemented. Would export to: {}",
            args.file.display()
        )
        .into()),
        Some(Commands::Import(ref args)) => Err(format!(
            "Import not yet implemented. Would import from: {}",
            args.file.display()
        )
        .into()),
    }
}
