//! TUI module for the messenger client
//!
//! Provides a Telegram/WhatsApp-style interface with:
//! - Conversation list on the left (1/3 width)
//! - Message view on the right (2/3 width)
//! - Input area at the bottom

mod app;
mod event;
mod password;
mod ui;

pub use app::{App, AppResult};

use crate::config::AppConfig;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use password::prompt_for_password;
use ratatui::prelude::*;
use reme_identity::{is_encrypted, load_identity, save_identity, Identity};
use std::io::{self, Write};
use std::fs;

/// Initialize and run the TUI
pub async fn run(config: AppConfig) -> AppResult<()> {
    // Ensure data directory exists
    fs::create_dir_all(&config.data_dir)?;

    // === PHASE 1: Identity setup (normal terminal mode) ===
    let identity_path = config.data_dir.join("identity.reme");
    let identity = setup_identity(&identity_path)?;

    // === PHASE 2: TUI mode ===
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and run
    let mut app = App::new(config, identity).await?;
    let res = app.run(&mut terminal).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

/// Setup identity: load existing or create new (with optional password protection)
fn setup_identity(identity_path: &std::path::Path) -> AppResult<Identity> {
    let mut stdout = io::stdout();

    if identity_path.exists() {
        // Load existing identity
        let data = fs::read(identity_path)?;
        let encrypted = is_encrypted(&data);

        if encrypted {
            // Prompt for password to decrypt
            println!();
            println!("========================================");
            println!("  Identity file is password-protected");
            println!("========================================");
            println!();
            stdout.flush()?;

            loop {
                let password = prompt_for_password("Enter password: ")?;
                match load_identity(&data, Some(password.as_bytes())) {
                    Ok(identity) => {
                        println!();
                        return Ok(identity);
                    }
                    Err(_) => {
                        println!("Wrong password. Try again (or press Ctrl+C to exit).");
                        println!();
                    }
                }
            }
        } else {
            // Plaintext identity - load directly
            let identity = load_identity(&data, None)
                .map_err(|e| format!("Failed to load identity: {}", e))?;
            Ok(identity)
        }
    } else {
        // Create new identity
        println!();
        println!("========================================");
        println!("       Creating new identity");
        println!("========================================");
        println!();
        println!("Would you like to protect your identity with a password?");
        println!("(Type password and press Enter, or just press Enter to skip)");
        println!();
        stdout.flush()?;

        let password = prompt_for_password("Password (optional): ")?;

        let identity = if password.is_empty() {
            println!();
            println!("No password set. Identity will be stored in plaintext.");
            let identity = Identity::generate();
            let data = save_identity(&identity, None)
                .map_err(|e| format!("Failed to save identity: {}", e))?;
            fs::write(identity_path, data)?;
            identity
        } else {
            // Confirm password with retry loop
            loop {
                println!();
                let confirm = prompt_for_password("Confirm password: ")?;

                if password == confirm {
                    println!();
                    println!("Password set. Identity will be encrypted.");
                    let identity = Identity::generate();
                    let data = save_identity(&identity, Some(password.as_bytes()))
                        .map_err(|e| format!("Failed to save identity: {}", e))?;
                    fs::write(identity_path, data)?;
                    break identity;
                } else {
                    println!();
                    println!("Passwords do not match. Please try again.");
                }
            }
        };

        println!();
        Ok(identity)
    }
}
