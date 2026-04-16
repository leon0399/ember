//! TUI module for the messenger client
//!
//! Provides a Telegram/WhatsApp-style interface with:
//! - Conversation list on the left (1/3 width)
//! - Message view on the right (2/3 width)
//! - Input area at the bottom

mod app;
mod commands;
pub mod conversation_list;
mod event;
pub mod http_server;
mod ui;

pub use app::{App, AppResult};

use crate::config::AppConfig;
use crossterm::{
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen,
        LeaveAlternateScreen,
    },
};
use ratatui::prelude::*;
use std::fs;
use std::io;

/// Initialize and run the TUI
pub async fn run(config: AppConfig) -> AppResult<()> {
    // Ensure data directory exists
    fs::create_dir_all(&config.data_dir)?;

    // === PHASE 1: Identity setup (normal terminal mode) ===
    let identity_path = config.data_dir.join("identity.ember");
    let identity = crate::identity::load_or_create(&identity_path)?;

    // === PHASE 2: TUI mode ===
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    // Enter alternate screen and explicitly clear it to remove any artifacts
    execute!(stdout, EnterAlternateScreen, Clear(ClearType::All))?;
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
