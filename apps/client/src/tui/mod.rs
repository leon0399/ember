//! TUI module for the messenger client
//!
//! Provides a Telegram/WhatsApp-style interface with:
//! - Conversation list on the left (1/3 width)
//! - Message view on the right (2/3 width)
//! - Input area at the bottom

mod app;
mod event;
mod ui;

pub use app::{App, AppResult};

use crate::config::AppConfig;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use std::io;

/// Initialize and run the TUI
pub async fn run(config: AppConfig) -> AppResult<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and run
    let mut app = App::new(config).await?;
    let res = app.run(&mut terminal).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}
