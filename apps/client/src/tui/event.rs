//! Event handling for the TUI
//!
//! Provides async event handling for keyboard and tick events.

use crossterm::event::{self, Event as CrosstermEvent, KeyEvent};
use std::time::Duration;
use tokio::sync::mpsc;

/// Terminal events
#[derive(Debug, Clone)]
pub enum Event {
    /// Terminal tick (for regular updates)
    Tick,
    /// Key press event
    Key(KeyEvent),
    /// Terminal resize
    Resize(u16, u16),
}

/// Handles terminal events asynchronously
pub struct EventHandler {
    /// Event receiver
    rx: mpsc::UnboundedReceiver<Event>,
}

impl EventHandler {
    /// Create a new event handler with specified tick rate in milliseconds
    pub fn new(tick_rate: u64) -> Self {
        let tick_rate = Duration::from_millis(tick_rate);
        let (tx, rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            loop {
                // Poll for events with timeout
                if event::poll(tick_rate).unwrap_or(false) {
                    match event::read() {
                        Ok(CrosstermEvent::Key(key)) => {
                            // Only handle key press events, ignore release
                            if key.kind == crossterm::event::KeyEventKind::Press {
                                if tx.send(Event::Key(key)).is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(CrosstermEvent::Resize(w, h)) => {
                            if tx.send(Event::Resize(w, h)).is_err() {
                                break;
                            }
                        }
                        Ok(_) => {} // Ignore mouse and other events
                        Err(_) => break,
                    }
                } else {
                    // Send tick event
                    if tx.send(Event::Tick).is_err() {
                        break;
                    }
                }
            }
        });

        Self { rx }
    }

    /// Get the next event
    pub async fn next(&mut self) -> Result<Event, Box<dyn std::error::Error>> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| "Event channel closed".into())
    }
}
