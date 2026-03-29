//! Event handling for the TUI
//!
//! Provides async event handling for keyboard and tick events.

use crossterm::event::{Event as CrosstermEvent, EventStream, KeyEvent, KeyEventKind};
use futures::{Stream, StreamExt};
use std::{io, time::Duration};
use tokio::sync::mpsc;

/// Terminal events
#[derive(Debug, Clone)]
pub enum Event {
    /// Terminal tick (for regular updates)
    Tick,
    /// Key press event
    Key(KeyEvent),
    /// Terminal resize (width, height) - reserved for future adaptive layouts
    #[allow(dead_code)]
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
            run_event_pump(tx, tick_rate, EventStream::new()).await;
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

async fn run_event_pump<S>(tx: mpsc::UnboundedSender<Event>, tick_rate: Duration, mut reader: S)
where
    S: Stream<Item = io::Result<CrosstermEvent>> + Unpin,
{
    loop {
        let sleep = tokio::time::sleep(tick_rate);
        tokio::pin!(sleep);

        tokio::select! {
            maybe_event = reader.next() => match maybe_event {
                Some(Ok(event)) => {
                    if !send_terminal_event(&tx, &event) {
                        break;
                    }
                }
                Some(Err(_)) | None => break,
            },
            () = &mut sleep => {
                if tx.send(Event::Tick).is_err() {
                    break;
                }
            }
        }
    }
}

fn send_terminal_event(tx: &mpsc::UnboundedSender<Event>, event: &CrosstermEvent) -> bool {
    match map_terminal_event(event) {
        Some(event) => tx.send(event).is_ok(),
        None => true,
    }
}

fn map_terminal_event(event: &CrosstermEvent) -> Option<Event> {
    match event {
        CrosstermEvent::Key(key) if key.kind == KeyEventKind::Press => Some(Event::Key(*key)),
        CrosstermEvent::FocusGained
        | CrosstermEvent::FocusLost
        | CrosstermEvent::Key(_)
        | CrosstermEvent::Mouse(_)
        | CrosstermEvent::Paste(_) => None,
        CrosstermEvent::Resize(width, height) => Some(Event::Resize(*width, *height)),
    }
}

#[cfg(test)]
mod tests {
    use super::{map_terminal_event, run_event_pump, Event};
    use crossterm::event::{
        Event as CrosstermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
    };
    use futures::stream;
    use std::{io, time::Duration};
    use tokio::sync::mpsc;

    #[test]
    fn terminal_event_maps_key_press() {
        let key = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);

        match map_terminal_event(&CrosstermEvent::Key(key)) {
            Some(Event::Key(mapped)) => assert_eq!(mapped, key),
            other => panic!("expected key event, got {other:?}"),
        }
    }

    #[test]
    fn terminal_event_ignores_key_release() {
        let key = KeyEvent::new_with_kind(
            KeyCode::Char('a'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );

        assert!(map_terminal_event(&CrosstermEvent::Key(key)).is_none());
    }

    #[test]
    fn terminal_event_maps_resize() {
        match map_terminal_event(&CrosstermEvent::Resize(80, 24)) {
            Some(Event::Resize(width, height)) => {
                assert_eq!(width, 80);
                assert_eq!(height, 24);
            }
            other => panic!("expected resize event, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pump_emits_tick_when_terminal_stream_is_idle() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let handle = tokio::spawn(run_event_pump(
            tx,
            Duration::from_millis(100),
            stream::pending::<io::Result<CrosstermEvent>>(),
        ));

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(100)).await;

        assert!(matches!(rx.recv().await, Some(Event::Tick)));

        handle.abort();
    }
}
