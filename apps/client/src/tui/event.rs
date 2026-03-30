//! Event handling for the TUI
//!
//! Provides async event handling for terminal input and resize events.

use crossterm::event::{Event as CrosstermEvent, EventStream, KeyEvent, KeyEventKind};
use futures::{Stream, StreamExt};
use std::io;
use tokio::sync::mpsc;

/// Terminal events
#[derive(Debug, Clone)]
pub enum Event {
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
    /// Create a new event handler for terminal input and resize notifications.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            run_event_pump(tx, EventStream::new()).await;
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

async fn run_event_pump<S>(tx: mpsc::UnboundedSender<Event>, mut reader: S)
where
    S: Stream<Item = io::Result<CrosstermEvent>> + Unpin,
{
    loop {
        let closed = tx.clone();

        tokio::select! {
            next_event = reader.next() => match next_event {
                Some(Ok(event)) => {
                    if !send_terminal_event(&tx, &event) {
                        break;
                    }
                }
                Some(Err(_)) | None => break,
            },
            () = closed.closed() => break,
        }
    }
}

fn send_terminal_event(tx: &mpsc::UnboundedSender<Event>, event: &CrosstermEvent) -> bool {
    match map_terminal_event(event) {
        Some(event) => tx.send(event).is_ok(),
        None => !tx.is_closed(),
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
    use super::{map_terminal_event, run_event_pump, send_terminal_event, Event};
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

    #[test]
    fn ignored_event_stops_when_channel_is_closed() {
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx);

        assert!(!send_terminal_event(&tx, &CrosstermEvent::FocusGained));
    }

    #[tokio::test]
    async fn pump_forwards_resize_events() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let handle = tokio::spawn(run_event_pump(
            tx,
            stream::iter([Ok(CrosstermEvent::Resize(80, 24))]),
        ));

        assert!(matches!(rx.recv().await, Some(Event::Resize(80, 24))));

        handle.abort();
    }

    #[tokio::test]
    async fn pump_exits_when_receiver_is_dropped_while_idle() {
        let (tx, rx) = mpsc::unbounded_channel();
        let handle = tokio::spawn(run_event_pump(
            tx,
            stream::pending::<io::Result<CrosstermEvent>>(),
        ));

        drop(rx);

        tokio::time::timeout(Duration::from_millis(100), handle)
            .await
            .expect("event pump should exit after the receiver drops")
            .expect("event pump task should not panic");
    }
}
