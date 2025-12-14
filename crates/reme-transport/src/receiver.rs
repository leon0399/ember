//! Push-based message receiver
//!
//! This module provides a push-based interface for receiving messages.
//! Currently implemented via HTTP polling, but the interface is designed
//! to support future transport mechanisms (WebSocket, DHT, BLE, LoRa).

use std::sync::Arc;
use std::time::Duration;

use reme_message::RoutingKey;
use tokio::sync::mpsc;
use tokio::time::{interval, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::http::HttpTransport;
use crate::{EventReceiver, EventSender, TransportEvent};

/// Configuration for the message receiver
#[derive(Debug, Clone, Copy)]
pub struct ReceiverConfig {
    /// How often to poll for new messages
    pub poll_interval: Duration,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(5),
        }
    }
}

impl ReceiverConfig {
    /// Create a config with a custom poll interval
    pub fn with_poll_interval(poll_interval: Duration) -> Self {
        Self { poll_interval }
    }
}

/// Handle to control a running message receiver
///
/// Drop this handle to stop the receiver.
pub struct ReceiverHandle {
    cancel_token: CancellationToken,
}

impl ReceiverHandle {
    /// Stop the receiver
    pub fn stop(&self) {
        self.cancel_token.cancel();
    }
}

impl Drop for ReceiverHandle {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

/// Push-based message receiver
///
/// Provides a channel-based interface for receiving messages.
/// Currently uses HTTP polling internally, but designed to support
/// future transport mechanisms.
///
/// # Example
///
/// ```ignore
/// let transport = Arc::new(HttpTransport::new("http://localhost:3000"));
/// let receiver = MessageReceiver::new(transport);
///
/// let (events, handle) = receiver.subscribe(routing_key, ReceiverConfig::default());
///
/// // Messages are pushed to the events channel
/// while let Some(event) = events.recv().await {
///     match event {
///         TransportEvent::Message(envelope) => { /* process */ }
///         TransportEvent::Error(e) => { /* handle error */ }
///     }
/// }
///
/// // Or stop explicitly
/// handle.stop();
/// ```
pub struct MessageReceiver {
    transport: Arc<HttpTransport>,
}

impl MessageReceiver {
    /// Create a new message receiver
    pub fn new(transport: Arc<HttpTransport>) -> Self {
        Self { transport }
    }

    /// Subscribe to messages for a routing key
    ///
    /// Returns:
    /// - An event receiver channel for incoming messages
    /// - A handle to control the subscription (drop to stop)
    ///
    /// Messages are automatically fetched and pushed to the channel
    /// based on the configured poll interval.
    pub fn subscribe(
        &self,
        routing_key: RoutingKey,
        config: ReceiverConfig,
    ) -> (EventReceiver, ReceiverHandle) {
        let (tx, rx) = mpsc::unbounded_channel();
        let cancel_token = CancellationToken::new();
        let handle = ReceiverHandle {
            cancel_token: cancel_token.clone(),
        };

        // Spawn the polling task
        let transport = self.transport.clone();
        tokio::spawn(polling_loop(
            transport,
            routing_key,
            config,
            tx,
            cancel_token,
        ));

        (rx, handle)
    }

    /// Subscribe with default configuration
    pub fn subscribe_default(&self, routing_key: RoutingKey) -> (EventReceiver, ReceiverHandle) {
        self.subscribe(routing_key, ReceiverConfig::default())
    }
}

/// Internal polling loop that fetches messages and sends them to the channel
async fn polling_loop(
    transport: Arc<HttpTransport>,
    routing_key: RoutingKey,
    config: ReceiverConfig,
    tx: EventSender,
    cancel_token: CancellationToken,
) {
    let mut poll_interval = interval(config.poll_interval);
    poll_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    debug!(
        "Started message polling for routing key {:?} (interval: {:?})",
        &routing_key[..4],
        config.poll_interval
    );

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                debug!("Message polling cancelled for routing key {:?}", &routing_key[..4]);
                break;
            }
            _ = poll_interval.tick() => {
                match transport.fetch_once(&routing_key).await {
                    Ok(messages) => {
                        if !messages.is_empty() {
                            debug!(
                                "Fetched {} messages for {:?}",
                                messages.len(), &routing_key[..4]
                            );
                        }

                        for envelope in messages {
                            if tx.send(TransportEvent::Message(envelope)).is_err() {
                                debug!("Channel closed, stopping polling");
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Error fetching messages: {}", e);
                        if tx.send(TransportEvent::Error(e.to_string())).is_err() {
                            debug!("Channel closed, stopping polling");
                            return;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ReceiverConfig::default();
        assert_eq!(config.poll_interval, Duration::from_secs(5));
    }

    #[test]
    fn test_custom_poll_interval() {
        let config = ReceiverConfig::with_poll_interval(Duration::from_secs(1));
        assert_eq!(config.poll_interval, Duration::from_secs(1));
    }
}
