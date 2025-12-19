//! Push-based message receiver
//!
//! This module provides a push-based interface for receiving messages.
//! Currently implemented via HTTP polling, but the interface is designed
//! to support future transport mechanisms (WebSocket, DHT, BLE, LoRa).

use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use reme_message::RoutingKey;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::http::HttpTransport;
use crate::{EventReceiver, EventSender, TransportEvent};

/// Configuration for the message receiver
#[derive(Debug, Clone, Copy)]
pub struct ReceiverConfig {
    /// How often to poll for new messages
    pub poll_interval: Duration,
    /// Whether to apply jitter to polling intervals
    ///
    /// When enabled, uses "equal jitter" strategy:
    /// - actual_delay = poll_interval/2 + random(0, poll_interval/2)
    /// - Result: delay between 50% and 100% of poll_interval
    ///
    /// This helps reduce load spikes and avoid thundering herd problems
    /// when multiple clients poll simultaneously.
    pub enable_jitter: bool,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(5),
            enable_jitter: false,
        }
    }
}

impl ReceiverConfig {
    /// Create a config with a custom poll interval
    pub fn with_poll_interval(poll_interval: Duration) -> Self {
        Self {
            poll_interval,
            enable_jitter: false,
        }
    }

    /// Create a config with jitter enabled
    pub fn with_jitter(poll_interval: Duration) -> Self {
        Self {
            poll_interval,
            enable_jitter: true,
        }
    }

    /// Enable or disable jitter on an existing config
    pub fn set_jitter(mut self, enable: bool) -> Self {
        self.enable_jitter = enable;
        self
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
    debug!(
        "Started message polling for routing key {:?} (interval: {:?}, jitter: {})",
        &routing_key[..4],
        config.poll_interval,
        config.enable_jitter
    );

    if config.enable_jitter {
        polling_loop_with_jitter(transport, routing_key, config, tx, cancel_token).await;
    } else {
        polling_loop_fixed(transport, routing_key, config, tx, cancel_token).await;
    }
}

/// Polling loop with fixed interval (no jitter)
async fn polling_loop_fixed(
    transport: Arc<HttpTransport>,
    routing_key: RoutingKey,
    config: ReceiverConfig,
    tx: EventSender,
    cancel_token: CancellationToken,
) {
    let mut poll_interval = interval(config.poll_interval);
    poll_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                debug!("Message polling cancelled for routing key {:?}", &routing_key[..4]);
                break;
            }
            _ = poll_interval.tick() => {
                fetch_and_send(&transport, &routing_key, &tx).await;
            }
        }
    }
}

/// Polling loop with jitter applied
///
/// Uses "equal jitter" strategy: delay = base/2 + random(0, base/2)
/// This provides delays between 50% and 100% of the base interval.
async fn polling_loop_with_jitter(
    transport: Arc<HttpTransport>,
    routing_key: RoutingKey,
    config: ReceiverConfig,
    tx: EventSender,
    cancel_token: CancellationToken,
) {
    let base_millis = config.poll_interval.as_millis() as u64;
    let half_base = base_millis / 2;

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                debug!("Message polling cancelled for routing key {:?}", &routing_key[..4]);
                break;
            }
            else => {
                fetch_and_send(&transport, &routing_key, &tx).await;

                // Calculate next delay with jitter: half_base + random(0, half_base)
                let jitter_millis = rand::rng().random_range(0..=half_base);
                let delay_millis = half_base + jitter_millis;
                let delay = Duration::from_millis(delay_millis);

                // Wait for the jittered delay or cancellation
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        debug!("Message polling cancelled for routing key {:?}", &routing_key[..4]);
                        break;
                    }
                    _ = sleep(delay) => {
                        // Continue to next iteration
                    }
                }
            }
        }
    }
}

/// Fetch messages and send them to the channel
async fn fetch_and_send(
    transport: &Arc<HttpTransport>,
    routing_key: &RoutingKey,
    tx: &EventSender,
) {
    match transport.fetch_once(routing_key).await {
        Ok(messages) => {
            if !messages.is_empty() {
                debug!(
                    "Fetched {} messages for {:?}",
                    messages.len(),
                    &routing_key[..4]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ReceiverConfig::default();
        assert_eq!(config.poll_interval, Duration::from_secs(5));
        assert_eq!(config.enable_jitter, false);
    }

    #[test]
    fn test_custom_poll_interval() {
        let config = ReceiverConfig::with_poll_interval(Duration::from_secs(1));
        assert_eq!(config.poll_interval, Duration::from_secs(1));
        assert_eq!(config.enable_jitter, false);
    }

    #[test]
    fn test_with_jitter() {
        let config = ReceiverConfig::with_jitter(Duration::from_secs(10));
        assert_eq!(config.poll_interval, Duration::from_secs(10));
        assert_eq!(config.enable_jitter, true);
    }

    #[test]
    fn test_set_jitter() {
        let config = ReceiverConfig::default()
            .set_jitter(true);
        assert_eq!(config.enable_jitter, true);

        let config = ReceiverConfig::with_jitter(Duration::from_secs(5))
            .set_jitter(false);
        assert_eq!(config.enable_jitter, false);
    }
}
