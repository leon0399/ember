//! MQTT subscription receiver for incoming messages.
//!
//! This module provides the subscription side of MQTT transport,
//! handling incoming messages and dispatching them to event channels.

use crate::mqtt_target::{parse_mqtt_url, parse_mqtt_url_with_auth};
use crate::seen_cache::SharedSeenCache;
use crate::{TransportError, TransportEvent};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use reme_message::{OuterEnvelope, RoutingKey, WirePayload};
use rumqttc::{
    AsyncClient, Event, EventLoop, Incoming, MqttOptions, QoS, Transport as MqttTransportType,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, trace, warn};

/// Action to take after processing an MQTT event.
enum EventAction {
    /// Continue the event loop normally.
    Continue,
    /// Stop the event loop (channel closed or stop signal).
    Stop,
    /// Sleep before the next poll (connection error recovery).
    RetryDelay,
}

/// Default topic prefix for REME messages.
pub const DEFAULT_TOPIC_PREFIX: &str = "reme/v1";

/// Configuration for MQTT receiver.
///
/// Note: MQTT uses system root certificates for TLS verification.
/// Certificate pinning is not currently supported for MQTT connections.
///
/// ## Authentication
///
/// Credentials can be specified in two ways with the following precedence:
/// 1. **Explicit config field** (highest priority) - `auth`
/// 2. **URL-embedded credentials** - `mqtt://user:pass@broker:1883`
///
/// If both are provided, explicit config field takes precedence.
#[derive(Debug, Clone)]
pub struct MqttReceiverConfig {
    /// Broker URL (e.g., "<mqtts://broker:8883>")
    pub url: String,
    /// Client ID (auto-generated if None)
    pub client_id: Option<String>,
    /// Topic prefix (default: "reme/v1")
    pub topic_prefix: String,
    /// Authentication credentials (username, password)
    pub auth: Option<(String, String)>,
}

impl MqttReceiverConfig {
    /// Create a new receiver config with just a URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client_id: None,
            topic_prefix: DEFAULT_TOPIC_PREFIX.to_string(),
            auth: None,
        }
    }

    /// Set a custom client ID.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set a custom topic prefix.
    pub fn with_topic_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.topic_prefix = prefix.into();
        self
    }

    /// Set authentication credentials.
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some((username.into(), password.into()));
        self
    }

    /// Set optional authentication credentials.
    pub fn with_auth_opt(mut self, auth: Option<(String, String)>) -> Self {
        self.auth = auth;
        self
    }
}

/// Handle to stop a running MQTT receiver.
pub struct MqttReceiverHandle {
    stop_tx: mpsc::Sender<()>,
}

impl MqttReceiverHandle {
    /// Signal the receiver to stop.
    pub async fn stop(&self) {
        let _ = self.stop_tx.send(()).await;
    }
}

/// MQTT receiver for subscribing to messages.
///
/// Connects to an MQTT broker and subscribes to message topics,
/// dispatching incoming messages to event channels.
pub struct MqttReceiver {
    client: AsyncClient,
    event_loop: Mutex<EventLoop>,
    seen_cache: Arc<SharedSeenCache>,
    topic_prefix: String,
    url: String,
}

impl MqttReceiver {
    /// Create a new MQTT receiver and connect to the broker.
    pub async fn new(config: MqttReceiverConfig) -> Result<Self, TransportError> {
        Self::with_seen_cache(config, Arc::new(SharedSeenCache::with_defaults())).await
    }

    /// Create a new MQTT receiver with a shared seen cache.
    ///
    /// Use this when you want to share deduplication state with other transports.
    #[allow(clippy::unused_async)] // Async for API consistency
    pub async fn with_seen_cache(
        config: MqttReceiverConfig,
        seen_cache: Arc<SharedSeenCache>,
    ) -> Result<Self, TransportError> {
        // Extract URL-embedded credentials and sanitize URL
        let (url_auth, sanitized_url) = parse_mqtt_url_with_auth(&config.url)?;

        // Merge auth with precedence: explicit config > URL-embedded > none
        let auth = config.auth.or(url_auth);

        let parsed = parse_mqtt_url(&sanitized_url)?;

        // Generate client ID if not specified
        let client_id = config
            .client_id
            .clone()
            .unwrap_or_else(|| format!("reme-recv-{}", uuid::Uuid::new_v4().simple()));

        let mut options = MqttOptions::new(client_id, &parsed.host, parsed.port);
        options.set_keep_alive(Duration::from_secs(30));
        options.set_clean_session(true);

        // Apply authentication if credentials are provided
        if let Some((username, password)) = auth {
            options.set_credentials(username, password);
        }

        // Configure TLS if using mqtts://
        if parsed.use_tls {
            options.set_transport(MqttTransportType::tls_with_default_config());
        }

        let (client, event_loop) = AsyncClient::new(options, 100);

        Ok(Self {
            client,
            event_loop: Mutex::new(event_loop),
            seen_cache,
            topic_prefix: config.topic_prefix,
            url: config.url,
        })
    }

    /// Subscribe to all messages (wildcard) and run the event loop.
    ///
    /// Returns an event receiver and a handle to stop the receiver.
    /// This subscribes to `{topic_prefix}/messages/#` to receive all messages.
    ///
    /// # Node Usage
    /// Nodes should call this to receive messages from all routing keys.
    pub async fn subscribe_all(
        self: Arc<Self>,
    ) -> Result<(mpsc::UnboundedReceiver<TransportEvent>, MqttReceiverHandle), TransportError> {
        let topic = format!("{}/messages/#", self.topic_prefix);
        self.subscribe_and_run(topic).await
    }

    /// Subscribe to messages for a specific routing key and run the event loop.
    ///
    /// # Client Usage
    /// Clients should call this with their routing key to receive their messages.
    pub async fn subscribe_routing_key(
        self: Arc<Self>,
        routing_key: &RoutingKey,
    ) -> Result<(mpsc::UnboundedReceiver<TransportEvent>, MqttReceiverHandle), TransportError> {
        let topic = format!(
            "{}/messages/{}",
            self.topic_prefix,
            hex::encode(routing_key.as_bytes())
        );
        self.subscribe_and_run(topic).await
    }

    /// Subscribe to a topic and spawn the event loop processor.
    async fn subscribe_and_run(
        self: Arc<Self>,
        topic: String,
    ) -> Result<(mpsc::UnboundedReceiver<TransportEvent>, MqttReceiverHandle), TransportError> {
        // Subscribe to the topic
        self.client
            .subscribe(&topic, QoS::AtLeastOnce)
            .await
            .map_err(|e| TransportError::Network(format!("Failed to subscribe: {e}")))?;

        debug!("MQTT subscribed to topic: {} on {}", topic, self.url);

        // Create event channel
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);

        // Spawn event loop processor
        let receiver = self.clone();
        tokio::spawn(async move {
            receiver.run_event_loop(event_tx, &mut stop_rx).await;
        });

        Ok((event_rx, MqttReceiverHandle { stop_tx }))
    }

    /// Run the event loop, processing incoming messages.
    async fn run_event_loop(
        &self,
        event_tx: mpsc::UnboundedSender<TransportEvent>,
        stop_rx: &mut mpsc::Receiver<()>,
    ) {
        loop {
            let mut event_loop = self.event_loop.lock().await;

            tokio::select! {
                _ = stop_rx.recv() => {
                    debug!("MQTT receiver stopping");
                    break;
                }
                result = event_loop.poll() => {
                    let action = self.handle_mqtt_event(result, &event_tx);
                    match action {
                        EventAction::Continue => {}
                        EventAction::Stop => break,
                        EventAction::RetryDelay => {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            }
        }
    }

    /// Process a single MQTT event and return an action for the event loop.
    fn handle_mqtt_event(
        &self,
        result: Result<Event, rumqttc::ConnectionError>,
        event_tx: &mpsc::UnboundedSender<TransportEvent>,
    ) -> EventAction {
        match result {
            Ok(event) => self.handle_ok_event(event, event_tx),
            Err(e) => {
                error!("MQTT event loop error: {}", e);
                let _ = event_tx.send(TransportEvent::Error(e.to_string()));
                EventAction::RetryDelay
            }
        }
    }

    /// Dispatch a successfully received MQTT event.
    fn handle_ok_event(
        &self,
        event: Event,
        event_tx: &mpsc::UnboundedSender<TransportEvent>,
    ) -> EventAction {
        let Event::Incoming(incoming) = event else {
            return EventAction::Continue;
        };

        self.handle_incoming(incoming, event_tx)
    }

    /// Dispatch an incoming MQTT packet.
    fn handle_incoming(
        &self,
        incoming: Incoming,
        event_tx: &mpsc::UnboundedSender<TransportEvent>,
    ) -> EventAction {
        if let Incoming::Publish(publish) = incoming {
            return self.handle_publish(&publish, event_tx);
        }

        self.log_incoming_event(&incoming, event_tx);
        EventAction::Continue
    }

    /// Log non-publish incoming MQTT events.
    fn log_incoming_event(
        &self,
        incoming: &Incoming,
        event_tx: &mpsc::UnboundedSender<TransportEvent>,
    ) {
        match incoming {
            Incoming::ConnAck(_) => log_conn_ack(&self.url),
            Incoming::SubAck(_) => log_sub_ack(),
            Incoming::Disconnect => log_disconnect(&self.url, event_tx),
            _ => {}
        }
    }

    /// Handle a received MQTT publish message: parse, deduplicate, and forward.
    fn handle_publish(
        &self,
        publish: &rumqttc::Publish,
        event_tx: &mpsc::UnboundedSender<TransportEvent>,
    ) -> EventAction {
        trace!("MQTT received publish on topic: {}", publish.topic);

        let envelope = match self.parse_message(&publish.payload) {
            Ok(e) => e,
            Err(ref e) => return forward_parse_error(e, event_tx),
        };

        deduplicate_and_forward(envelope, &self.seen_cache, event_tx)
    }

    /// Parse a base64-encoded MQTT message payload.
    #[allow(clippy::unused_self)] // Method for future extensibility
    fn parse_message(&self, payload: &[u8]) -> Result<OuterEnvelope, TransportError> {
        // Payload is base64-encoded WirePayload
        let wire_bytes = BASE64_STANDARD
            .decode(payload)
            .map_err(|e| TransportError::Serialization(format!("Invalid base64: {e}")))?;

        let wire = WirePayload::decode(&wire_bytes)
            .map_err(|e| TransportError::Serialization(format!("Invalid wire format: {e}")))?;

        match wire {
            WirePayload::Message(envelope) => Ok(envelope),
            WirePayload::AckTombstone(_) => Err(TransportError::Serialization(
                "Expected message, got ack tombstone".to_string(),
            )),
        }
    }

    /// Get the seen cache for deduplication.
    pub const fn seen_cache(&self) -> &Arc<SharedSeenCache> {
        &self.seen_cache
    }
}

/// Log a connection acknowledgment event.
fn log_conn_ack(url: &str) {
    debug!("MQTT receiver connected to {url}");
}

/// Log a subscription acknowledgment event.
fn log_sub_ack() {
    debug!("MQTT subscription acknowledged");
}

/// Log a disconnection event and notify the event channel.
fn log_disconnect(url: &str, event_tx: &mpsc::UnboundedSender<TransportEvent>) {
    warn!("MQTT receiver disconnected from {url}");
    let _ = event_tx.send(TransportEvent::Error("MQTT disconnected".to_string()));
}

/// Check deduplication and forward envelope if novel.
fn deduplicate_and_forward(
    envelope: reme_message::OuterEnvelope,
    seen_cache: &SharedSeenCache,
    event_tx: &mpsc::UnboundedSender<TransportEvent>,
) -> EventAction {
    if !seen_cache.check_and_mark(&envelope.message_id) {
        trace!("MQTT skipping duplicate message");
        return EventAction::Continue;
    }
    forward_envelope(envelope, event_tx)
}

/// Forward a parse error to the event channel and continue.
fn forward_parse_error(
    e: &TransportError,
    event_tx: &mpsc::UnboundedSender<TransportEvent>,
) -> EventAction {
    warn!("Failed to parse MQTT message: {}", e);
    let _ = event_tx.send(TransportEvent::Error(e.to_string()));
    EventAction::Continue
}

/// Forward a parsed envelope to the event channel.
fn forward_envelope(
    envelope: reme_message::OuterEnvelope,
    event_tx: &mpsc::UnboundedSender<TransportEvent>,
) -> EventAction {
    if event_tx.send(TransportEvent::Message(envelope)).is_err() {
        debug!("MQTT event channel closed");
        return EventAction::Stop;
    }
    EventAction::Continue
}

/// Multi-broker MQTT receiver that aggregates events from multiple brokers.
pub struct MultiBrokerReceiver {
    receivers: Vec<Arc<MqttReceiver>>,
    seen_cache: Arc<SharedSeenCache>,
}

impl MultiBrokerReceiver {
    /// Create a multi-broker receiver from multiple configs.
    pub async fn new(configs: Vec<MqttReceiverConfig>) -> Result<Self, TransportError> {
        if configs.is_empty() {
            return Err(TransportError::Network(
                "No MQTT broker configs provided".to_string(),
            ));
        }

        let seen_cache = Arc::new(SharedSeenCache::with_defaults());
        let mut receivers = Vec::with_capacity(configs.len());
        let mut errors = Vec::new();

        for config in configs {
            match MqttReceiver::with_seen_cache(config.clone(), seen_cache.clone()).await {
                Ok(receiver) => receivers.push(Arc::new(receiver)),
                Err(e) => {
                    warn!("Failed to connect to MQTT broker {}: {}", config.url, e);
                    errors.push(e);
                }
            }
        }

        if receivers.is_empty() {
            return Err(TransportError::Network(format!(
                "Failed to connect to any MQTT brokers: {:?}",
                errors
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
            )));
        }

        Ok(Self {
            receivers,
            seen_cache,
        })
    }

    /// Create a multi-broker receiver with a shared seen cache.
    ///
    /// Use this when you want to share deduplication state with other components
    /// (e.g., an `MqttTransport` that publishes to the same brokers).
    pub async fn with_seen_cache(
        configs: Vec<MqttReceiverConfig>,
        seen_cache: Arc<SharedSeenCache>,
    ) -> Result<Self, TransportError> {
        if configs.is_empty() {
            return Err(TransportError::Network(
                "No MQTT broker configs provided".to_string(),
            ));
        }

        let mut receivers = Vec::with_capacity(configs.len());
        let mut errors = Vec::new();

        for config in configs {
            match MqttReceiver::with_seen_cache(config.clone(), seen_cache.clone()).await {
                Ok(receiver) => receivers.push(Arc::new(receiver)),
                Err(e) => {
                    warn!("Failed to connect to MQTT broker {}: {}", config.url, e);
                    errors.push(e);
                }
            }
        }

        if receivers.is_empty() {
            return Err(TransportError::Network(format!(
                "Failed to connect to any MQTT brokers: {:?}",
                errors
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
            )));
        }

        Ok(Self {
            receivers,
            seen_cache,
        })
    }

    /// Subscribe to all messages on all brokers.
    ///
    /// Returns a single event receiver that aggregates events from all brokers.
    pub async fn subscribe_all(
        self,
    ) -> Result<
        (
            mpsc::UnboundedReceiver<TransportEvent>,
            Vec<MqttReceiverHandle>,
        ),
        TransportError,
    > {
        let (merged_tx, merged_rx) = mpsc::unbounded_channel();
        let mut handles = Vec::with_capacity(self.receivers.len());

        for receiver in self.receivers {
            let (rx, handle) = receiver.subscribe_all().await?;
            handles.push(handle);

            // Spawn a task to forward events to the merged channel
            let tx = merged_tx.clone();
            tokio::spawn(async move {
                let mut rx = rx;
                while let Some(event) = rx.recv().await {
                    if tx.send(event).is_err() {
                        break;
                    }
                }
            });
        }

        Ok((merged_rx, handles))
    }

    /// Subscribe to a specific routing key on all brokers.
    pub async fn subscribe_routing_key(
        self,
        routing_key: &RoutingKey,
    ) -> Result<
        (
            mpsc::UnboundedReceiver<TransportEvent>,
            Vec<MqttReceiverHandle>,
        ),
        TransportError,
    > {
        let (merged_tx, merged_rx) = mpsc::unbounded_channel();
        let mut handles = Vec::with_capacity(self.receivers.len());

        for receiver in self.receivers {
            let (rx, handle) = receiver.subscribe_routing_key(routing_key).await?;
            handles.push(handle);

            let tx = merged_tx.clone();
            tokio::spawn(async move {
                let mut rx = rx;
                while let Some(event) = rx.recv().await {
                    if tx.send(event).is_err() {
                        break;
                    }
                }
            });
        }

        Ok((merged_rx, handles))
    }

    /// Get the shared seen cache.
    pub const fn seen_cache(&self) -> &Arc<SharedSeenCache> {
        &self.seen_cache
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receiver_config() {
        let config = MqttReceiverConfig::new("mqtts://broker.example.com:8883")
            .with_client_id("my-receiver")
            .with_topic_prefix("custom/v1");

        assert_eq!(config.url, "mqtts://broker.example.com:8883");
        assert_eq!(config.client_id, Some("my-receiver".to_string()));
        assert_eq!(config.topic_prefix, "custom/v1");
    }

    #[test]
    fn test_parse_url_with_tls() {
        let result = parse_mqtt_url("mqtts://broker.example.com:8883").unwrap();
        assert_eq!(result.host, "broker.example.com");
        assert_eq!(result.port, 8883);
        assert!(result.use_tls);
    }

    #[test]
    fn test_parse_url_default_port() {
        let result = parse_mqtt_url("mqtts://broker.example.com").unwrap();
        assert_eq!(result.port, 8883);

        let result = parse_mqtt_url("mqtt://broker.example.com").unwrap();
        assert_eq!(result.port, 1883);
    }
}
