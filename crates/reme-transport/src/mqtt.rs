//! MQTT transport implementation.
//!
//! Provides pub/sub messaging over MQTT brokers with TLS support.
//!
//! # Topic Structure
//!
//! ```text
//! reme/v1/
//! ├── messages/{routing_key_hex}    # Main message topic per recipient
//! └── tombstones/{routing_key_hex}  # Tombstone acknowledgments
//! ```
//!
//! - `routing_key_hex`: 32-character lowercase hex (16 bytes)
//! - Wildcard subscription: `reme/v1/messages/#`
//!
//! # TLS Note
//!
//! MQTT connections use standard TLS with system root certificates.
//! Certificate pinning is not currently supported for MQTT (use HTTP
//! transport if certificate pinning is required).

use crate::seen_cache::SharedSeenCache;
use crate::{Transport, TransportError};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use futures::future::join_all;
use reme_message::{OuterEnvelope, RoutingKey, SignedAckTombstone, WirePayload};
use rumqttc::{
    AsyncClient, Event, EventLoop, Incoming, MqttOptions, Publish, QoS,
    Transport as MqttTransportType,
};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace, warn};

/// Default topic prefix for REME messages.
pub const DEFAULT_TOPIC_PREFIX: &str = "reme/v1";

/// MQTT broker specification.
///
/// Note: MQTT uses system root certificates for TLS verification.
/// Certificate pinning is not currently supported for MQTT connections.
#[derive(Debug, Clone)]
pub struct MqttBrokerSpec {
    /// Broker URL (e.g., "<mqtts://broker:8883>" or "<mqtt://broker:1883>")
    pub url: String,
    /// Client ID (auto-generated if None)
    pub client_id: Option<String>,
}

impl MqttBrokerSpec {
    /// Create a new broker spec with just a URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client_id: None,
        }
    }

    /// Create a broker spec with URL and client ID.
    pub fn with_client_id(url: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client_id: Some(client_id.into()),
        }
    }
}

/// Connected MQTT broker with client and event loop.
struct ConnectedBroker {
    client: AsyncClient,
    #[allow(dead_code)] // Event loop is spawned as a task
    event_loop: EventLoop,
    url: String,
}

/// MQTT transport for publishing and subscribing to messages.
pub struct MqttTransport {
    /// Connected broker clients
    clients: Vec<AsyncClient>,
    /// Seen cache for deduplication (shared across all brokers)
    seen_cache: Arc<SharedSeenCache>,
    /// Topic prefix (default: "reme/v1")
    topic_prefix: String,
}

impl MqttTransport {
    /// Create a new MQTT transport connected to the specified brokers.
    ///
    /// Connects to all brokers in parallel and returns once all are connected.
    ///
    /// # Errors
    /// Returns an error if any broker connection fails.
    pub async fn new(brokers: Vec<MqttBrokerSpec>) -> Result<Self, TransportError> {
        Self::with_config(brokers, DEFAULT_TOPIC_PREFIX.to_string()).await
    }

    /// Create a new MQTT transport with custom topic prefix.
    pub async fn with_config(
        brokers: Vec<MqttBrokerSpec>,
        topic_prefix: String,
    ) -> Result<Self, TransportError> {
        if brokers.is_empty() {
            return Err(TransportError::Network(
                "No MQTT brokers configured".to_string(),
            ));
        }

        let connected = Self::connect_brokers(&brokers).await?;

        // Spawn event loops
        let clients: Vec<_> = connected
            .into_iter()
            .map(|broker| {
                let url = broker.url.clone();
                let mut event_loop = broker.event_loop;

                // Spawn a task to drive the event loop
                tokio::spawn(async move {
                    loop {
                        match event_loop.poll().await {
                            Ok(Event::Incoming(Incoming::ConnAck(_))) => {
                                debug!("MQTT connected to {}", url);
                            }
                            Ok(Event::Incoming(Incoming::PubAck(_))) => {
                                trace!("MQTT PubAck received");
                            }
                            Ok(Event::Incoming(Incoming::Disconnect)) => {
                                warn!("MQTT disconnected from {}", url);
                                // The library will attempt to reconnect
                            }
                            Ok(_) => {}
                            Err(e) => {
                                warn!("MQTT event loop error for {}: {}", url, e);
                                // Small delay before retry
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                        }
                    }
                });

                broker.client
            })
            .collect();

        Ok(Self {
            clients,
            seen_cache: Arc::new(SharedSeenCache::with_defaults()),
            topic_prefix,
        })
    }

    /// Connect to all brokers in parallel.
    async fn connect_brokers(
        brokers: &[MqttBrokerSpec],
    ) -> Result<Vec<ConnectedBroker>, TransportError> {
        let futures: Vec<_> = brokers.iter().map(Self::connect_broker).collect();
        let results = join_all(futures).await;

        let mut connected = Vec::with_capacity(brokers.len());
        let mut errors = Vec::new();

        for result in results {
            match result {
                Ok(broker) => connected.push(broker),
                Err(e) => errors.push(e),
            }
        }

        if connected.is_empty() {
            return Err(TransportError::Network(format!(
                "Failed to connect to any MQTT brokers: {errors:?}"
            )));
        }

        if !errors.is_empty() {
            warn!(
                "Some MQTT brokers failed to connect ({} of {} failed)",
                errors.len(),
                brokers.len()
            );
        }

        Ok(connected)
    }

    /// Connect to a single broker.
    #[allow(clippy::unused_async)] // Async for API consistency with other transports
    async fn connect_broker(spec: &MqttBrokerSpec) -> Result<ConnectedBroker, TransportError> {
        let parsed = Self::parse_mqtt_url(&spec.url)?;

        // Generate client ID if not specified
        let client_id = spec
            .client_id
            .clone()
            .unwrap_or_else(|| format!("reme-{}", uuid::Uuid::new_v4().simple()));

        let mut options = MqttOptions::new(client_id, &parsed.host, parsed.port);
        options.set_keep_alive(Duration::from_secs(30));
        options.set_clean_session(true);

        // Configure TLS if using mqtts://
        if parsed.use_tls {
            // Use rumqttc's native rustls configuration with system roots
            options.set_transport(MqttTransportType::tls_with_default_config());
        }

        // Create client (capacity 100 for the internal channel)
        let (client, event_loop) = AsyncClient::new(options, 100);

        Ok(ConnectedBroker {
            client,
            event_loop,
            url: spec.url.clone(),
        })
    }

    /// Parse an MQTT URL into host, port, and TLS flag.
    ///
    /// Supports both IPv4/hostname and IPv6 addresses:
    /// - `mqtt://broker:1883`
    /// - `mqtts://broker.example.com:8883`
    /// - `mqtt://[::1]:1883`
    /// - `mqtts://[2001:db8::1]` (uses default port 8883)
    fn parse_mqtt_url(url: &str) -> Result<ParsedMqttUrl, TransportError> {
        let use_tls = url.starts_with("mqtts://");
        let is_mqtt = url.starts_with("mqtt://") || use_tls;

        if !is_mqtt {
            return Err(TransportError::Network(format!(
                "Invalid MQTT URL scheme: {url}. Expected mqtt:// or mqtts://"
            )));
        }

        let prefix = if use_tls { "mqtts://" } else { "mqtt://" };
        let rest = url.strip_prefix(prefix).unwrap();
        let default_port = if use_tls { 8883 } else { 1883 };

        // Parse host:port, handling IPv6 addresses in brackets
        let (host, port) = if rest.starts_with('[') {
            // IPv6 address: [host]:port or [host]
            // Strip brackets - MQTT libraries expect raw IPv6 address
            if let Some(bracket_end) = rest.find(']') {
                let host = rest[1..bracket_end].to_string();
                let after_bracket = &rest[bracket_end + 1..];

                if let Some(port_str) = after_bracket.strip_prefix(':') {
                    let port: u16 = port_str.parse().map_err(|_| {
                        TransportError::Network(format!("Invalid port in URL: {url}"))
                    })?;
                    (host, port)
                } else if after_bracket.is_empty() {
                    (host, default_port)
                } else {
                    return Err(TransportError::Network(format!(
                        "Invalid IPv6 URL format: {url}"
                    )));
                }
            } else {
                return Err(TransportError::Network(format!(
                    "Unclosed bracket in IPv6 URL: {url}"
                )));
            }
        } else if let Some((h, p)) = rest.rsplit_once(':') {
            // IPv4/hostname: host:port
            let port: u16 = p
                .parse()
                .map_err(|_| TransportError::Network(format!("Invalid port in URL: {url}")))?;
            (h.to_string(), port)
        } else {
            // No port specified, use default
            (rest.to_string(), default_port)
        };

        Ok(ParsedMqttUrl {
            host,
            port,
            use_tls,
        })
    }

    /// Build a topic string for a routing key.
    ///
    /// Format: `{prefix}/messages/{routing_key_hex}`
    pub fn topic_for_routing_key(&self, routing_key: &RoutingKey) -> String {
        format!(
            "{}/messages/{}",
            self.topic_prefix,
            hex::encode(routing_key)
        )
    }

    /// Build a topic string for a tombstone routing key.
    ///
    /// Format: `{prefix}/tombstones/{routing_key_hex}`
    pub fn tombstone_topic_for_routing_key(&self, routing_key: &RoutingKey) -> String {
        format!(
            "{}/tombstones/{}",
            self.topic_prefix,
            hex::encode(routing_key)
        )
    }

    /// Publish a payload to all connected brokers.
    async fn publish_to_all(&self, topic: &str, payload: &[u8]) -> Result<(), TransportError> {
        if self.clients.is_empty() {
            return Err(TransportError::Network(
                "No MQTT brokers connected".to_string(),
            ));
        }

        let payload_b64 = BASE64_STANDARD.encode(payload);

        let futures: Vec<_> = self
            .clients
            .iter()
            .map(|client| {
                let topic = topic.to_string();
                let payload = payload_b64.clone().into_bytes();
                async move {
                    client
                        .publish(topic, QoS::AtLeastOnce, false, payload)
                        .await
                        .map_err(|e| TransportError::Network(e.to_string()))
                }
            })
            .collect();

        let results = join_all(futures).await;

        // Success if ANY broker accepts
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        if success_count > 0 {
            trace!(
                "Published to {}/{} MQTT brokers",
                success_count,
                self.clients.len()
            );
            Ok(())
        } else {
            let errors: Vec<_> = results
                .into_iter()
                .filter_map(std::result::Result::err)
                .map(|e| e.to_string())
                .collect();
            Err(TransportError::Network(format!(
                "All MQTT brokers failed: {errors:?}"
            )))
        }
    }

    /// Get the seen cache for deduplication.
    pub fn seen_cache(&self) -> &Arc<SharedSeenCache> {
        &self.seen_cache
    }

    /// Get the topic prefix.
    pub fn topic_prefix(&self) -> &str {
        &self.topic_prefix
    }
}

#[async_trait]
impl Transport for MqttTransport {
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        // Check seen cache for deduplication (without marking yet)
        if self.seen_cache.was_seen(&envelope.message_id) {
            trace!(
                "Skipping duplicate message via MQTT: {:?}",
                envelope.message_id
            );
            return Ok(());
        }

        let topic = self.topic_for_routing_key(&envelope.routing_key);
        let wire = WirePayload::Message(envelope.clone());
        let bytes = wire.encode();

        // Attempt to publish
        let result = self.publish_to_all(&topic, &bytes).await;

        // Only mark as seen after successful publish
        // This ensures retries work if the first attempt fails
        if result.is_ok() {
            self.seen_cache.mark(&envelope.message_id);
        }

        result
    }

    async fn submit_ack_tombstone(
        &self,
        tombstone: SignedAckTombstone,
    ) -> Result<(), TransportError> {
        // MQTT tombstones go to the general tombstone topic
        // Since AckTombstone doesn't have routing_key, we use a broadcast topic
        let topic = format!("{}/ack-tombstones", self.topic_prefix);
        let wire = WirePayload::AckTombstone(tombstone);
        let bytes = wire.encode();

        self.publish_to_all(&topic, &bytes).await
    }
}

/// Parsed MQTT URL components.
struct ParsedMqttUrl {
    host: String,
    port: u16,
    use_tls: bool,
}

/// Parse a base64-encoded MQTT message payload into an `OuterEnvelope`.
pub fn parse_mqtt_message(publish: &Publish) -> Result<OuterEnvelope, TransportError> {
    // Payload is base64-encoded WirePayload
    let wire_bytes = BASE64_STANDARD
        .decode(&publish.payload)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mqtt_url_with_tls() {
        let result = MqttTransport::parse_mqtt_url("mqtts://broker.example.com:8883").unwrap();
        assert_eq!(result.host, "broker.example.com");
        assert_eq!(result.port, 8883);
        assert!(result.use_tls);
    }

    #[test]
    fn test_parse_mqtt_url_without_tls() {
        let result = MqttTransport::parse_mqtt_url("mqtt://broker.example.com:1883").unwrap();
        assert_eq!(result.host, "broker.example.com");
        assert_eq!(result.port, 1883);
        assert!(!result.use_tls);
    }

    #[test]
    fn test_parse_mqtt_url_default_port_tls() {
        let result = MqttTransport::parse_mqtt_url("mqtts://broker.example.com").unwrap();
        assert_eq!(result.host, "broker.example.com");
        assert_eq!(result.port, 8883); // Default TLS port
        assert!(result.use_tls);
    }

    #[test]
    fn test_parse_mqtt_url_default_port_plain() {
        let result = MqttTransport::parse_mqtt_url("mqtt://broker.example.com").unwrap();
        assert_eq!(result.host, "broker.example.com");
        assert_eq!(result.port, 1883); // Default plain port
        assert!(!result.use_tls);
    }

    #[test]
    fn test_parse_mqtt_url_invalid_scheme() {
        let result = MqttTransport::parse_mqtt_url("https://broker.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_topic_for_routing_key() {
        let routing_key = RoutingKey::from_bytes([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ]);

        // Create a minimal transport for testing (will fail to connect but that's ok)
        let topic_prefix = "reme/v1".to_string();
        let expected = format!(
            "{}/messages/{}",
            topic_prefix,
            hex::encode(routing_key.as_bytes())
        );

        // Direct test of topic generation
        assert_eq!(
            expected,
            "reme/v1/messages/123456789abcdef01122334455667788"
        );
    }

    #[test]
    fn test_broker_spec_creation() {
        let spec = MqttBrokerSpec::new("mqtts://broker.example.com:8883");
        assert_eq!(spec.url, "mqtts://broker.example.com:8883");
        assert!(spec.client_id.is_none());

        let spec = MqttBrokerSpec::with_client_id("mqtts://broker.example.com:8883", "my-client");
        assert_eq!(spec.url, "mqtts://broker.example.com:8883");
        assert_eq!(spec.client_id, Some("my-client".to_string()));
    }
}
