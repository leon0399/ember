//! MQTT transport target implementation.
//!
//! This module provides `MqttTarget`, a single-broker MQTT transport
//! with its own configuration, connection, and health tracking.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use reme_message::{OuterEnvelope, RoutingKey, SignedAckTombstone, WirePayload};
use rumqttc::{
    AsyncClient, Event, EventLoop, Incoming, MqttOptions, QoS, Transport as MqttTransportType,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::target::{
    HealthState, RawReceipt, TargetConfig, TargetHealth, TargetId, TargetKind, TransportTarget,
};
use crate::url_auth::{parse_url_with_auth, sanitize_url_for_logging};
use crate::TransportError;

/// Default topic prefix for REME messages.
pub const DEFAULT_TOPIC_PREFIX: &str = "reme/v1";

/// Configuration for a single MQTT target.
#[derive(Debug, Clone)]
pub struct MqttTargetConfig {
    /// Base target configuration.
    pub base: TargetConfig,

    /// Broker URL (e.g., "<mqtts://broker:8883>" or "<mqtt://broker:1883>").
    pub url: String,

    /// Client ID (auto-generated if None).
    pub client_id: Option<String>,

    /// Topic prefix (default: "reme/v1").
    pub topic_prefix: String,

    /// Authentication credentials (username, password).
    ///
    /// Takes precedence over URL-embedded credentials.
    pub auth: Option<(String, String)>,
}

impl MqttTargetConfig {
    /// Create a new MQTT target configuration.
    pub fn new(url: impl Into<String>) -> Self {
        let url = url.into();
        let id = TargetId::mqtt(&url);
        Self {
            base: TargetConfig::new(id, TargetKind::Stable),
            url,
            client_id: None,
            topic_prefix: DEFAULT_TOPIC_PREFIX.to_string(),
            auth: None,
        }
    }

    /// Set the client ID.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the topic prefix.
    pub fn with_topic_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.topic_prefix = prefix.into();
        self
    }

    /// Set authentication credentials.
    ///
    /// Takes precedence over URL-embedded credentials.
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some((username.into(), password.into()));
        self
    }

    /// Set a human-readable label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.base.label = Some(label.into());
        self
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.base.priority = priority;
        self
    }
}

/// A single MQTT broker transport target.
///
/// Each `MqttTarget` has its own:
/// - `AsyncClient` for publishing
/// - Event loop task for connection management
/// - Health tracking with circuit breaker
///
/// The event loop task is automatically stopped when the target is dropped.
pub struct MqttTarget {
    config: MqttTargetConfig,
    client: AsyncClient,
    health: TargetHealth,
    /// Cancellation token to stop the event loop task on drop.
    shutdown: CancellationToken,
}

impl MqttTarget {
    /// Create a new MQTT target and connect to the broker.
    ///
    /// This spawns an event loop task to manage the connection.
    #[allow(clippy::unused_async)] // Async for API consistency with other transports
    pub async fn connect(config: MqttTargetConfig) -> Result<Self, TransportError> {
        let parsed = parse_mqtt_url(&config.url)?;

        // Parse URL-embedded credentials
        let url_auth = parse_mqtt_url_auth(&config.url)?;

        // Generate client ID if not specified
        let client_id = config
            .client_id
            .clone()
            .unwrap_or_else(|| format!("reme-{}", uuid::Uuid::new_v4().simple()));

        let mut options = MqttOptions::new(client_id, &parsed.host, parsed.port);
        options.set_keep_alive(Duration::from_secs(30));
        options.set_clean_session(true);

        // Configure TLS if using mqtts://
        if parsed.use_tls {
            options.set_transport(MqttTransportType::tls_with_default_config());
        }

        // Apply auth with precedence: explicit config > URL-embedded
        let auth = config.auth.as_ref().or(url_auth.as_ref());
        if let Some((username, password)) = auth {
            options.set_credentials(username, password);
        }

        // Create client
        let (client, event_loop) = AsyncClient::new(options, 100);

        let health = TargetHealth::new(
            config.base.circuit_breaker_threshold,
            config.base.circuit_breaker_recovery,
        );

        let shutdown = CancellationToken::new();

        let target = Self {
            config,
            client,
            health,
            shutdown,
        };

        // Spawn event loop task
        target.spawn_event_loop(event_loop);

        Ok(target)
    }

    /// Spawn the event loop task to drive the connection.
    ///
    /// The task will run until the shutdown token is cancelled (on drop).
    fn spawn_event_loop(&self, mut event_loop: EventLoop) {
        let url = sanitize_url_for_logging(&self.config.url);
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;

                    () = shutdown.cancelled() => {
                        debug!("MQTT event loop shutting down for {}", url);
                        break;
                    }

                    result = event_loop.poll() => {
                        match result {
                            Ok(Event::Incoming(Incoming::ConnAck(_))) => {
                                debug!("MQTT connected to {}", url);
                            }
                            Ok(Event::Incoming(Incoming::PubAck(_))) => {
                                trace!("MQTT PubAck received from {}", url);
                            }
                            Ok(Event::Incoming(Incoming::Disconnect)) => {
                                warn!("MQTT disconnected from {}", url);
                            }
                            Ok(_) => {}
                            Err(e) => {
                                warn!("MQTT event loop error for {}: {}", url, e);
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                        }
                    }
                }
            }
        });
    }

    /// Get the broker URL.
    pub fn url(&self) -> &str {
        &self.config.url
    }

    /// Get the topic prefix.
    pub fn topic_prefix(&self) -> &str {
        &self.config.topic_prefix
    }

    /// Build a topic string for a routing key.
    pub fn topic_for_routing_key(&self, routing_key: &RoutingKey) -> String {
        format!(
            "{}/messages/{}",
            self.config.topic_prefix,
            hex::encode(routing_key)
        )
    }

    /// Build a topic string for a tombstone routing key.
    pub fn tombstone_topic_for_routing_key(&self, routing_key: &RoutingKey) -> String {
        format!(
            "{}/tombstones/{}",
            self.config.topic_prefix,
            hex::encode(routing_key)
        )
    }

    /// Publish a payload to this broker.
    async fn publish(&self, topic: &str, payload: &[u8]) -> Result<(), TransportError> {
        let payload_b64 = BASE64_STANDARD.encode(payload);

        self.client
            .publish(topic, QoS::AtLeastOnce, false, payload_b64.into_bytes())
            .await
            .map_err(|e| TransportError::Network(e.to_string()))
    }

    /// Get a display label for logging (sanitized to prevent credential exposure).
    fn display_label(&self) -> String {
        if let Some(ref label) = self.config.base.label {
            label.clone()
        } else {
            sanitize_url_for_logging(&self.config.url)
        }
    }
}

impl Drop for MqttTarget {
    fn drop(&mut self) {
        // Cancel the event loop task to prevent resource leaks
        self.shutdown.cancel();
    }
}

#[async_trait]
impl TransportTarget for MqttTarget {
    fn id(&self) -> &TargetId {
        &self.config.base.id
    }

    fn config(&self) -> &TargetConfig {
        &self.config.base
    }

    fn health(&self) -> HealthState {
        self.health.state()
    }

    fn is_available(&self) -> bool {
        self.health.is_available()
    }

    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<RawReceipt, TransportError> {
        let start = Instant::now();

        let topic = self.topic_for_routing_key(&envelope.routing_key);
        let wire = WirePayload::Message(envelope);
        let bytes = wire
            .encode()
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        let result = self.publish(&topic, &bytes).await;

        match &result {
            Ok(()) => {
                self.record_success(start.elapsed());
                debug!("Message published to {}", self.display_label());
            }
            Err(e) => {
                self.record_failure(e);
                warn!(
                    "Failed to publish message to {}: {}",
                    self.display_label(),
                    e
                );
            }
        }

        // MQTT doesn't return receipt data - return empty receipt
        result.map(|()| RawReceipt::default())
    }

    async fn submit_ack_tombstone(
        &self,
        tombstone: SignedAckTombstone,
    ) -> Result<(), TransportError> {
        let start = Instant::now();

        // Ack tombstones go to a broadcast topic
        let topic = format!("{}/ack-tombstones", self.topic_prefix());
        let wire = WirePayload::AckTombstone(tombstone);
        let bytes = wire
            .encode()
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        let result = self.publish(&topic, &bytes).await;

        match &result {
            Ok(()) => {
                self.record_success(start.elapsed());
                debug!("AckTombstone published to {}", self.display_label());
            }
            Err(e) => {
                self.record_failure(e);
                warn!(
                    "Failed to publish ack tombstone to {}: {}",
                    self.display_label(),
                    e
                );
            }
        }

        result
    }

    fn record_success(&self, latency: Duration) {
        self.health.record_success(latency);
    }

    fn record_failure(&self, _error: &TransportError) {
        self.health.record_failure();
    }
}

/// Parsed MQTT URL components.
pub(crate) struct ParsedMqttUrl {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) use_tls: bool,
}

/// Parse MQTT URL to extract embedded credentials.
///
/// Uses the same URL parsing logic as HTTP for consistency.
pub(crate) fn parse_mqtt_url_auth(url: &str) -> Result<Option<(String, String)>, TransportError> {
    let parsed = parse_url_with_auth(url)
        .map_err(|e| TransportError::Network(format!("Invalid MQTT URL: {e}")))?;
    Ok(parsed.auth)
}

/// Parse MQTT URL to extract credentials and sanitized URL.
///
/// Returns a tuple of (`auth`, `sanitized_url`) where `sanitized_url` has userinfo stripped.
/// This prevents DNS resolution issues when URLs contain embedded credentials.
pub(crate) fn parse_mqtt_url_with_auth(
    url: &str,
) -> Result<(Option<(String, String)>, String), TransportError> {
    let parsed = parse_url_with_auth(url)
        .map_err(|e| TransportError::Network(format!("Invalid MQTT URL: {e}")))?;
    Ok((parsed.auth, parsed.url))
}

/// Parse an MQTT URL into host, port, and TLS flag.
pub(crate) fn parse_mqtt_url(url: &str) -> Result<ParsedMqttUrl, TransportError> {
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
        if let Some(bracket_end) = rest.find(']') {
            let host = rest[1..bracket_end].to_string();
            let after_bracket = &rest[bracket_end + 1..];

            if let Some(port_str) = after_bracket.strip_prefix(':') {
                let port: u16 = port_str
                    .parse()
                    .map_err(|_| TransportError::Network(format!("Invalid port in URL: {url}")))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mqtt_target_config() {
        let config = MqttTargetConfig::new("mqtts://broker.example.com:8883");
        assert_eq!(config.url, "mqtts://broker.example.com:8883");
        assert!(config.client_id.is_none());
        assert_eq!(config.topic_prefix, DEFAULT_TOPIC_PREFIX);
    }

    #[test]
    fn test_mqtt_target_config_builder() {
        let config = MqttTargetConfig::new("mqtts://broker.example.com")
            .with_client_id("my-client")
            .with_topic_prefix("custom/v2")
            .with_label("Primary broker")
            .with_priority(150);

        assert_eq!(config.client_id, Some("my-client".to_string()));
        assert_eq!(config.topic_prefix, "custom/v2");
        assert_eq!(config.base.label, Some("Primary broker".to_string()));
        assert_eq!(config.base.priority, 150);
    }

    #[test]
    fn test_parse_mqtt_url_with_tls() {
        let result = parse_mqtt_url("mqtts://broker.example.com:8883").unwrap();
        assert_eq!(result.host, "broker.example.com");
        assert_eq!(result.port, 8883);
        assert!(result.use_tls);
    }

    #[test]
    fn test_parse_mqtt_url_without_tls() {
        let result = parse_mqtt_url("mqtt://broker.example.com:1883").unwrap();
        assert_eq!(result.host, "broker.example.com");
        assert_eq!(result.port, 1883);
        assert!(!result.use_tls);
    }

    #[test]
    fn test_parse_mqtt_url_default_port() {
        let result = parse_mqtt_url("mqtts://broker.example.com").unwrap();
        assert_eq!(result.port, 8883);

        let result = parse_mqtt_url("mqtt://broker.example.com").unwrap();
        assert_eq!(result.port, 1883);
    }

    #[test]
    fn test_parse_mqtt_url_ipv6() {
        let result = parse_mqtt_url("mqtt://[::1]:1883").unwrap();
        assert_eq!(result.host, "::1");
        assert_eq!(result.port, 1883);
        assert!(!result.use_tls);
    }

    #[test]
    fn test_parse_mqtt_url_invalid() {
        assert!(parse_mqtt_url("https://broker.example.com").is_err());
    }

    #[test]
    fn test_mqtt_target_config_with_auth() {
        let config = MqttTargetConfig::new("mqtts://broker:8883").with_auth("user", "pass");
        assert_eq!(config.auth, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_parse_mqtt_url_with_credentials() {
        let result = parse_mqtt_url_auth("mqtt://user:pass@broker:1883").unwrap();
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_parse_mqtt_url_no_credentials() {
        let result = parse_mqtt_url_auth("mqtt://broker:1883").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_mqtt_url_credentials_with_special_chars() {
        let result = parse_mqtt_url_auth("mqtt://user:p%40ss@broker:1883").unwrap();
        assert_eq!(result, Some(("user".to_string(), "p@ss".to_string())));
    }
}
