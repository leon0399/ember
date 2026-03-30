//! MQTT Bridge for bidirectional message exchange.
//!
//! The MQTT bridge enables nodes to exchange messages with MQTT brokers:
//! - Publishes messages received via HTTP to MQTT brokers
//! - Subscribes to MQTT topics and stores received messages locally
//! - Uses message ID deduplication to prevent loops in mesh topologies
//!
//! ## Authentication
//!
//! Both publishing and subscribing support username/password authentication:
//! - Configure in `node.toml` with `username` and `password` fields per broker
//! - URL-embedded credentials also supported: `mqtt://user:pass@broker:1883`
//! - Precedence: explicit config fields > URL-embedded > none
//!
//! Incomplete explicit credentials (username without password or vice versa)
//! are silently ignored for backward compatibility, falling back to URL-embedded
//! credentials if available.

use crate::config::{MqttBridgeConfig, MqttBrokerConfig};
use ember_message::OuterEnvelope;
use ember_node_core::{MailboxStore, PersistentMailboxStore};
use ember_transport::{
    url_auth::parse_url_with_auth, MqttBrokerSpec, MqttReceiverConfig, MqttTransport,
    MultiBrokerReceiver, SharedSeenCache, Transport, TransportEvent,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Errors that can occur in the MQTT bridge
#[derive(Debug, thiserror::Error)]
pub enum MqttBridgeError {
    #[error("Transport error: {0}")]
    Transport(#[from] ember_transport::TransportError),

    #[error("Store error: {0}")]
    Store(#[from] ember_node_core::NodeError),
}

/// MQTT Bridge for bidirectional HTTP <-> MQTT message exchange.
///
/// When a message is received via HTTP, call `publish()` to broadcast it
/// to all configured MQTT brokers. The bridge also runs a subscriber that
/// receives messages from MQTT and stores them locally.
pub struct MqttBridge {
    /// Transport for publishing to MQTT
    transport: MqttTransport,
    /// Topic prefix for publishing
    topic_prefix: String,
    /// Receiver configs for subscribing
    receiver_configs: Vec<MqttReceiverConfig>,
}

impl MqttBridge {
    /// Create a new MQTT bridge from configuration.
    ///
    /// Returns None if no brokers are configured.
    pub async fn new(config: &MqttBridgeConfig) -> Result<Option<Self>, MqttBridgeError> {
        if !config.is_enabled() {
            return Ok(None);
        }

        let topic_prefix = config.topic_prefix().to_string();
        let broker_specs = Self::config_to_broker_specs(&config.brokers);

        // Create transport for publishing (it has its own internal seen cache)
        let transport = MqttTransport::with_config(broker_specs, topic_prefix.clone()).await?;

        // Create receiver configs for subscribing
        let receiver_configs = Self::config_to_receiver_configs(&config.brokers, &topic_prefix);

        info!(
            "MQTT bridge configured with {} broker(s), topic prefix: {}",
            config.brokers.len(),
            topic_prefix
        );

        Ok(Some(Self {
            transport,
            topic_prefix,
            receiver_configs,
        }))
    }

    /// Convert config brokers to transport broker specs.
    fn config_to_broker_specs(brokers: &[MqttBrokerConfig]) -> Vec<MqttBrokerSpec> {
        brokers
            .iter()
            .map(|b| MqttBrokerSpec {
                url: b.url.clone(),
                client_id: b.client_id.clone(),
                auth: Self::merge_auth_credentials(
                    &b.url,
                    b.username.as_ref(),
                    b.password.as_ref(),
                ),
            })
            .collect()
    }

    /// Convert config brokers to receiver configs.
    fn config_to_receiver_configs(
        brokers: &[MqttBrokerConfig],
        topic_prefix: &str,
    ) -> Vec<MqttReceiverConfig> {
        brokers
            .iter()
            .map(|b| MqttReceiverConfig {
                url: b.url.clone(),
                client_id: b.client_id.clone(),
                topic_prefix: topic_prefix.to_string(),
                auth: Self::merge_auth_credentials(
                    &b.url,
                    b.username.as_ref(),
                    b.password.as_ref(),
                ),
            })
            .collect()
    }

    /// Merge username and password into an auth tuple with URL fallback.
    ///
    /// Precedence: explicit config fields > URL-embedded credentials > none
    ///
    /// Returns `Some((username, password))` only if both fields are non-empty strings.
    ///
    /// Note: Unlike client-side validation (which rejects incomplete credentials),
    /// this uses lenient behavior that ignores incomplete credentials for backward
    /// compatibility with existing node configurations.
    fn merge_auth_credentials(
        url: &str,
        username: Option<&String>,
        password: Option<&String>,
    ) -> Option<(String, String)> {
        // Check explicit config first
        match (username, password) {
            (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => {
                return Some((u.clone(), p.clone()));
            }
            _ => {}
        }

        // Fall back to URL-embedded credentials
        parse_url_with_auth(url).ok().and_then(|parsed| parsed.auth)
    }

    /// Get the shared seen cache for external deduplication checks.
    ///
    /// Useful when the node wants to check if a message has been seen
    /// before storing it, preventing duplicates from HTTP that were
    /// already received via MQTT.
    #[allow(dead_code)] // API for future deduplication integration
    pub const fn seen_cache(&self) -> &Arc<SharedSeenCache> {
        self.transport.seen_cache()
    }

    /// Publish a message to all MQTT brokers.
    ///
    /// This is called when a message is received via HTTP and should
    /// be broadcast to MQTT. The transport's internal seen cache prevents
    /// duplicate publishing.
    pub async fn publish(&self, envelope: &OuterEnvelope) -> Result<(), MqttBridgeError> {
        // The transport's submit_message already checks its seen cache internally
        self.transport.submit_message(envelope.clone()).await?;
        debug!(
            "Published message {:?} to MQTT (routing_key: {:?})",
            envelope.message_id, envelope.routing_key
        );
        Ok(())
    }

    /// Get the topic prefix
    #[allow(dead_code)] // API for future configuration inspection
    pub fn topic_prefix(&self) -> &str {
        &self.topic_prefix
    }

    /// Run the MQTT subscriber.
    ///
    /// This task subscribes to all messages (`{topic_prefix}/messages/#`) and
    /// stores received messages in the local store. It runs until `cancel`
    /// is triggered, the event channel closes, or an unrecoverable error occurs.
    ///
    /// Messages are deduplicated via the shared seen cache to prevent loops.
    pub async fn run_subscriber(
        &self,
        store: Arc<PersistentMailboxStore>,
        cancel: CancellationToken,
    ) -> Result<(), MqttBridgeError> {
        let (events, _handles) = self.create_subscriber().await?;
        subscriber_event_loop(store, events, cancel).await;
        Ok(())
    }

    async fn create_subscriber(
        &self,
    ) -> Result<
        (
            mpsc::UnboundedReceiver<TransportEvent>,
            Vec<ember_transport::MqttReceiverHandle>,
        ),
        MqttBridgeError,
    > {
        let receiver = MultiBrokerReceiver::with_seen_cache(
            self.receiver_configs.clone(),
            self.transport.seen_cache().clone(),
        )
        .await?;
        receiver.subscribe_all().await.map_err(Into::into)
    }

    /// Create a channel for receiving MQTT messages.
    ///
    /// Alternative to `run_subscriber()` for more control over message handling.
    /// Returns a channel that yields messages as they arrive from MQTT.
    #[allow(dead_code)] // API for future async message processing
    pub async fn subscribe_channel(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<OuterEnvelope>, MqttBridgeError> {
        let receiver = MultiBrokerReceiver::with_seen_cache(
            self.receiver_configs.clone(),
            self.transport.seen_cache().clone(),
        )
        .await?;
        let (mut events, handles) = receiver.subscribe_all().await?;

        let (tx, rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            // Keep handles alive for the duration of the event loop.
            // Dropping them would close the stop channel and terminate receivers.
            let _handles = handles;

            while let Some(event) = events.recv().await {
                match event {
                    TransportEvent::Message(envelope) => {
                        if tx.send(envelope).is_err() {
                            // Receiver dropped
                            break;
                        }
                    }
                    TransportEvent::Error(e) => {
                        // Log errors rather than silently discarding them
                        warn!("MQTT subscribe_channel error: {}", e);
                        // Continue - the receiver will handle reconnection
                    }
                }
            }
        });

        Ok(rx)
    }
}

async fn subscriber_event_loop(
    store: Arc<PersistentMailboxStore>,
    mut events: mpsc::UnboundedReceiver<TransportEvent>,
    cancel: CancellationToken,
) {
    loop {
        let event = tokio::select! {
            event = events.recv() => event,
            () = cancel.cancelled() => break,
        };
        let Some(event) = event else { break };
        handle_transport_event(&store, event);
    }
}

/// Handle a single transport event from the MQTT subscriber.
fn handle_transport_event(store: &PersistentMailboxStore, event: TransportEvent) {
    match event {
        TransportEvent::Message(envelope) => store_mqtt_message(store, envelope),
        TransportEvent::Error(e) => warn!("MQTT receiver error: {}", e),
    }
}

fn store_mqtt_message(store: &PersistentMailboxStore, envelope: ember_message::OuterEnvelope) {
    let routing_key = envelope.routing_key;
    let result = store.enqueue(routing_key, envelope);
    log_mqtt_store_result(result);
}

fn log_mqtt_store_result(result: Result<(), ember_node_core::NodeError>) {
    if let Err(e) = result {
        error!("Failed to store MQTT message: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_auth_credentials_both_present() {
        let url = "mqtt://broker:1883";
        let username = Some("user".to_string());
        let password = Some("pass".to_string());
        let result = MqttBridge::merge_auth_credentials(url, username.as_ref(), password.as_ref());
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_merge_auth_credentials_username_only() {
        let url = "mqtt://broker:1883";
        let username = Some("user".to_string());
        let password = None;
        let result = MqttBridge::merge_auth_credentials(url, username.as_ref(), password.as_ref());
        assert_eq!(result, None);
    }

    #[test]
    fn test_merge_auth_credentials_password_only() {
        let url = "mqtt://broker:1883";
        let username = None;
        let password = Some("pass".to_string());
        let result = MqttBridge::merge_auth_credentials(url, username.as_ref(), password.as_ref());
        assert_eq!(result, None);
    }

    #[test]
    fn test_merge_auth_credentials_both_none() {
        let url = "mqtt://broker:1883";
        let username: Option<String> = None;
        let password: Option<String> = None;
        let result = MqttBridge::merge_auth_credentials(url, username.as_ref(), password.as_ref());
        assert_eq!(result, None);
    }

    #[test]
    fn test_merge_auth_credentials_empty_username() {
        let url = "mqtt://broker:1883";
        let username = Some(String::new());
        let password = Some("pass".to_string());
        let result = MqttBridge::merge_auth_credentials(url, username.as_ref(), password.as_ref());
        assert_eq!(result, None);
    }

    #[test]
    fn test_merge_auth_credentials_empty_password() {
        let url = "mqtt://broker:1883";
        let username = Some("user".to_string());
        let password = Some(String::new());
        let result = MqttBridge::merge_auth_credentials(url, username.as_ref(), password.as_ref());
        assert_eq!(result, None);
    }

    #[test]
    fn test_merge_auth_credentials_both_empty() {
        let url = "mqtt://broker:1883";
        let username = Some(String::new());
        let password = Some(String::new());
        let result = MqttBridge::merge_auth_credentials(url, username.as_ref(), password.as_ref());
        assert_eq!(result, None);
    }

    #[test]
    fn test_merge_auth_credentials_url_only() {
        let url = "mqtt://url_user:url_pass@broker:1883";
        let result = MqttBridge::merge_auth_credentials(url, None, None);
        assert_eq!(
            result,
            Some(("url_user".to_string(), "url_pass".to_string()))
        );
    }

    #[test]
    fn test_merge_auth_credentials_explicit_overrides_url() {
        let url = "mqtt://url_user:url_pass@broker:1883";
        let username = Some("explicit_user".to_string());
        let password = Some("explicit_pass".to_string());
        let result = MqttBridge::merge_auth_credentials(url, username.as_ref(), password.as_ref());
        assert_eq!(
            result,
            Some(("explicit_user".to_string(), "explicit_pass".to_string()))
        );
    }

    #[test]
    fn test_merge_auth_credentials_incomplete_explicit_falls_back_to_url() {
        let url = "mqtt://url_user:url_pass@broker:1883";
        let username = Some("explicit_user".to_string());
        let password = None;
        let result = MqttBridge::merge_auth_credentials(url, username.as_ref(), password.as_ref());
        // Incomplete explicit credentials should fall back to URL
        assert_eq!(
            result,
            Some(("url_user".to_string(), "url_pass".to_string()))
        );
    }

    #[test]
    fn test_config_to_broker_specs_with_auth() {
        let brokers = vec![MqttBrokerConfig {
            url: "mqtt://broker:1883".to_string(),
            client_id: Some("test-client".to_string()),
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
        }];

        let specs = MqttBridge::config_to_broker_specs(&brokers);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].url, "mqtt://broker:1883");
        assert_eq!(specs[0].client_id, Some("test-client".to_string()));
        assert_eq!(
            specs[0].auth,
            Some(("user".to_string(), "pass".to_string()))
        );
    }

    #[test]
    fn test_config_to_broker_specs_without_auth() {
        let brokers = vec![MqttBrokerConfig {
            url: "mqtt://broker:1883".to_string(),
            client_id: Some("test-client".to_string()),
            username: None,
            password: None,
        }];

        let specs = MqttBridge::config_to_broker_specs(&brokers);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].auth, None);
    }

    #[test]
    fn test_config_to_receiver_configs_with_auth() {
        let brokers = vec![MqttBrokerConfig {
            url: "mqtt://broker:1883".to_string(),
            client_id: Some("test-client".to_string()),
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
        }];

        let configs = MqttBridge::config_to_receiver_configs(&brokers, "ember/v1");
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].url, "mqtt://broker:1883");
        assert_eq!(configs[0].client_id, Some("test-client".to_string()));
        assert_eq!(configs[0].topic_prefix, "ember/v1");
        assert_eq!(
            configs[0].auth,
            Some(("user".to_string(), "pass".to_string()))
        );
    }

    #[test]
    fn test_config_to_receiver_configs_without_auth() {
        let brokers = vec![MqttBrokerConfig {
            url: "mqtt://broker:1883".to_string(),
            client_id: Some("test-client".to_string()),
            username: None,
            password: None,
        }];

        let configs = MqttBridge::config_to_receiver_configs(&brokers, "ember/v1");
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].auth, None);
    }
}
