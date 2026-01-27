//! MQTT Bridge for bidirectional message exchange.
//!
//! The MQTT bridge enables nodes to exchange messages with MQTT brokers:
//! - Publishes messages received via HTTP to MQTT brokers
//! - Subscribes to MQTT topics and stores received messages locally
//! - Uses message ID deduplication to prevent loops in mesh topologies

use crate::config::{MqttBridgeConfig, MqttBrokerConfig};
use reme_message::OuterEnvelope;
use reme_node_core::{MailboxStore, PersistentMailboxStore};
use reme_transport::{
    MqttBrokerSpec, MqttReceiverConfig, MqttTransport, MultiBrokerReceiver, SharedSeenCache,
    Transport, TransportEvent,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Errors that can occur in the MQTT bridge
#[derive(Debug, thiserror::Error)]
pub enum MqttBridgeError {
    #[error("Transport error: {0}")]
    Transport(#[from] reme_transport::TransportError),

    #[error("Store error: {0}")]
    Store(#[from] reme_node_core::NodeError),
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
                auth: None, // Node bridge doesn't support auth yet
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
            })
            .collect()
    }

    /// Get the shared seen cache for external deduplication checks.
    ///
    /// Useful when the node wants to check if a message has been seen
    /// before storing it, preventing duplicates from HTTP that were
    /// already received via MQTT.
    #[allow(dead_code)] // API for future deduplication integration
    pub fn seen_cache(&self) -> &Arc<SharedSeenCache> {
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
    /// stores received messages in the local store. It runs until the store
    /// is dropped or an unrecoverable error occurs.
    ///
    /// Messages are deduplicated via the shared seen cache to prevent loops.
    pub async fn run_subscriber(
        &self,
        store: Arc<PersistentMailboxStore>,
    ) -> Result<(), MqttBridgeError> {
        info!(
            "Starting MQTT subscriber for {}/messages/#",
            self.topic_prefix
        );

        // Create multi-broker receiver with shared seen cache
        let receiver = MultiBrokerReceiver::with_seen_cache(
            self.receiver_configs.clone(),
            self.transport.seen_cache().clone(),
        )
        .await?;

        // Subscribe to all messages (wildcard)
        let (mut events, _handles) = receiver.subscribe_all().await?;

        info!("MQTT subscriber active, waiting for messages...");

        // Process events
        while let Some(event) = events.recv().await {
            match event {
                TransportEvent::Message(envelope) => {
                    // Seen cache is already checked by the receiver,
                    // so this message is new to us
                    debug!(
                        "Received message from MQTT: {:?} (routing_key: {:?})",
                        envelope.message_id, envelope.routing_key
                    );

                    // Store in local mailbox
                    let routing_key = envelope.routing_key;
                    if let Err(e) = store.enqueue(routing_key, envelope) {
                        error!("Failed to store MQTT message: {}", e);
                        // Continue processing other messages
                    }
                }
                TransportEvent::Error(e) => {
                    warn!("MQTT receiver error: {}", e);
                    // Continue - the receiver will handle reconnection
                }
            }
        }

        info!("MQTT subscriber event channel closed");
        Ok(())
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
