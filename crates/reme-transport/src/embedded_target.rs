//! Embedded node transport target implementation.
//!
//! This module provides `EmbeddedTarget`, a transport target that wraps an
//! in-process embedded node for direct local message delivery.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use reme_message::{OuterEnvelope, SignedAckTombstone};
use reme_node_core::{EmbeddedNodeHandle, NodeError};
use tracing::debug;

use crate::target::{
    HealthState, RawReceipt, TargetConfig, TargetHealth, TargetId, TargetKind, TransportTarget,
};
use crate::TransportError;

/// Configuration for an embedded node target.
#[derive(Debug, Clone)]
pub struct EmbeddedTargetConfig {
    /// Base target configuration.
    pub base: TargetConfig,
}

impl Default for EmbeddedTargetConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl EmbeddedTargetConfig {
    /// Create a new embedded target configuration.
    ///
    /// Uses `TargetKind::Ephemeral` since the embedded node is local and
    /// should be preferred over remote targets when available.
    pub fn new() -> Self {
        let id = TargetId::embedded();
        Self {
            base: TargetConfig::new(id, TargetKind::Ephemeral).with_label("Embedded Node"),
        }
    }

    /// Set the priority.
    pub const fn with_priority(mut self, priority: u8) -> Self {
        self.base.priority = priority;
        self
    }

    /// Set a custom label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.base.label = Some(label.into());
        self
    }
}

/// An embedded node transport target.
///
/// This target wraps an `EmbeddedNodeHandle` and provides the `TransportTarget`
/// interface for integration with the transport coordinator.
///
/// The embedded target:
/// - Has the highest priority by default (ephemeral targets are preferred)
/// - Has minimal latency (in-process communication)
/// - Is always considered healthy while the node is running
pub struct EmbeddedTarget {
    config: EmbeddedTargetConfig,
    handle: EmbeddedNodeHandle,
    health: TargetHealth,
}

impl EmbeddedTarget {
    /// Create a new embedded target wrapping the given node handle.
    pub fn new(handle: EmbeddedNodeHandle) -> Self {
        Self::with_config(handle, EmbeddedTargetConfig::default())
    }

    /// Create a new embedded target with custom configuration.
    pub const fn with_config(handle: EmbeddedNodeHandle, config: EmbeddedTargetConfig) -> Self {
        let health = TargetHealth::new(
            config.base.circuit_breaker_threshold,
            config.base.circuit_breaker_recovery,
        );

        Self {
            config,
            handle,
            health,
        }
    }

    /// Get the underlying node handle.
    pub const fn handle(&self) -> &EmbeddedNodeHandle {
        &self.handle
    }

    /// Check if the embedded node is still running.
    pub fn is_node_running(&self) -> bool {
        self.handle.is_running()
    }

    /// Get a display label for logging.
    fn display_label(&self) -> &str {
        self.config.base.label.as_deref().unwrap_or("Embedded Node")
    }
}

/// Convert `NodeError` to `TransportError`.
fn convert_error(error: NodeError) -> TransportError {
    match error {
        NodeError::ChannelClosed => TransportError::ChannelClosed,
        NodeError::Serialization(msg) => TransportError::Serialization(msg),
        NodeError::Deserialization(msg) => {
            TransportError::Serialization(format!("deserialization: {msg}"))
        }
        NodeError::Database(e) => TransportError::ServerError(format!("database error: {e}")),
        NodeError::LockPoisoned => TransportError::ServerError("lock poisoned".to_string()),
        NodeError::MailboxFull => TransportError::ServerError("mailbox full".to_string()),
        NodeError::InvalidMessage(msg) => {
            TransportError::ServerError(format!("invalid message: {msg}"))
        }
        NodeError::InvalidConfig(msg) => {
            TransportError::ServerError(format!("invalid config: {msg}"))
        }
        // NodeError is non_exhaustive, handle future variants
        _ => TransportError::ServerError(format!("node error: {error}")),
    }
}

#[async_trait]
impl TransportTarget for EmbeddedTarget {
    fn id(&self) -> &TargetId {
        &self.config.base.id
    }

    fn config(&self) -> &TargetConfig {
        &self.config.base
    }

    fn health(&self) -> HealthState {
        // If the node is not running, report as unhealthy
        if !self.handle.is_running() {
            return HealthState::Unhealthy;
        }
        self.health.state()
    }

    fn is_available(&self) -> bool {
        self.handle.is_running() && self.health.is_available()
    }

    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<RawReceipt, TransportError> {
        let start = Instant::now();

        let result = self
            .handle
            .submit_message(envelope)
            .await
            .map_err(convert_error);

        match &result {
            Ok(()) => {
                self.record_success(start.elapsed());
                debug!("Message submitted to {}", self.display_label());
            }
            Err(e) => {
                self.record_failure(e);
                debug!(
                    "Failed to submit message to {}: {}",
                    self.display_label(),
                    e
                );
            }
        }

        // TODO: Extract receipt from embedded node response
        // For now, return empty receipt
        result.map(|()| RawReceipt::default())
    }

    async fn submit_ack_tombstone(
        &self,
        tombstone: SignedAckTombstone,
    ) -> Result<(), TransportError> {
        let start = Instant::now();

        let result = self
            .handle
            .process_ack_tombstone(&tombstone)
            .map_err(convert_error);

        match &result {
            Ok(deleted) => {
                self.record_success(start.elapsed());
                if *deleted {
                    debug!(
                        "AckTombstone processed, message deleted from {}",
                        self.display_label()
                    );
                } else {
                    debug!(
                        "AckTombstone processed, message not found in {} (already deleted?)",
                        self.display_label()
                    );
                }
            }
            Err(e) => {
                self.record_failure(e);
                debug!(
                    "Failed to process AckTombstone in {}: {}",
                    self.display_label(),
                    e
                );
            }
        }

        // Convert Result<bool, _> to Result<(), _>
        result.map(|_| ())
    }

    fn record_success(&self, latency: Duration) {
        self.health.record_success(latency);
    }

    fn record_failure(&self, _error: &TransportError) {
        self.health.record_failure();
    }
}

/// Implement `Transport` trait for compatibility with `CompositeTransport`.
///
/// This allows `EmbeddedTarget` to be used alongside `HttpTransport` and `MqttTransport`
/// in the composite transport for multi-transport message delivery.
///
/// Note: Receipt data is discarded in this wrapper; use `TransportTarget`
/// directly if receipt verification is needed.
#[async_trait]
impl crate::Transport for EmbeddedTarget {
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        // Discard receipt data - use TransportTarget directly for receipt verification
        <Self as TransportTarget>::submit_message(self, envelope)
            .await
            .map(|_receipt| ())
    }

    async fn submit_ack_tombstone(
        &self,
        tombstone: SignedAckTombstone,
    ) -> Result<(), TransportError> {
        <Self as TransportTarget>::submit_ack_tombstone(self, tombstone).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_message::{MessageID, RoutingKey, CURRENT_VERSION};
    use reme_node_core::{EmbeddedNode, PersistentMailboxStore, PersistentStoreConfig};

    fn create_test_envelope(routing_key: RoutingKey) -> OuterEnvelope {
        OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: 482_253,
            ttl_hours: Some(24),
            message_id: MessageID::new(),
            ephemeral_key: [0u8; 32],
            ack_hash: [0u8; 16],
            inner_ciphertext: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn test_embedded_target_config() {
        let config = EmbeddedTargetConfig::new();
        assert_eq!(config.base.kind, TargetKind::Ephemeral);
        assert_eq!(config.base.id.as_str(), "embedded:local");
        assert_eq!(config.base.label, Some("Embedded Node".to_string()));
    }

    #[test]
    fn test_embedded_target_config_custom() {
        let config = EmbeddedTargetConfig::new()
            .with_priority(255)
            .with_label("Custom Node");

        assert_eq!(config.base.priority, 255);
        assert_eq!(config.base.label, Some("Custom Node".to_string()));
    }

    #[tokio::test]
    async fn test_embedded_target_submit_message() {
        let store_config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(store_config).unwrap();

        let (node, handle, _event_rx) = EmbeddedNode::new(store);
        let node_task = tokio::spawn(async move { node.run().await });

        let target = EmbeddedTarget::new(handle.clone());

        // Verify target is available
        assert!(target.is_available());
        assert!(target.is_node_running());
        assert_eq!(target.health(), HealthState::Healthy);

        // Submit a message
        let routing_key = RoutingKey::from_bytes([42u8; 16]);
        let envelope = create_test_envelope(routing_key);
        let msg_id = envelope.message_id;

        target.submit_message(envelope).await.unwrap();

        // Verify message was stored
        let messages = handle.fetch_messages(routing_key).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id, msg_id);

        // Cleanup
        handle.shutdown().await.unwrap();
        node_task.await.unwrap();

        // After shutdown, target should be unavailable
        assert!(!target.is_node_running());
        assert!(!target.is_available());
    }

    #[tokio::test]
    async fn test_embedded_target_health_tracking() {
        let store_config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(store_config).unwrap();

        let (node, handle, _event_rx) = EmbeddedNode::new(store);
        let node_task = tokio::spawn(async move { node.run().await });

        let target = EmbeddedTarget::new(handle.clone());

        // Initial state
        assert_eq!(target.health(), HealthState::Healthy);

        // Submit a message successfully
        let routing_key = RoutingKey::from_bytes([1u8; 16]);
        let envelope = create_test_envelope(routing_key);
        target.submit_message(envelope).await.unwrap();

        // Health should still be healthy
        assert_eq!(target.health(), HealthState::Healthy);

        // Cleanup
        handle.shutdown().await.unwrap();
        node_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_embedded_target_failure_handling() {
        let store_config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(store_config).unwrap();

        let (node, handle, _event_rx) = EmbeddedNode::new(store);
        let node_task = tokio::spawn(async move { node.run().await });

        let target = EmbeddedTarget::new(handle.clone());

        // Shutdown node before submitting
        handle.shutdown().await.unwrap();
        node_task.await.unwrap();

        // Target should report as unavailable
        assert!(!target.is_node_running());
        assert!(!target.is_available());
        assert_eq!(target.health(), HealthState::Unhealthy);

        // Attempting to submit should fail with ChannelClosed
        let routing_key = RoutingKey::from_bytes([1u8; 16]);
        let envelope = create_test_envelope(routing_key);
        let result = target.submit_message(envelope).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TransportError::ChannelClosed));
    }

    #[tokio::test]
    async fn test_embedded_target_ack_tombstone() {
        use reme_encryption::derive_ack_hash;
        use reme_message::SignedAckTombstone;

        let store_config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(store_config).unwrap();

        let (node, handle, _event_rx) = EmbeddedNode::new(store);
        let node_task = tokio::spawn(async move { node.run().await });

        let target = EmbeddedTarget::new(handle.clone());

        // Submit a message with known ack_secret
        let routing_key = RoutingKey::from_bytes([42u8; 16]);
        let ack_secret = [1u8; 16];
        let ack_hash = derive_ack_hash(&ack_secret);

        let envelope = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: 482_253,
            ttl_hours: Some(24),
            message_id: MessageID::new(),
            ephemeral_key: [0u8; 32],
            ack_hash,
            inner_ciphertext: vec![1, 2, 3, 4],
        };
        let message_id = envelope.message_id;

        target.submit_message(envelope).await.unwrap();

        // Verify message is stored
        let messages = handle.fetch_messages(routing_key).await.unwrap();
        assert_eq!(messages.len(), 1);

        // Re-submit message since fetch removes it
        let envelope2 = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: 482_253,
            ttl_hours: Some(24),
            message_id,
            ephemeral_key: [0u8; 32],
            ack_hash,
            inner_ciphertext: vec![1, 2, 3, 4],
        };
        target.submit_message(envelope2).await.unwrap();

        // Create tombstone with correct ack_secret (use a dummy signer key)
        let dummy_signer_key = [42u8; 32];
        let tombstone = SignedAckTombstone::new(message_id, ack_secret, &dummy_signer_key);

        // Submit tombstone - should succeed and delete message
        target.submit_ack_tombstone(tombstone).await.unwrap();

        // Verify message is deleted
        let messages = handle.fetch_messages(routing_key).await.unwrap();
        assert!(
            messages.is_empty(),
            "Message should have been deleted by tombstone"
        );

        // Cleanup
        handle.shutdown().await.unwrap();
        node_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_embedded_target_invalid_ack_tombstone() {
        use reme_encryption::derive_ack_hash;
        use reme_message::SignedAckTombstone;

        let store_config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(store_config).unwrap();

        let (node, handle, _event_rx) = EmbeddedNode::new(store);
        let node_task = tokio::spawn(async move { node.run().await });

        let target = EmbeddedTarget::new(handle.clone());

        // Submit a message with known ack_secret
        let routing_key = RoutingKey::from_bytes([42u8; 16]);
        let ack_secret = [1u8; 16];
        let ack_hash = derive_ack_hash(&ack_secret);

        let envelope = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: 482_253,
            ttl_hours: Some(24),
            message_id: MessageID::new(),
            ephemeral_key: [0u8; 32],
            ack_hash,
            inner_ciphertext: vec![1, 2, 3, 4],
        };
        let message_id = envelope.message_id;

        target.submit_message(envelope).await.unwrap();

        // Create tombstone with WRONG ack_secret
        let dummy_signer_key = [42u8; 32];
        let wrong_ack_secret = [99u8; 16];
        let tombstone = SignedAckTombstone::new(message_id, wrong_ack_secret, &dummy_signer_key);

        // Submit tombstone - should fail with invalid ack_secret
        let result = target.submit_ack_tombstone(tombstone).await;
        assert!(
            result.is_err(),
            "Tombstone with invalid ack_secret should fail"
        );

        // Verify message is NOT deleted
        let messages = handle.fetch_messages(routing_key).await.unwrap();
        assert_eq!(
            messages.len(),
            1,
            "Message should not be deleted on invalid tombstone"
        );

        // Cleanup
        handle.shutdown().await.unwrap();
        node_task.await.unwrap();
    }
}
