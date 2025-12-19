//! Embedded node client for local-first messaging.
//!
//! The `EmbeddedClient` runs an in-process mailbox node and communicates with it
//! via tokio channels. This enables:
//!
//! - Zero-latency local message submission
//! - Async push notifications for incoming messages
//! - HTTP server for LAN peer replication
//!
//! ## Architecture
//!
//! ```text
//! EmbeddedClient ←→ [mpsc channels] ←→ EmbeddedNode ←→ [HTTP] ←→ LAN Peers
//! ```
//!
//! ## Example
//!
//! ```ignore
//! use reme_core::embedded::{EmbeddedClient, EmbeddedClientConfig};
//! use reme_storage::UnifiedStorage;
//! use std::sync::Arc;
//!
//! // Create storage
//! let storage = Arc::new(UnifiedStorage::open("app.db")?);
//!
//! // Create client with embedded node
//! let config = EmbeddedClientConfig {
//!     peers: vec!["http://192.168.1.100:3000".to_string()],
//!     ..Default::default()
//! };
//! let mut client = EmbeddedClient::new(identity, storage, config).await?;
//!
//! // Use in event loop with tokio::select!
//! loop {
//!     tokio::select! {
//!         Some(event) = client.event_receiver().recv() => {
//!             match event {
//!                 NodeEvent::MessageReceived(envelope) => {
//!                     let msg = client.process_message(&envelope).await?;
//!                     // Handle message...
//!                 }
//!                 _ => {}
//!             }
//!         }
//!         // ... other events
//!     }
//! }
//!
//! // Graceful shutdown
//! client.shutdown().await?;
//! ```

use crate::{Client, ClientError, Contact, ReceivedMessage};
use reme_identity::{Identity, PublicID};
use reme_message::{MessageID, OuterEnvelope, RoutingKey, TombstoneStatus};
use reme_node_core::{
    start_embedded_node, EmbeddedNodeConfig, EmbeddedNodeHandle, NodeError, NodeEvent,
};
use reme_outbox::{
    AttemptResult, DeliveryState, OutboxConfig, OutboxEntryId, PendingMessage,
    TransportRetryPolicy,
};
use reme_storage::UnifiedStorage;
use reme_transport::ChannelTransport;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::info;

/// Error type for embedded client operations.
#[derive(Debug, Error)]
pub enum EmbeddedClientError {
    #[error("Client error: {0}")]
    Client(#[from] ClientError),

    #[error("Node error: {0}")]
    Node(#[from] NodeError),

    #[error("Shutdown error: {0}")]
    Shutdown(String),
}

/// Configuration for the embedded client.
#[derive(Debug, Clone)]
pub struct EmbeddedClientConfig {
    /// LAN peer URLs for message replication.
    pub peers: Vec<String>,

    /// HTTP server bind address for accepting peer connections.
    /// Set to Some("0.0.0.0:0") for automatic port selection.
    /// Set to None to disable HTTP server.
    pub http_bind_addr: Option<std::net::SocketAddr>,

    /// Maximum messages per mailbox (default: 1000).
    pub max_messages_per_mailbox: usize,

    /// Default message TTL in seconds (default: 7 days).
    pub default_ttl_secs: u64,

    /// Outbox configuration for retry policies.
    pub outbox_config: OutboxConfig,
}

impl Default for EmbeddedClientConfig {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            http_bind_addr: None,
            max_messages_per_mailbox: 1000,
            default_ttl_secs: 7 * 24 * 60 * 60, // 7 days
            outbox_config: OutboxConfig::default(),
        }
    }
}

/// Client with embedded mailbox node.
///
/// This client runs an in-process mailbox node and communicates with it
/// via tokio channels for zero-latency local operations.
///
/// Use `event_receiver()` in a `tokio::select!` loop to receive push
/// notifications for incoming messages.
pub struct EmbeddedClient {
    /// The underlying client using channel transport.
    inner: Client<ChannelTransport>,

    /// Handle to the embedded node (for lifecycle management).
    node_handle: EmbeddedNodeHandle,

    /// Shared storage reference.
    storage: Arc<UnifiedStorage>,
}

impl EmbeddedClient {
    /// Create a new client with an embedded mailbox node.
    ///
    /// This starts the embedded node and configures channel transport for
    /// communication. The node begins monitoring for messages immediately.
    ///
    /// # Arguments
    /// * `identity` - Client's identity for encryption/signing
    /// * `storage` - Shared storage for client state and mailbox
    /// * `config` - Embedded client configuration
    pub async fn new(
        identity: Identity,
        storage: Arc<UnifiedStorage>,
        config: EmbeddedClientConfig,
    ) -> Result<Self, EmbeddedClientError> {
        let routing_key = identity.public_id().routing_key();

        // Configure the embedded node
        let node_config = EmbeddedNodeConfig {
            max_messages_per_mailbox: config.max_messages_per_mailbox,
            default_ttl_secs: config.default_ttl_secs,
            peers: config.peers,
            node_id: uuid::Uuid::new_v4().to_string(),
            http_bind_addr: config.http_bind_addr,
            monitored_routing_keys: vec![routing_key],
        };

        // Start the embedded node
        let node_handle = start_embedded_node(storage.clone(), node_config).await?;

        // Create channel transport for communication with the node
        let channel_transport = ChannelTransport::new(node_handle.request_sender());

        // Create the inner client with channel transport
        let inner = Client::with_config(
            identity,
            Arc::new(channel_transport),
            // We need Storage, but we have UnifiedStorage
            // For now, create a separate Storage for the client
            // TODO: Make Client generic over storage type
            reme_storage::Storage::in_memory().map_err(|e| {
                EmbeddedClientError::Client(ClientError::Storage(e))
            })?,
            config.outbox_config,
        );

        info!("Embedded client started");

        Ok(Self {
            inner,
            node_handle,
            storage,
        })
    }

    /// Get a mutable reference to the event receiver.
    ///
    /// Use this in a `tokio::select!` loop to receive push notifications
    /// for incoming messages.
    ///
    /// # Example
    ///
    /// ```ignore
    /// loop {
    ///     tokio::select! {
    ///         Some(event) = client.event_receiver().recv() => {
    ///             match event {
    ///                 NodeEvent::MessageReceived(envelope) => {
    ///                     let msg = client.process_message(&envelope).await?;
    ///                     println!("Received: {:?}", msg);
    ///                 }
    ///                 NodeEvent::Error(e) => {
    ///                     eprintln!("Node error: {}", e);
    ///                 }
    ///                 NodeEvent::ShuttingDown => break,
    ///             }
    ///         }
    ///     }
    /// }
    /// ```
    pub fn event_receiver(&mut self) -> &mut mpsc::Receiver<NodeEvent> {
        &mut self.node_handle.event_rx
    }

    /// Get the HTTP address the embedded node is listening on.
    ///
    /// Returns `None` if HTTP server is disabled.
    pub fn http_addr(&self) -> Option<std::net::SocketAddr> {
        self.node_handle.http_addr()
    }

    /// Get the HTTP URL for the embedded node.
    ///
    /// Returns `None` if HTTP server is disabled.
    pub fn http_url(&self) -> Option<String> {
        self.node_handle.http_url()
    }

    /// Shutdown the embedded client gracefully.
    ///
    /// This stops the embedded node and waits for it to complete.
    pub async fn shutdown(self) -> Result<(), EmbeddedClientError> {
        info!("Shutting down embedded client...");
        self.node_handle
            .shutdown()
            .await
            .map_err(|e| EmbeddedClientError::Shutdown(e.to_string()))?;
        info!("Embedded client shutdown complete");
        Ok(())
    }

    /// Get the shared storage reference.
    pub fn storage(&self) -> &Arc<UnifiedStorage> {
        &self.storage
    }

    // ========================================
    // Delegated methods from inner Client
    // ========================================

    /// Get the client's public identity (MIK).
    pub fn public_id(&self) -> &PublicID {
        self.inner.public_id()
    }

    /// Get the routing key for this client's mailbox.
    pub fn routing_key(&self) -> RoutingKey {
        self.inner.routing_key()
    }

    /// Add a new contact.
    pub fn add_contact(
        &self,
        public_id: &PublicID,
        name: Option<&str>,
    ) -> Result<Contact, ClientError> {
        self.inner.add_contact(public_id, name)
    }

    /// Get contact by public ID.
    pub fn get_contact(&self, public_id: &PublicID) -> Result<Contact, ClientError> {
        self.inner.get_contact(public_id)
    }

    /// List all contacts.
    pub fn list_contacts(&self) -> Result<Vec<Contact>, ClientError> {
        self.inner.list_contacts()
    }

    /// Clear conversation history with a contact and increment epoch.
    pub fn clear_conversation_dag(&self, contact: &PublicID) -> u16 {
        self.inner.clear_conversation_dag(contact)
    }

    /// Get the current epoch for a conversation.
    pub fn get_conversation_epoch(&self, contact: &PublicID) -> u16 {
        self.inner.get_conversation_epoch(contact)
    }

    /// Send a text message to a contact.
    pub async fn send_text(&self, to: &PublicID, text: &str) -> Result<MessageID, ClientError> {
        self.inner.send_text(to, text).await
    }

    /// Send a detached text message (no DAG linkage).
    pub async fn send_text_detached(
        &self,
        to: &PublicID,
        text: &str,
    ) -> Result<MessageID, ClientError> {
        self.inner.send_text_detached(to, text).await
    }

    /// Send a delivery receipt for a received message.
    pub async fn send_delivery_receipt(
        &self,
        to: &PublicID,
        for_message_id: MessageID,
    ) -> Result<MessageID, ClientError> {
        self.inner.send_delivery_receipt(to, for_message_id).await
    }

    /// Send a read receipt for a received message.
    pub async fn send_read_receipt(
        &self,
        to: &PublicID,
        for_message_id: MessageID,
    ) -> Result<MessageID, ClientError> {
        self.inner.send_read_receipt(to, for_message_id).await
    }

    /// Process a raw envelope into a decrypted message.
    pub async fn process_message(
        &self,
        outer: &OuterEnvelope,
    ) -> Result<ReceivedMessage, ClientError> {
        self.inner.process_message(outer).await
    }

    /// Process a delivery receipt.
    pub fn process_delivery_receipt(&self, message_id: MessageID) -> Result<(), ClientError> {
        self.inner.process_delivery_receipt(message_id)
    }

    /// Process a read receipt.
    pub fn process_read_receipt(&self, message_id: MessageID) -> Result<(), ClientError> {
        self.inner.process_read_receipt(message_id)
    }

    /// Send a tombstone to acknowledge message receipt.
    pub async fn send_tombstone(
        &self,
        message: &ReceivedMessage,
        status: TombstoneStatus,
    ) -> Result<(), ClientError> {
        self.inner.send_tombstone(message, status).await
    }

    /// Send a delivery tombstone.
    pub async fn send_delivery_tombstone(
        &self,
        message: &ReceivedMessage,
    ) -> Result<(), ClientError> {
        self.inner.send_delivery_tombstone(message).await
    }

    /// Send a read tombstone.
    pub async fn send_read_tombstone(&self, message: &ReceivedMessage) -> Result<(), ClientError> {
        self.inner.send_read_tombstone(message).await
    }

    /// Set retry policy for a transport type.
    pub fn set_transport_policy(&mut self, transport_prefix: &str, policy: TransportRetryPolicy) {
        self.inner.set_transport_policy(transport_prefix, policy)
    }

    /// Attempt to deliver a pending message.
    pub async fn attempt_delivery(&self, entry_id: OutboxEntryId) -> Result<AttemptResult, ClientError> {
        self.inner.attempt_delivery(entry_id).await
    }

    /// Schedule immediate retry for a message.
    pub fn schedule_retry(&self, entry_id: OutboxEntryId) -> Result<(), ClientError> {
        self.inner.schedule_retry(entry_id)
    }

    /// Get messages ready for retry.
    pub fn get_ready_for_retry(&self) -> Result<Vec<PendingMessage>, ClientError> {
        self.inner.get_ready_for_retry()
    }

    /// Get all pending (unconfirmed) messages.
    pub fn get_pending_messages(&self) -> Result<Vec<PendingMessage>, ClientError> {
        self.inner.get_pending_messages()
    }

    /// Get pending messages for a specific recipient.
    pub fn get_pending_for(&self, recipient: &PublicID) -> Result<Vec<PendingMessage>, ClientError> {
        self.inner.get_pending_for(recipient)
    }

    /// Get delivery state for a message.
    pub fn get_delivery_state(&self, entry_id: OutboxEntryId) -> Result<Option<DeliveryState>, ClientError> {
        self.inner.get_delivery_state(entry_id)
    }

    /// Process outbox tick: retry due messages and check expirations.
    pub async fn outbox_tick(&self) -> Result<(usize, u64), ClientError> {
        self.inner.outbox_tick().await
    }

    /// Clean up old confirmed/expired outbox entries.
    pub fn outbox_cleanup(&self) -> Result<u64, ClientError> {
        self.inner.outbox_cleanup()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_embedded_client_config_default() {
        let config = EmbeddedClientConfig::default();
        assert!(config.peers.is_empty());
        assert!(config.http_bind_addr.is_none());
        assert_eq!(config.max_messages_per_mailbox, 1000);
    }
}
