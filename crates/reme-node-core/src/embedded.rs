//! Embedded node for in-process mailbox functionality.
//!
//! The embedded node runs as a background task within the client process,
//! enabling direct LAN P2P messaging without an external mailbox server.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                       Client                            │
//! │  ┌──────────────┐        ┌──────────────────────────┐  │
//! │  │   App Logic  │◄──────►│    EmbeddedNodeHandle    │  │
//! │  └──────────────┘        │  - send_request()        │  │
//! │         ▲                │  - subscribe_events()    │  │
//! │         │                └─────────────┬────────────┘  │
//! │         │                              │               │
//! │         │ NodeEvent       NodeRequest  │               │
//! │         │                              ▼               │
//! │  ┌──────┴───────────────────────────────────────────┐  │
//! │  │                   EmbeddedNode                    │  │
//! │  │  - processes requests via channels                │  │
//! │  │  - emits events for incoming messages             │  │
//! │  │  - manages MailboxStore                           │  │
//! │  └──────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use reme_node_core::{EmbeddedNode, PersistentMailboxStore, PersistentStoreConfig};
//!
//! // Create mailbox store
//! let config = PersistentStoreConfig::default();
//! let store = PersistentMailboxStore::in_memory(config)?;
//!
//! // Create embedded node
//! let (node, handle) = EmbeddedNode::new(store);
//!
//! // Run node in background
//! let node_task = tokio::spawn(async move {
//!     node.run().await;
//! });
//!
//! // Use handle to interact with node
//! handle.submit_message(envelope).await?;
//! ```

use std::sync::Arc;

use reme_message::{OuterEnvelope, RoutingKey, TombstoneEnvelope};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, trace, warn};

use crate::{MailboxStore, NodeError, NodeRequest, NodeEvent};

/// Default channel buffer size for request/event channels.
const DEFAULT_CHANNEL_SIZE: usize = 256;

/// Embedded mailbox node that runs within the client process.
///
/// Processes requests from the client and emits events for incoming
/// messages (e.g., from HTTP server receiving LAN peer messages).
pub struct EmbeddedNode<S: MailboxStore> {
    /// The mailbox storage backend.
    store: Arc<S>,

    /// Channel for receiving requests from client/handle.
    requests: mpsc::Receiver<NodeRequest>,

    /// Channel for emitting events to the client.
    events: mpsc::Sender<NodeEvent>,
}

impl<S: MailboxStore + 'static> EmbeddedNode<S> {
    /// Create a new embedded node with the given store.
    ///
    /// Returns:
    /// - The node (run via [`EmbeddedNode::run()`] in a background task)
    /// - A handle for sending requests to the node (cloneable)
    /// - An event receiver for receiving notifications (e.g., incoming messages)
    ///
    /// The event receiver should typically be consumed by a single task that
    /// processes incoming messages.
    pub fn new(store: S) -> (Self, EmbeddedNodeHandle, mpsc::Receiver<NodeEvent>) {
        let (request_tx, request_rx) = mpsc::channel(DEFAULT_CHANNEL_SIZE);
        let (event_tx, event_rx) = mpsc::channel(DEFAULT_CHANNEL_SIZE);

        let store = Arc::new(store);
        let node = Self {
            store: Arc::clone(&store),
            requests: request_rx,
            events: event_tx.clone(),
        };

        let handle = EmbeddedNodeHandle {
            requests: request_tx,
            store,
            event_sender: event_tx,
        };

        (node, handle, event_rx)
    }

    /// Run the embedded node event loop.
    ///
    /// This processes incoming requests and should be spawned as a
    /// background task. Returns when a Shutdown request is received
    /// or when all request senders are dropped.
    pub async fn run(mut self) {
        info!("Embedded node starting");

        while let Some(request) = self.requests.recv().await {
            match request {
                NodeRequest::SubmitMessage { envelope, response } => {
                    let result = self.handle_submit_message(envelope);
                    let _ = response.send(result);
                }

                NodeRequest::SubmitTombstone { envelope, response } => {
                    let result = self.handle_submit_tombstone(envelope);
                    let _ = response.send(result);
                }

                NodeRequest::FetchMessages { routing_key, response } => {
                    let result = self.handle_fetch_messages(routing_key);
                    let _ = response.send(result);
                }

                NodeRequest::Shutdown => {
                    info!("Embedded node received shutdown request");
                    break;
                }
            }
        }

        info!("Embedded node stopped");
    }

    /// Handle a submit message request.
    fn handle_submit_message(&self, envelope: OuterEnvelope) -> Result<(), NodeError> {
        let routing_key = envelope.routing_key;
        let message_id = envelope.message_id;

        trace!(?message_id, "Enqueueing message");
        self.store.enqueue(routing_key, envelope)?;
        debug!(?message_id, "Message enqueued successfully");

        Ok(())
    }

    /// Handle a submit tombstone request.
    fn handle_submit_tombstone(&self, envelope: TombstoneEnvelope) -> Result<(), NodeError> {
        let message_id = &envelope.target_message_id;

        trace!(?message_id, "Processing tombstone");

        let deleted = self.store.delete_message(message_id)?;
        if deleted {
            debug!(?message_id, "Message deleted via tombstone");
        } else {
            debug!(?message_id, "Tombstone for non-existent message, ignoring");
        }

        Ok(())
    }

    /// Handle a fetch messages request.
    fn handle_fetch_messages(&self, routing_key: RoutingKey) -> Result<Vec<OuterEnvelope>, NodeError> {
        trace!(?routing_key, "Fetching messages");
        let messages = self.store.fetch(&routing_key)?;
        debug!(count = messages.len(), "Fetched messages");
        Ok(messages)
    }

    /// Notify the client that a message was received from an external source.
    ///
    /// This is called by the HTTP server when a LAN peer sends a message.
    /// The message is:
    /// 1. Stored in the mailbox
    /// 2. Pushed to the client via the event channel
    ///
    /// This allows the client to immediately process incoming messages
    /// without polling.
    pub fn notify_message_received(&self, envelope: OuterEnvelope) -> Result<(), NodeError> {
        let routing_key = envelope.routing_key;
        let message_id = envelope.message_id;

        // Store the message
        trace!(?message_id, "Storing message from external source");
        self.store.enqueue(routing_key, envelope.clone())?;

        // Push event to client
        if let Err(e) = self.events.try_send(NodeEvent::MessageReceived(envelope)) {
            warn!(?message_id, error = %e, "Failed to send message event to client");
            // Don't fail - message is stored, client can fetch later
        } else {
            debug!(?message_id, "Message event sent to client");
        }

        Ok(())
    }
}

/// Handle for interacting with an embedded node.
///
/// Provides methods for sending requests and receiving events.
/// Clone this handle to share access across tasks.
#[derive(Clone)]
pub struct EmbeddedNodeHandle {
    /// Channel for sending requests to the node.
    requests: mpsc::Sender<NodeRequest>,

    /// Direct access to store for notify_message_received.
    store: Arc<dyn MailboxStore>,

    /// Event sender for external notifications.
    event_sender: mpsc::Sender<NodeEvent>,
}

impl EmbeddedNodeHandle {
    /// Submit a message to the embedded node's mailbox.
    pub async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), NodeError> {
        let (tx, rx) = oneshot::channel();
        self.requests
            .send(NodeRequest::SubmitMessage {
                envelope,
                response: tx,
            })
            .await
            .map_err(|_| NodeError::LockPoisoned)?;

        rx.await.map_err(|_| NodeError::LockPoisoned)?
    }

    /// Submit a tombstone to the embedded node.
    pub async fn submit_tombstone(&self, envelope: TombstoneEnvelope) -> Result<(), NodeError> {
        let (tx, rx) = oneshot::channel();
        self.requests
            .send(NodeRequest::SubmitTombstone {
                envelope,
                response: tx,
            })
            .await
            .map_err(|_| NodeError::LockPoisoned)?;

        rx.await.map_err(|_| NodeError::LockPoisoned)?
    }

    /// Fetch messages for a routing key from the embedded node.
    pub async fn fetch_messages(&self, routing_key: RoutingKey) -> Result<Vec<OuterEnvelope>, NodeError> {
        let (tx, rx) = oneshot::channel();
        self.requests
            .send(NodeRequest::FetchMessages {
                routing_key,
                response: tx,
            })
            .await
            .map_err(|_| NodeError::LockPoisoned)?;

        rx.await.map_err(|_| NodeError::LockPoisoned)?
    }

    /// Request graceful shutdown of the embedded node.
    pub async fn shutdown(&self) -> Result<(), NodeError> {
        self.requests
            .send(NodeRequest::Shutdown)
            .await
            .map_err(|_| NodeError::LockPoisoned)
    }

    /// Notify the client that a message was received from an external source.
    ///
    /// This bypasses the request channel and directly stores + notifies,
    /// making it suitable for use from HTTP handlers.
    pub fn notify_message_received(&self, envelope: OuterEnvelope) -> Result<(), NodeError> {
        let routing_key = envelope.routing_key;
        let message_id = envelope.message_id;

        // Store the message
        trace!(?message_id, "Storing message from external source");
        self.store.enqueue(routing_key, envelope.clone())?;

        // Push event to client
        if let Err(e) = self.event_sender.try_send(NodeEvent::MessageReceived(envelope)) {
            warn!(?message_id, error = %e, "Failed to send message event to client");
        } else {
            debug!(?message_id, "Message event sent to client");
        }

        Ok(())
    }

    /// Check if the node is still running (request channel not closed).
    pub fn is_running(&self) -> bool {
        !self.requests.is_closed()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PersistentMailboxStore, PersistentStoreConfig};
    use reme_message::{MessageID, CURRENT_VERSION};

    fn create_test_envelope(routing_key: RoutingKey) -> OuterEnvelope {
        OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: 482253,
            ttl_hours: Some(24),
            message_id: MessageID::new(),
            ephemeral_key: [0u8; 32],
            inner_ciphertext: vec![1, 2, 3, 4],
        }
    }

    #[tokio::test]
    async fn test_embedded_node_submit_and_fetch() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();

        let (node, handle, _event_rx) = EmbeddedNode::new(store);
        let node_task = tokio::spawn(async move { node.run().await });

        let routing_key = RoutingKey::from_bytes([42u8; 16]);
        let envelope = create_test_envelope(routing_key);
        let msg_id = envelope.message_id;

        // Submit message
        handle.submit_message(envelope).await.unwrap();

        // Fetch messages
        let messages = handle.fetch_messages(routing_key).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id, msg_id);

        // Shutdown
        handle.shutdown().await.unwrap();
        node_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_embedded_node_notify_message_received() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();

        let (node, handle, mut event_rx) = EmbeddedNode::new(store);
        let _node_task = tokio::spawn(async move { node.run().await });

        let routing_key = RoutingKey::from_bytes([99u8; 16]);
        let envelope = create_test_envelope(routing_key);
        let msg_id = envelope.message_id;

        // Simulate HTTP server receiving a message
        handle.notify_message_received(envelope).unwrap();

        // Should be able to fetch the message
        let messages = handle.fetch_messages(routing_key).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id, msg_id);

        // Event should be available (use try_recv to avoid blocking)
        let event = event_rx.try_recv();
        assert!(event.is_ok());
        match event.unwrap() {
            NodeEvent::MessageReceived(env) => {
                assert_eq!(env.message_id, msg_id);
            }
            _ => panic!("Expected MessageReceived event"),
        }
    }

    #[tokio::test]
    async fn test_embedded_node_shutdown() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();

        let (node, handle, _event_rx) = EmbeddedNode::new(store);
        let node_task = tokio::spawn(async move { node.run().await });

        assert!(handle.is_running());

        // Shutdown
        handle.shutdown().await.unwrap();

        // Wait for node to stop
        node_task.await.unwrap();

        // Channel should be closed after node stops
        // Note: is_running checks if requests channel is closed
    }

    #[tokio::test]
    async fn test_embedded_node_tombstone() {
        use reme_identity::Identity;
        use reme_message::TombstoneEnvelope;

        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();

        let (node, handle, _event_rx) = EmbeddedNode::new(store);
        let node_task = tokio::spawn(async move { node.run().await });

        let routing_key = RoutingKey::from_bytes([55u8; 16]);
        let envelope = create_test_envelope(routing_key);
        let msg_id = envelope.message_id;

        // Submit message
        handle.submit_message(envelope).await.unwrap();

        // Verify message exists
        let messages = handle.fetch_messages(routing_key).await.unwrap();
        assert_eq!(messages.len(), 1);

        // Create tombstone
        let recipient = Identity::generate();
        let tombstone = TombstoneEnvelope {
            version: CURRENT_VERSION,
            target_message_id: msg_id,
            routing_key,
            recipient_id_pub: recipient.public_id().to_bytes(),
            device_id: [1u8; 16], // DeviceID is a type alias for [u8; 16]
            timestamp_hours: 482253,
            sequence: 1,
            signature: [0u8; 64], // Not verified in embedded node
            encrypted_receipt: None,
        };

        // Submit tombstone
        handle.submit_tombstone(tombstone).await.unwrap();

        // Message should be deleted
        let messages = handle.fetch_messages(routing_key).await.unwrap();
        assert_eq!(messages.len(), 0);

        handle.shutdown().await.unwrap();
        node_task.await.unwrap();
    }
}
