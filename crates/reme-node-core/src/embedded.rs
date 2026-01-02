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
//! let (node, handle, _event_rx) = EmbeddedNode::new(store);
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

use reme_message::{MessageID, OuterEnvelope, RoutingKey};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, trace, warn};

use crate::{MailboxStore, NodeError, NodeEvent, NodeRequest};

/// Default channel buffer size for request/event channels.
const DEFAULT_CHANNEL_SIZE: usize = 256;

/// Embedded mailbox node that runs within the client process.
///
/// Processes requests from the client via channels. External message
/// notifications (e.g., from HTTP server receiving LAN peer messages)
/// are handled by [`EmbeddedNodeHandle::notify_message_received`].
pub struct EmbeddedNode<S: MailboxStore> {
    /// The mailbox storage backend.
    store: Arc<S>,

    /// Channel for receiving requests from client/handle.
    requests: mpsc::Receiver<NodeRequest>,
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

                NodeRequest::FetchMessages {
                    routing_key,
                    response,
                } => {
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

    /// Handle a fetch messages request.
    fn handle_fetch_messages(
        &self,
        routing_key: RoutingKey,
    ) -> Result<Vec<OuterEnvelope>, NodeError> {
        trace!(?routing_key, "Fetching messages");
        let messages = self.store.fetch(&routing_key)?;
        debug!(count = messages.len(), "Fetched messages");
        Ok(messages)
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

    /// Direct access to store for `notify_message_received`.
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
            .map_err(|_| NodeError::ChannelClosed)?;

        rx.await.map_err(|_| NodeError::ChannelClosed)?
    }

    /// Fetch messages for a routing key from the embedded node.
    pub async fn fetch_messages(
        &self,
        routing_key: RoutingKey,
    ) -> Result<Vec<OuterEnvelope>, NodeError> {
        let (tx, rx) = oneshot::channel();
        self.requests
            .send(NodeRequest::FetchMessages {
                routing_key,
                response: tx,
            })
            .await
            .map_err(|_| NodeError::ChannelClosed)?;

        rx.await.map_err(|_| NodeError::ChannelClosed)?
    }

    /// Request graceful shutdown of the embedded node.
    pub async fn shutdown(&self) -> Result<(), NodeError> {
        self.requests
            .send(NodeRequest::Shutdown)
            .await
            .map_err(|_| NodeError::ChannelClosed)
    }

    /// Check if a message already exists in the mailbox.
    ///
    /// Useful for duplicate detection before storing.
    pub fn has_message(
        &self,
        routing_key: &RoutingKey,
        message_id: &MessageID,
    ) -> Result<bool, NodeError> {
        self.store.has_message(routing_key, message_id)
    }

    /// Notify the client that a message was received from an external source.
    ///
    /// This bypasses the request channel and directly stores + notifies,
    /// making it suitable for use from HTTP handlers.
    ///
    /// # Event Notification
    ///
    /// If the event channel is full, the message is still stored but the client
    /// won't be immediately notified (it will see the message on next fetch).
    /// If the channel is closed, this returns an error as the client may have crashed.
    pub fn notify_message_received(&self, envelope: OuterEnvelope) -> Result<(), NodeError> {
        let routing_key = envelope.routing_key;
        let message_id = envelope.message_id;

        // Store the message
        trace!(?message_id, "Storing message from external source");
        self.store.enqueue(routing_key, envelope.clone())?;

        // Push event to client
        match self
            .event_sender
            .try_send(NodeEvent::MessageReceived(envelope))
        {
            Ok(()) => {
                debug!(?message_id, "Message event sent to client");
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Message stored, but client backlogged - they'll see it on next fetch
                warn!(
                    ?message_id,
                    "Event channel full - message stored but client not immediately notified"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Client receiver dropped - this is a serious error
                error!(
                    ?message_id,
                    "Event channel closed - message stored but client may have crashed"
                );
                return Err(NodeError::ChannelClosed);
            }
        }

        Ok(())
    }

    /// Check if the node is still running (request channel not closed).
    pub fn is_running(&self) -> bool {
        !self.requests.is_closed()
    }

    /// Process an ack tombstone to delete a message from the mailbox.
    ///
    /// This verifies the tombstone's `ack_secret` against the stored `ack_hash`
    /// and deletes the message if valid.
    ///
    /// # Returns
    /// - `Ok(true)` if the message was deleted
    /// - `Ok(false)` if the message was not found (already deleted or never existed)
    /// - `Err(NodeError::InvalidMessage)` if the `ack_secret` is invalid
    pub fn process_ack_tombstone(
        &self,
        tombstone: &reme_message::SignedAckTombstone,
    ) -> Result<bool, NodeError> {
        let message_id = tombstone.message_id;

        // Get the stored ack_hash for this message
        let Some(ack_hash) = self.store.get_ack_hash(&message_id)? else {
            debug!(
                ?message_id,
                "AckTombstone for unknown message (already deleted?)"
            );
            return Ok(false);
        };

        // Verify the ack_secret
        if !tombstone.verify_authorization(&ack_hash) {
            warn!(
                ?message_id,
                "AckTombstone authorization failed - invalid ack_secret"
            );
            return Err(NodeError::InvalidMessage("Invalid ack_secret".to_string()));
        }

        // Delete the message
        let deleted = self.store.delete_message(&message_id)?;
        if deleted {
            debug!(?message_id, "Message deleted via AckTombstone");
        }

        Ok(deleted)
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
            timestamp_hours: 482_253,
            ttl_hours: Some(24),
            message_id: MessageID::new(),
            ephemeral_key: [0u8; 32],
            ack_hash: [0u8; 16],
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
        let node_task = tokio::spawn(async move { node.run().await });

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
            NodeEvent::Error(_) => panic!("Expected MessageReceived event"),
        }

        // Shutdown
        handle.shutdown().await.unwrap();
        node_task.await.unwrap();
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
        assert!(
            !handle.is_running(),
            "Node should not be running after shutdown"
        );
    }
}
