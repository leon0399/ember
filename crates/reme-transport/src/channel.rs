//! Channel-based transport for embedded node communication.
//!
//! The `ChannelTransport` implements the `Transport` trait using tokio channels,
//! enabling zero-copy, zero-overhead communication with an embedded node.
//!
//! ## Architecture
//!
//! ```text
//! Client → ChannelTransport → [mpsc channel] → EmbeddedNode
//!                           ← [oneshot response] ←
//! ```
//!
//! ## Channel Types
//!
//! - `NodeRequest`: Client → Node (with oneshot response channel)
//! - `NodeEvent`: Node → Client (async push for incoming messages)
//! - `NodeError`: Error type for node operations

use async_trait::async_trait;
use reme_message::{OuterEnvelope, RoutingKey, TombstoneEnvelope};
use tokio::sync::{mpsc, oneshot};
use tracing::trace;

use crate::{Transport, TransportError};

/// Channel buffer size for requests (client → node).
pub const REQUEST_CHANNEL_SIZE: usize = 1024;

/// Channel buffer size for events (node → client).
pub const EVENT_CHANNEL_SIZE: usize = 4096;

/// Request from client to internal node.
///
/// Each request includes a oneshot channel for the response,
/// enabling request-response semantics over async channels.
#[derive(Debug)]
pub enum NodeRequest {
    /// Submit a message to the node's mailbox.
    SubmitMessage {
        envelope: OuterEnvelope,
        response: oneshot::Sender<Result<(), NodeError>>,
    },

    /// Submit a tombstone acknowledgment.
    SubmitTombstone {
        tombstone: TombstoneEnvelope,
        response: oneshot::Sender<Result<(), NodeError>>,
    },

    /// Fetch messages for a routing key (used for initial sync).
    FetchMessages {
        routing_key: RoutingKey,
        response: oneshot::Sender<Result<Vec<OuterEnvelope>, NodeError>>,
    },

    /// Request graceful shutdown.
    Shutdown,
}

/// Event pushed from internal node to client.
///
/// These are delivered asynchronously via the event channel,
/// enabling true push-based message delivery.
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// A message was received (from HTTP peer or MQTT).
    MessageReceived(OuterEnvelope),

    /// An error occurred in node processing.
    Error(String),

    /// Node is shutting down.
    ShuttingDown,
}

/// Errors that can occur in node operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum NodeError {
    /// Storage operation failed.
    #[error("Storage error: {0}")]
    Storage(String),

    /// Mailbox is full (capacity limit reached).
    #[error("Mailbox full")]
    MailboxFull,

    /// The communication channel was closed.
    #[error("Channel closed")]
    ChannelClosed,

    /// Node is shutting down.
    #[error("Shutdown in progress")]
    ShuttingDown,

    /// Message was already seen (duplicate).
    #[error("Duplicate message")]
    Duplicate,

    /// HTTP server error.
    #[error("HTTP server error: {0}")]
    HttpServer(String),
}

/// Transport implementation using tokio channels.
///
/// This transport communicates with an embedded node via mpsc channels,
/// providing zero-copy message passing without network overhead.
///
/// ## Example
///
/// ```ignore
/// // Obtain request_tx from EmbeddedNodeHandle
/// let transport = ChannelTransport::new(request_tx);
///
/// // Use like any other transport
/// transport.submit_message(envelope).await?;
/// ```
pub struct ChannelTransport {
    /// Sender for requests to the embedded node.
    request_tx: mpsc::Sender<NodeRequest>,

    /// Transport identifier for logging/debugging.
    transport_id: String,
}

impl ChannelTransport {
    /// Create a new channel transport.
    ///
    /// # Arguments
    ///
    /// * `request_tx` - The sender half of the request channel to the embedded node.
    pub fn new(request_tx: mpsc::Sender<NodeRequest>) -> Self {
        Self {
            request_tx,
            transport_id: "channel:internal".to_string(),
        }
    }

    /// Create a new channel transport with a custom ID.
    ///
    /// # Arguments
    ///
    /// * `request_tx` - The sender half of the request channel to the embedded node.
    /// * `transport_id` - Custom identifier for this transport instance.
    pub fn with_id(request_tx: mpsc::Sender<NodeRequest>, transport_id: impl Into<String>) -> Self {
        Self {
            request_tx,
            transport_id: transport_id.into(),
        }
    }

    /// Get the transport identifier.
    pub fn transport_id(&self) -> &str {
        &self.transport_id
    }

    /// Fetch messages for a routing key.
    ///
    /// This is used for initial sync when the client starts.
    pub async fn fetch_messages(
        &self,
        routing_key: RoutingKey,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        let (response_tx, response_rx) = oneshot::channel();

        self.request_tx
            .send(NodeRequest::FetchMessages {
                routing_key,
                response: response_tx,
            })
            .await
            .map_err(|_| TransportError::ChannelClosed)?;

        response_rx
            .await
            .map_err(|_| TransportError::ChannelClosed)?
            .map_err(|e| TransportError::ServerError(e.to_string()))
    }
}

#[async_trait]
impl Transport for ChannelTransport {
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        let message_id = envelope.message_id;
        let (response_tx, response_rx) = oneshot::channel();

        trace!(
            transport = %self.transport_id,
            ?message_id,
            "Submitting message via channel"
        );

        self.request_tx
            .send(NodeRequest::SubmitMessage {
                envelope,
                response: response_tx,
            })
            .await
            .map_err(|_| TransportError::ChannelClosed)?;

        response_rx
            .await
            .map_err(|_| TransportError::ChannelClosed)?
            .map_err(|e| TransportError::ServerError(e.to_string()))
    }

    async fn submit_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), TransportError> {
        let message_id = tombstone.target_message_id;
        let (response_tx, response_rx) = oneshot::channel();

        trace!(
            transport = %self.transport_id,
            ?message_id,
            "Submitting tombstone via channel"
        );

        self.request_tx
            .send(NodeRequest::SubmitTombstone {
                tombstone,
                response: response_tx,
            })
            .await
            .map_err(|_| TransportError::ChannelClosed)?;

        response_rx
            .await
            .map_err(|_| TransportError::ChannelClosed)?
            .map_err(|e| TransportError::ServerError(e.to_string()))
    }
}

impl Clone for ChannelTransport {
    fn clone(&self) -> Self {
        Self {
            request_tx: self.request_tx.clone(),
            transport_id: self.transport_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_message::{MessageID, CURRENT_VERSION};

    fn create_test_envelope() -> OuterEnvelope {
        OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key: RoutingKey::from_bytes([1u8; 16]),
            timestamp_hours: 482253,
            ttl_hours: Some(24),
            message_id: MessageID::new(),
            ephemeral_key: [0u8; 32],
            inner_ciphertext: vec![1, 2, 3, 4],
        }
    }

    #[tokio::test]
    async fn test_channel_transport_submit_message() {
        let (request_tx, mut request_rx) = mpsc::channel(REQUEST_CHANNEL_SIZE);
        let transport = ChannelTransport::new(request_tx);

        let envelope = create_test_envelope();
        let message_id = envelope.message_id;

        // Spawn handler to respond to request
        tokio::spawn(async move {
            if let Some(NodeRequest::SubmitMessage { envelope: env, response }) = request_rx.recv().await {
                assert_eq!(env.message_id, message_id);
                let _ = response.send(Ok(()));
            }
        });

        let result = transport.submit_message(envelope).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_channel_transport_channel_closed() {
        let (request_tx, request_rx) = mpsc::channel(REQUEST_CHANNEL_SIZE);
        let transport = ChannelTransport::new(request_tx);

        // Drop receiver to close channel
        drop(request_rx);

        let envelope = create_test_envelope();
        let result = transport.submit_message(envelope).await;
        assert!(matches!(result, Err(TransportError::ChannelClosed)));
    }

    #[tokio::test]
    async fn test_channel_transport_error_response() {
        let (request_tx, mut request_rx) = mpsc::channel(REQUEST_CHANNEL_SIZE);
        let transport = ChannelTransport::new(request_tx);

        // Spawn handler to respond with error
        tokio::spawn(async move {
            if let Some(NodeRequest::SubmitMessage { response, .. }) = request_rx.recv().await {
                let _ = response.send(Err(NodeError::MailboxFull));
            }
        });

        let envelope = create_test_envelope();
        let result = transport.submit_message(envelope).await;
        assert!(matches!(result, Err(TransportError::ServerError(_))));
    }
}
