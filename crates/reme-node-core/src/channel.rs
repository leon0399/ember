//! Channel types for client ↔ internal node communication.
//!
//! The embedded node uses tokio mpsc channels for async communication:
//! - `NodeRequest`: Client → Node (with oneshot response channel)
//! - `NodeEvent`: Node → Client (async push for incoming messages)

use reme_message::{OuterEnvelope, RoutingKey, TombstoneEnvelope};
use tokio::sync::oneshot;

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
