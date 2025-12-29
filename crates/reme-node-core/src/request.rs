//! Request and event types for embedded node communication.
//!
//! These types enable in-process communication between the client
//! and an embedded mailbox node via tokio channels.

use reme_message::{OuterEnvelope, RoutingKey, TombstoneEnvelope};
use tokio::sync::oneshot;

use crate::NodeError;

/// Requests that can be sent to an embedded node.
///
/// Each request includes a oneshot channel for the response,
/// enabling async request/response patterns.
#[derive(Debug)]
pub enum NodeRequest {
    /// Submit a message to the mailbox for a recipient.
    SubmitMessage {
        envelope: OuterEnvelope,
        response: oneshot::Sender<Result<(), NodeError>>,
    },

    /// Submit a tombstone (message acknowledgment).
    SubmitTombstone {
        envelope: TombstoneEnvelope,
        response: oneshot::Sender<Result<(), NodeError>>,
    },

    /// Fetch all messages for a routing key.
    FetchMessages {
        routing_key: RoutingKey,
        response: oneshot::Sender<Result<Vec<OuterEnvelope>, NodeError>>,
    },

    /// Request graceful shutdown of the embedded node.
    Shutdown,
}

/// Events emitted by the embedded node to the client.
///
/// These events notify the client of incoming messages or errors
/// that occur asynchronously (e.g., from HTTP server receiving
/// messages from LAN peers).
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// A message was received for this client.
    ///
    /// This is emitted when:
    /// - HTTP server receives a message from a LAN peer
    /// - Message is deposited into the mailbox
    MessageReceived(OuterEnvelope),

    /// An error occurred in the node.
    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_message::{MessageID, CURRENT_VERSION};

    #[test]
    fn test_node_request_debug() {
        let (tx, _rx) = oneshot::channel();
        let routing_key = RoutingKey::from_bytes([0u8; 16]);
        let req = NodeRequest::FetchMessages {
            routing_key,
            response: tx,
        };
        // Should be debuggable without panic
        let _ = format!("{:?}", req);
    }

    #[test]
    fn test_node_event_clone() {
        let routing_key = RoutingKey::from_bytes([42u8; 16]);
        let envelope = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: 482253,
            ttl_hours: Some(24),
            message_id: MessageID::new(),
            ephemeral_key: [0u8; 32],
            ack_hash: [0u8; 16],
            inner_ciphertext: vec![1, 2, 3, 4],
        };

        let event = NodeEvent::MessageReceived(envelope.clone());
        let cloned = event.clone();

        match (event, cloned) {
            (NodeEvent::MessageReceived(e1), NodeEvent::MessageReceived(e2)) => {
                assert_eq!(e1.message_id, e2.message_id);
            }
            _ => panic!("Expected MessageReceived events"),
        }
    }

    #[test]
    fn test_node_event_error() {
        let event = NodeEvent::Error("test error".to_string());
        match event {
            NodeEvent::Error(msg) => assert_eq!(msg, "test error"),
            _ => panic!("Expected Error event"),
        }
    }
}
