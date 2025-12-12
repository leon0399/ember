use async_trait::async_trait;
use reme_message::{OuterEnvelope, RoutingKey};
use reme_prekeys::SignedPrekeyBundle;
use thiserror::Error;

pub mod http;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Not found")]
    NotFound,

    #[error("Server error: {0}")]
    ServerError(String),
}

/// Transport trait for sending and receiving messages
///
/// This trait abstracts the underlying transport mechanism (HTTP, LoRa, BLE, etc.)
/// allowing the same message types to be sent over different transports.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Submit an OuterEnvelope to the mailbox
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError>;

    /// Fetch pending messages for a given routing key
    async fn fetch_messages(&self, routing_key: RoutingKey) -> Result<Vec<OuterEnvelope>, TransportError>;

    /// Upload a prekey bundle for an identity
    async fn upload_prekeys(&self, routing_key: RoutingKey, bundle: SignedPrekeyBundle) -> Result<(), TransportError>;

    /// Fetch a prekey bundle for an identity
    async fn fetch_prekeys(&self, routing_key: RoutingKey) -> Result<SignedPrekeyBundle, TransportError>;
}
