use async_trait::async_trait;
use reme_message::{OuterEnvelope, TombstoneEnvelope};
use thiserror::Error;
use tokio::sync::mpsc;

pub mod http;
pub mod receiver;
pub mod tls;
pub mod url_auth;

pub use http::NodeSpec;
pub use receiver::{MessageReceiver, ReceiverConfig, ReceiverHandle};
pub use tls::{CertPin, PinParseError, PinningVerifier, VerifierBuildError};
pub use url_auth::{parse_url_with_auth, ParsedUrl};

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

    #[error("Channel closed")]
    ChannelClosed,

    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    #[error("Certificate pin mismatch for {hostname}: expected {expected}, got {actual}")]
    CertificatePinMismatch {
        hostname: String,
        expected: String,
        actual: String,
    },
}

/// Transport trait for sending messages (MIK-only, no prekeys)
///
/// This trait abstracts the underlying transport mechanism (HTTP, LoRa, BLE, etc.)
/// for outgoing operations. Incoming messages are handled separately via
/// `MessageReceiver` which provides push-based delivery.
///
/// With MIK-only encryption, there are no prekeys to upload or fetch.
/// Each message includes an ephemeral key for stateless ECDH.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Submit an OuterEnvelope to the mailbox
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError>;

    /// Submit a tombstone to acknowledge message receipt
    ///
    /// Tombstones enable cache clearing and prevent duplicate delivery.
    /// They are cryptographically signed by the recipient.
    async fn submit_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), TransportError>;
}

/// Event delivered by the message receiver
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// A message was received
    Message(OuterEnvelope),
    /// An error occurred while fetching
    Error(String),
}

/// Channel for receiving transport events
pub type EventReceiver = mpsc::UnboundedReceiver<TransportEvent>;
pub type EventSender = mpsc::UnboundedSender<TransportEvent>;
