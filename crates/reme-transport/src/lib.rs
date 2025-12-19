use async_trait::async_trait;
use reme_message::{OuterEnvelope, TombstoneEnvelope};
use thiserror::Error;
use tokio::sync::mpsc;

pub mod composite;
pub mod http;
pub mod http_target;
pub mod pool;
pub mod receiver;
pub mod seen_cache;
pub mod target;
pub mod tls;
pub mod url_auth;

#[cfg(feature = "mqtt")]
pub mod mqtt;
#[cfg(feature = "mqtt")]
pub mod mqtt_receiver;

pub use composite::CompositeTransport;
pub use http::NodeSpec;
pub use http_target::{HttpTarget, HttpTargetConfig};
pub use receiver::{MessageReceiver, ReceiverConfig, ReceiverHandle};
pub use seen_cache::{SeenCache, SharedSeenCache};
pub use target::{
    HealthState, TargetConfig, TargetHealth, TargetId, TargetKind, TransportTarget,
};
pub use pool::{PoolConfig, PoolStrategy, TransportPool};
pub use tls::{
    build_pinning_config, build_pinning_config_single, CertPin, PinParseError, PinningVerifier,
    VerifierBuildError,
};
pub use url_auth::{parse_url_with_auth, ParsedUrl};

#[cfg(feature = "mqtt")]
pub use mqtt::{MqttBrokerSpec, MqttTransport};
#[cfg(feature = "mqtt")]
pub use mqtt_receiver::{MultiBrokerReceiver, MqttReceiver, MqttReceiverConfig, MqttReceiverHandle};

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
