#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
use async_trait::async_trait;
use ember_message::{OuterEnvelope, SignedAckTombstone};
use thiserror::Error;
use tokio::sync::mpsc;

pub mod composite;
pub mod coordinator;
pub(crate) mod dedup;
pub mod delivery;
pub mod http;
pub(crate) mod http_pagination;
pub mod http_target;
pub mod pool;
pub mod query;
pub mod registry;
pub mod seen_cache;
pub mod target;
pub mod tls;
pub mod url_auth;

#[cfg(feature = "mqtt")]
pub mod mqtt;
#[cfg(feature = "mqtt")]
pub mod mqtt_receiver;
#[cfg(feature = "mqtt")]
pub mod mqtt_target;

#[cfg(feature = "embedded")]
pub mod embedded_target;

pub use composite::{CompositeTransport, CompositeTransportBuilder};
pub use coordinator::{
    CoordinatorConfig, CoordinatorHandle, CoordinatorHealth, RoutingStrategy, TransportCoordinator,
};
pub use delivery::{
    DeliveryConfidence, DeliveryResult, DeliveryTier, QuorumStrategy, QuorumStrategyError,
    TargetOutcome, TargetResult, TierResult, TieredDeliveryConfig,
};
pub use http::NodeSpec;
pub use http_target::{HttpTarget, HttpTargetConfig};
pub use pool::{PoolConfig, PoolStrategy, TransportPool};
pub use query::{HealthSummary, TargetSnapshot, TransportQuery};
pub use registry::{EnrichedSnapshot, EphemeralMeta, TransportRegistry};
pub use seen_cache::{SeenCache, SharedSeenCache};
pub use target::{
    HealthData, HealthState, RawReceipt, TargetCapabilities, TargetConfig, TargetHealth, TargetId,
    TargetKind, TransportTarget,
};
pub use tls::{
    build_pinning_config, build_pinning_config_single, CertPin, PinParseError, PinningVerifier,
    VerifierBuildError,
};
pub use url_auth::{parse_url_with_auth, sanitize_url_for_logging, ParsedUrl};

#[cfg(feature = "mqtt")]
pub use mqtt::{MqttBrokerSpec, MqttTransport};
#[cfg(feature = "mqtt")]
pub use mqtt_receiver::{
    MqttReceiver, MqttReceiverConfig, MqttReceiverHandle, MultiBrokerReceiver,
};
#[cfg(feature = "mqtt")]
pub use mqtt_target::{MqttTarget, MqttTargetConfig};

#[cfg(feature = "embedded")]
pub use embedded_target::{EmbeddedTarget, EmbeddedTargetConfig};

#[derive(Debug, Error, Clone)]
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

    #[error("Request timed out")]
    Timeout,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,
}

impl TransportError {
    /// Check if this error is transient and the operation should be retried.
    ///
    /// Transient errors are temporary failures that may succeed on retry:
    /// - Network errors (connection issues, DNS failures)
    /// - Timeouts
    /// - Server errors (5xx status codes)
    ///
    /// Non-transient errors should not be retried:
    /// - Authentication failures
    /// - Not found (4xx client errors)
    /// - Serialization errors (data issues)
    /// - TLS configuration errors
    /// - Certificate pin mismatches (security failures)
    /// - Channel closed (sender/receiver dropped - permanent state)
    pub const fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Network(_) | Self::Timeout | Self::ServerError(_)
        )
    }
}

/// Transport trait for sending messages (MIK-only, no prekeys)
///
/// This trait abstracts the underlying transport mechanism (HTTP, `LoRa`, BLE, etc.)
/// for outgoing operations. Incoming messages are handled separately via
/// `TransportCoordinator::subscribe()` which provides push-based delivery.
///
/// With MIK-only encryption, there are no prekeys to upload or fetch.
/// Each message includes an ephemeral key for stateless ECDH.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Submit an `OuterEnvelope` to the mailbox
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError>;

    /// Submit a signed ack tombstone (Tombstone V2)
    ///
    /// Enables cache clearing and prevents duplicate delivery.
    /// Uses ECDH-derived ack verification (96 bytes) with O(1) node verification.
    ///
    /// Both sender and recipient can create valid tombstones without
    /// leaking identity information.
    async fn submit_ack_tombstone(
        &self,
        tombstone: SignedAckTombstone,
    ) -> Result<(), TransportError>;
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
