//! Unified configuration system for Resilient Messenger.
//!
//! This crate provides shared configuration types used by both client and node applications,
//! enabling transport-agnostic peer configuration with security primitives.

mod peer;
mod security;
mod tier;

pub mod validation;

#[cfg(feature = "http")]
mod http;

#[cfg(feature = "mqtt")]
mod mqtt;

// Re-exports
pub use peer::PeerCommon;
pub use security::*;
pub use tier::ConfiguredTier;
pub use validation::*;

#[cfg(feature = "http")]
pub use http::HttpPeerConfig;

#[cfg(feature = "mqtt")]
pub use mqtt::MqttPeerConfig;

/// Collection of all peer configurations.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PeersConfig {
    #[cfg(feature = "http")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http: Vec<HttpPeerConfig>,

    #[cfg(feature = "mqtt")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mqtt: Vec<MqttPeerConfig>,
}
