//! Unified configuration system for Resilient Messenger.
//!
//! This crate provides shared configuration types used by both client and node applications,
//! enabling transport-agnostic peer configuration with security primitives.

mod peer;
mod security;
mod tier;

pub mod validation;

/// Check if secondary CLI array length mismatches primary, returning a warning if so.
///
/// Used internally by `HttpPeerConfig::from_cli_urls` and `MqttPeerConfig::from_cli_urls`
/// to validate that optional parameter arrays (cert pins, client IDs, auth) match the
/// number of URLs provided.
///
/// # Returns
///
/// `Some(warning_message)` if lengths mismatch, `None` if arrays match or secondary is empty.
pub(crate) fn check_cli_array_mismatch(
    primary_len: usize,
    secondary: Option<&[String]>,
    primary_flag: &str,
    secondary_flag: &str,
) -> Option<String> {
    secondary
        .filter(|s| !s.is_empty() && primary_len != s.len())
        .map(|s| {
            format!(
                "{primary_flag} count ({primary_len}) != {secondary_flag} count ({}), some ignored",
                s.len()
            )
        })
}

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
