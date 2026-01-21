//! HTTP peer configuration.

use serde::{Deserialize, Serialize};

use crate::PeerCommon;

/// HTTP peer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpPeerConfig {
    /// Common peer fields (label, tier, priority).
    #[serde(flatten)]
    pub common: PeerCommon,

    /// Peer URL (e.g., `<https://node.example.com:23003>`).
    pub url: String,

    /// TLS certificate pin (format: "spki//sha256/BASE64...").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_pin: Option<String>,

    /// Node public identity (base64-encoded `PublicID` for identity verification).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_pubkey: Option<String>,

    /// Basic Auth username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Basic Auth password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}
