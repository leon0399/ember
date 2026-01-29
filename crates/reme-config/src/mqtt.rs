//! MQTT peer configuration.

use serde::{Deserialize, Serialize};

use crate::PeerCommon;

/// MQTT peer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttPeerConfig {
    /// Common peer fields (label, tier, priority).
    #[serde(flatten)]
    pub common: PeerCommon,

    /// Broker URL (e.g., `<mqtts://broker.example.com:8883>`).
    pub url: String,

    /// Client ID (auto-generated if not set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Topic prefix for messages (default: `reme/v1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic_prefix: Option<String>,

    /// Basic Auth username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Basic Auth password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}
