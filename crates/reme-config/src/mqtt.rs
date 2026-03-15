//! MQTT peer configuration.

use serde::{Deserialize, Serialize};

use crate::{ConfiguredTier, PeerCommon};

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

impl MqttPeerConfig {
    /// Create MQTT peer from CLI arguments with default tier/priority.
    ///
    /// Uses standard CLI defaults:
    /// - tier: Quorum
    /// - priority: 100
    /// - label: "CLI MQTT {index + 1}"
    ///
    /// # Arguments
    ///
    /// * `url` - MQTT(S) broker URL
    /// * `index` - Zero-based index for label generation
    /// * `client_id` - Optional MQTT client ID
    /// * `username` - Optional Basic Auth username
    /// * `password` - Optional Basic Auth password
    pub fn from_cli(
        url: String,
        index: usize,
        client_id: Option<String>,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            common: PeerCommon {
                label: Some(format!("CLI MQTT {}", index + 1)),
                tier: ConfiguredTier::Quorum,
                priority: 100,
            },
            url,
            client_id,
            topic_prefix: None,
            username,
            password,
        }
    }

    /// Parse multiple CLI URLs into MQTT peers with optional client IDs and auth.
    ///
    /// Returns peers and optional warning messages for array length mismatches.
    /// The caller should log these warnings appropriately.
    ///
    /// # Arguments
    ///
    /// * `urls` - MQTT(S) broker URLs to create peers from
    /// * `client_ids` - Optional client IDs (matched by index)
    /// * `usernames` - Optional usernames (matched by index)
    /// * `passwords` - Optional passwords (matched by index)
    ///
    /// # Returns
    ///
    /// Tuple of (peers, warnings). Warnings are non-empty if array lengths mismatch.
    pub fn from_cli_urls(
        urls: &[String],
        client_ids: Option<&[String]>,
        usernames: Option<&[String]>,
        passwords: Option<&[String]>,
    ) -> (Vec<Self>, Vec<String>) {
        // Validate array lengths and collect warnings
        let warnings: Vec<String> = [
            crate::check_cli_array_mismatch(
                urls.len(),
                client_ids,
                "--mqtt-url",
                "--mqtt-client-id",
            ),
            crate::check_cli_array_mismatch(urls.len(), usernames, "--mqtt-url", "--mqtt-username"),
            crate::check_cli_array_mismatch(urls.len(), passwords, "--mqtt-url", "--mqtt-password"),
        ]
        .into_iter()
        .flatten()
        .collect();

        let peers = urls
            .iter()
            .enumerate()
            .map(|(i, url)| {
                Self::from_cli(
                    url.clone(),
                    i,
                    client_ids.and_then(|ids| ids.get(i).cloned()),
                    usernames.and_then(|u| u.get(i).cloned()),
                    passwords.and_then(|p| p.get(i).cloned()),
                )
            })
            .collect();

        (peers, warnings)
    }
}
