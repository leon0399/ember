//! HTTP peer configuration.

use serde::{Deserialize, Serialize};

use crate::{ConfiguredTier, PeerCommon};

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

impl HttpPeerConfig {
    /// Create HTTP peer from CLI arguments with default tier/priority.
    ///
    /// Uses standard CLI defaults:
    /// - tier: Quorum
    /// - priority: 100
    /// - label: "CLI HTTP {index + 1}"
    ///
    /// # Arguments
    ///
    /// * `url` - HTTP(S) URL for the peer
    /// * `index` - Zero-based index for label generation
    /// * `cert_pin` - Optional TLS certificate pin
    /// * `username` - Optional Basic Auth username
    /// * `password` - Optional Basic Auth password
    pub fn from_cli(
        url: String,
        index: usize,
        cert_pin: Option<String>,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            common: PeerCommon {
                label: Some(format!("CLI HTTP {}", index + 1)),
                tier: ConfiguredTier::Quorum,
                priority: 100,
            },
            url,
            cert_pin,
            node_pubkey: None,
            username,
            password,
        }
    }

    /// Parse multiple CLI URLs into HTTP peers with optional cert pins and auth.
    ///
    /// Returns peers and optional warning messages for array length mismatches.
    /// The caller should log these warnings appropriately.
    ///
    /// # Arguments
    ///
    /// * `urls` - HTTP(S) URLs to create peers from
    /// * `cert_pins` - Optional certificate pins (matched by index)
    /// * `usernames` - Optional usernames (matched by index)
    /// * `passwords` - Optional passwords (matched by index)
    ///
    /// # Returns
    ///
    /// Tuple of (peers, warnings). Warnings are non-empty if array lengths mismatch.
    pub fn from_cli_urls(
        urls: &[String],
        cert_pins: Option<&[String]>,
        usernames: Option<&[String]>,
        passwords: Option<&[String]>,
    ) -> (Vec<Self>, Vec<String>) {
        // Validate array lengths and collect warnings
        let warnings: Vec<String> = [
            crate::check_cli_array_mismatch(urls.len(), cert_pins, "--http-url", "--http-cert-pin"),
            crate::check_cli_array_mismatch(urls.len(), usernames, "--http-url", "--http-username"),
            crate::check_cli_array_mismatch(urls.len(), passwords, "--http-url", "--http-password"),
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
                    cert_pins.and_then(|p| p.get(i).cloned()),
                    usernames.and_then(|u| u.get(i).cloned()),
                    passwords.and_then(|p| p.get(i).cloned()),
                )
            })
            .collect();

        (peers, warnings)
    }
}
