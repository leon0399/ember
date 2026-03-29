//! Common peer configuration types.

use serde::{Deserialize, Serialize};

use crate::ConfiguredTier;

/// Default priority for peers within a tier.
const fn default_priority() -> u16 {
    100
}

/// Common fields for all peer types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCommon {
    /// Human-readable label for this peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Delivery tier assignment.
    #[serde(default)]
    pub tier: ConfiguredTier,

    /// Priority within tier (higher = preferred).
    #[serde(default = "default_priority")]
    pub priority: u16,
}

impl Default for PeerCommon {
    fn default() -> Self {
        Self {
            label: None,
            tier: ConfiguredTier::default(),
            priority: default_priority(),
        }
    }
}

impl PeerCommon {
    /// Normalize the common fields after deserialization.
    ///
    /// Currently filters out empty labels (no value for display).
    pub(crate) fn normalize(mut self) -> Self {
        self.label = self.label.filter(|s| !s.is_empty());
        self
    }
}
