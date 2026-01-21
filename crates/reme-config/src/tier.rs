//! Delivery tier configuration.

use serde::{Deserialize, Serialize};

/// Delivery tier for a configured peer.
///
/// This determines the default tier assignment for the peer when it does not match
/// a recipient's direct identity.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfiguredTier {
    /// Store-and-forward tier requiring quorum for delivery confirmation.
    #[default]
    Quorum,

    /// Best-effort delivery tier (fire-and-forget).
    BestEffort,
}
