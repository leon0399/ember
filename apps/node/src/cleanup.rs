//! Background cleanup task for expired data
//!
//! This module provides a background task that periodically cleans up:
//! - Expired messages (based on TTL)
//!
//! **Note**: The `enqueue` operation performs lightweight per-mailbox cleanup
//! of expired messages for self-healing. This background task handles global
//! cleanup across all mailboxes periodically.

use crate::persistent_store::PersistentMailboxStore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Configuration for the background cleanup task
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CleanupConfig {
    /// Enable/disable the cleanup task entirely
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// How often to run cleanup (in seconds)
    /// Default: 300 (5 minutes)
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,

    /// Delay before cleaning tombstones after they're stored (in seconds)
    /// This allows time for replication and client retrieval.
    /// Default: 3600 (1 hour)
    /// Note: Currently unused - tombstones pending refactor
    #[serde(default = "default_tombstone_delay_secs")]
    pub tombstone_delay_secs: u64,

    /// Delay before cleaning orphan tombstones (in seconds)
    /// Orphan tombstones wait for their target message to arrive.
    /// Default: 86400 (24 hours)
    /// Note: Currently unused - tombstones pending refactor
    #[serde(default = "default_orphan_delay_secs")]
    pub orphan_delay_secs: u64,

    /// Delay before cleaning stale rate limit entries (in seconds)
    /// Rate limit windows reset after this period.
    /// Default: 3600 (1 hour)
    /// Note: Currently unused - rate limiting pending implementation
    #[serde(default = "default_rate_limit_delay_secs")]
    pub rate_limit_delay_secs: u64,
}

fn default_enabled() -> bool {
    true
}

fn default_interval_secs() -> u64 {
    300 // 5 minutes
}

fn default_tombstone_delay_secs() -> u64 {
    3600 // 1 hour
}

fn default_orphan_delay_secs() -> u64 {
    86400 // 24 hours
}

fn default_rate_limit_delay_secs() -> u64 {
    3600 // 1 hour
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            interval_secs: default_interval_secs(),
            tombstone_delay_secs: default_tombstone_delay_secs(),
            orphan_delay_secs: default_orphan_delay_secs(),
            rate_limit_delay_secs: default_rate_limit_delay_secs(),
        }
    }
}

impl CleanupConfig {
    /// Log the cleanup configuration
    pub fn log_config(&self) {
        if self.enabled {
            info!("Cleanup: enabled");
            info!("  Interval: {}s", self.interval_secs);
        } else {
            info!("Cleanup: disabled");
        }
    }
}

/// Run the background cleanup task
///
/// This function runs indefinitely, periodically cleaning up expired data.
/// It should be spawned as a background task using `tokio::spawn`.
///
/// # Example
///
/// ```ignore
/// let store = Arc::new(PersistentMailboxStore::open("mailbox.db", config)?);
/// let config = CleanupConfig::default();
/// tokio::spawn(run_cleanup_task(store, config));
/// ```
pub async fn run_cleanup_task(store: Arc<PersistentMailboxStore>, config: CleanupConfig) {
    if !config.enabled {
        info!("Cleanup task disabled, exiting");
        return;
    }

    let interval = Duration::from_secs(config.interval_secs);
    info!(
        "Starting cleanup task with {}s interval",
        config.interval_secs
    );

    loop {
        tokio::time::sleep(interval).await;

        // Cleanup expired messages
        match store.cleanup_expired() {
            Ok(n) if n > 0 => info!("Cleaned {} expired messages", n),
            Ok(_) => debug!("Message cleanup: nothing to clean"),
            Err(e) => warn!("Message cleanup failed: {}", e),
        }

        // Checkpoint WAL periodically
        if let Err(e) = store.checkpoint() {
            warn!("WAL checkpoint failed: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CleanupConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval_secs, 300);
        assert_eq!(config.tombstone_delay_secs, 3600);
        assert_eq!(config.orphan_delay_secs, 86400);
        assert_eq!(config.rate_limit_delay_secs, 3600);
    }

    #[test]
    fn test_serde_roundtrip() {
        let config = CleanupConfig {
            enabled: false,
            interval_secs: 60,
            tombstone_delay_secs: 1800,
            orphan_delay_secs: 43200,
            rate_limit_delay_secs: 7200,
        };

        let toml_str = toml::to_string(&config).unwrap();
        let parsed: CleanupConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(parsed.enabled, config.enabled);
        assert_eq!(parsed.interval_secs, config.interval_secs);
        assert_eq!(parsed.tombstone_delay_secs, config.tombstone_delay_secs);
        assert_eq!(parsed.orphan_delay_secs, config.orphan_delay_secs);
        assert_eq!(parsed.rate_limit_delay_secs, config.rate_limit_delay_secs);
    }
}
