//! Background cleanup task for expired data
//!
//! This module provides a background task that periodically cleans up:
//! - Expired tombstones (after tombstone_delay_secs)
//! - Expired orphan tombstones (after orphan_delay_secs)
//! - Stale rate limit entries (after rate_limit_delay_secs)
//! - Expired messages (implicit via TTL checks on access)
//!
//! **Important**: Cleanup is NOT triggered on message enqueue to avoid
//! latency impact on the hot path. Instead, this background task runs
//! periodically.

use crate::store::MailboxStore;
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
    #[serde(default = "default_tombstone_delay_secs")]
    pub tombstone_delay_secs: u64,

    /// Delay before cleaning orphan tombstones (in seconds)
    /// Orphan tombstones wait for their target message to arrive.
    /// Default: 86400 (24 hours)
    #[serde(default = "default_orphan_delay_secs")]
    pub orphan_delay_secs: u64,

    /// Delay before cleaning stale rate limit entries (in seconds)
    /// Rate limit windows reset after this period.
    /// Default: 3600 (1 hour)
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
            info!("  Tombstone delay: {}s", self.tombstone_delay_secs);
            info!("  Orphan delay: {}s", self.orphan_delay_secs);
            info!("  Rate limit delay: {}s", self.rate_limit_delay_secs);
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
/// let store = Arc::new(MailboxStore::new(1000, 3600));
/// let config = CleanupConfig::default();
/// tokio::spawn(run_cleanup_task(store, config));
/// ```
pub async fn run_cleanup_task(store: Arc<MailboxStore>, config: CleanupConfig) {
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

        // Cleanup tombstones and orphans
        match store.cleanup_tombstones() {
            Ok(n) if n > 0 => info!("Cleaned {} tombstones/orphans", n),
            Ok(_) => debug!("Tombstone cleanup: nothing to clean"),
            Err(e) => warn!("Tombstone cleanup failed: {}", e),
        }

        // Cleanup rate limits
        match store.cleanup_rate_limits() {
            Ok(n) if n > 0 => debug!("Cleaned {} rate limit entries", n),
            Ok(_) => {}
            Err(e) => warn!("Rate limit cleanup failed: {}", e),
        }

        // Cleanup expired messages (explicit sweep)
        match store.cleanup_expired_messages() {
            Ok(n) if n > 0 => info!("Cleaned {} expired messages", n),
            Ok(_) => debug!("Message cleanup: nothing to clean"),
            Err(e) => warn!("Message cleanup failed: {}", e),
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
