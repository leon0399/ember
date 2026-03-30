//! Background cleanup task for expired data
//!
//! This module provides a background task that periodically cleans up:
//! - Expired messages (based on TTL)
//!
//! **Note**: The `enqueue` operation performs lightweight per-mailbox cleanup
//! of expired messages for self-healing. This background task handles global
//! cleanup across all mailboxes periodically.

use derivative::Derivative;
use ember_node_core::{MailboxStore, PersistentMailboxStore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// 5 minutes - default cleanup interval
const fn default_interval_secs() -> u64 {
    300
}

/// 1 hour - tombstone cleanup delay
const fn default_tombstone_delay_secs() -> u64 {
    3600
}

/// 24 hours - orphan tombstone cleanup delay
const fn default_orphan_delay_secs() -> u64 {
    86400
}

/// 1 hour - rate limit cleanup delay
const fn default_rate_limit_delay_secs() -> u64 {
    3600
}

/// Configuration for the background cleanup task
#[derive(Debug, Clone, Deserialize, Serialize, Derivative)]
#[derivative(Default)]
pub struct CleanupConfig {
    /// Enable/disable the cleanup task entirely
    #[serde(default = "default_enabled")]
    #[derivative(Default(value = "true"))]
    pub enabled: bool,

    /// How often to run cleanup (in seconds)
    /// Default: 300 (5 minutes)
    #[serde(default = "default_interval_secs")]
    #[derivative(Default(value = "default_interval_secs()"))]
    pub interval_secs: u64,

    /// Delay before cleaning tombstones after they're stored (in seconds)
    /// This allows time for replication and client retrieval.
    /// Default: 3600 (1 hour)
    /// Note: Currently unused - tombstones pending refactor
    #[serde(default = "default_tombstone_delay_secs")]
    #[derivative(Default(value = "default_tombstone_delay_secs()"))]
    pub tombstone_delay_secs: u64,

    /// Delay before cleaning orphan tombstones (in seconds)
    /// Orphan tombstones wait for their target message to arrive.
    /// Default: 86400 (24 hours)
    /// Note: Currently unused - tombstones pending refactor
    #[serde(default = "default_orphan_delay_secs")]
    #[derivative(Default(value = "default_orphan_delay_secs()"))]
    pub orphan_delay_secs: u64,

    /// Delay before cleaning stale rate limit entries (in seconds)
    /// Rate limit windows reset after this period.
    /// Default: 3600 (1 hour)
    /// Note: Currently unused - rate limiting pending implementation
    #[serde(default = "default_rate_limit_delay_secs")]
    #[derivative(Default(value = "default_rate_limit_delay_secs()"))]
    pub rate_limit_delay_secs: u64,
}

const fn default_enabled() -> bool {
    true
}

impl CleanupConfig {
    /// Log the cleanup configuration
    pub fn log_config(&self) {
        log_cleanup_config(self.enabled, self.interval_secs);
    }
}

/// Run the background cleanup task
fn log_cleanup_config(enabled: bool, interval_secs: u64) {
    let label = if enabled { "enabled" } else { "disabled" };
    info!(enabled, interval_secs, "Cleanup: {label}");
}

///
/// Periodically cleans up expired data until `cancel` is triggered.
/// Should be spawned as a background task using `tokio::spawn`.
///
/// # Example
///
/// ```ignore
/// let store = Arc::new(PersistentMailboxStore::open("mailbox.db", config)?);
/// let config = CleanupConfig::default();
/// let cancel = CancellationToken::new();
/// tokio::spawn(run_cleanup_task(store, config, cancel.clone()));
/// // later: cancel.cancel();
/// ```
pub async fn run_cleanup_task(
    store: Arc<PersistentMailboxStore>,
    config: CleanupConfig,
    cancel: CancellationToken,
) {
    if !config.enabled {
        return;
    }

    let interval = Duration::from_secs(config.interval_secs);
    cleanup_loop(&store, interval, &cancel).await;
}

async fn cleanup_loop(
    store: &PersistentMailboxStore,
    interval: Duration,
    cancel: &CancellationToken,
) {
    loop {
        if wait_or_cancel(interval, cancel).await {
            break;
        }
        run_cleanup_cycle(store);
    }
}

/// Wait for the next cleanup interval or cancellation.
/// Returns `true` if cancelled, `false` if the interval elapsed.
async fn wait_or_cancel(interval: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        () = tokio::time::sleep(interval) => false,
        () = cancel.cancelled() => true,
    }
}

/// Execute a single cleanup cycle: expire messages and checkpoint WAL.
fn run_cleanup_cycle(store: &PersistentMailboxStore) {
    log_cleanup_result(store.cleanup_expired());
    log_checkpoint_result(store.checkpoint());
}

fn log_cleanup_result(result: Result<usize, ember_node_core::NodeError>) {
    if let Err(e) = result {
        warn!("Message cleanup failed: {e}");
    }
}

fn log_checkpoint_result(result: Result<(), ember_node_core::NodeError>) {
    if let Err(e) = result {
        warn!("WAL checkpoint failed: {e}");
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

    #[tokio::test]
    async fn test_cleanup_task_stops_on_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store_config = ember_node_core::PersistentStoreConfig {
            max_messages_per_mailbox: 100,
            default_ttl_secs: 3600,
        };
        let store = Arc::new(
            ember_node_core::PersistentMailboxStore::open(db_path.to_str().unwrap(), store_config)
                .unwrap(),
        );

        let config = CleanupConfig {
            enabled: true,
            interval_secs: 3600, // 1 hour — task must NOT wait this long
            ..CleanupConfig::default()
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let handle = tokio::spawn(async move {
            run_cleanup_task(store, config, cancel_clone).await;
        });

        // Cancel immediately
        cancel.cancel();

        // Task should exit within 1 second, not wait for the 3600s interval
        let result = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(
            result.is_ok(),
            "cleanup task did not stop promptly on cancel"
        );
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
