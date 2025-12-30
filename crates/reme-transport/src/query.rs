//! Transport query interface for UI and monitoring.
//!
//! This module provides a read-only view into transport metadata for use by
//! UI frontends (TUI, native GUI, mobile, web), CLI tools, and monitoring systems.
//!
//! The key abstraction is [`TransportQuery`] which allows querying transport
//! state without modifying it, and [`TargetSnapshot`] which provides a
//! point-in-time, cloneable view of target state safe to hold across await points.

use std::time::Duration;

use crate::target::{HealthState, TargetConfig, TargetId, TargetKind, TransportTarget};

/// Read-only view of transport metadata for UI queries.
///
/// This trait is implemented by transport pools and coordinators to expose
/// their internal state to UI layers without coupling them to specific
/// transport implementations.
///
/// # Thread Safety
///
/// All methods are safe to call from any thread. Implementations should
/// not hold locks across method calls; instead, they should take a snapshot
/// of the current state and return it.
pub trait TransportQuery: Send + Sync {
    /// List all targets with their current state.
    ///
    /// Returns a point-in-time snapshot of all targets. The returned
    /// `TargetSnapshot` values are cloneable and safe to hold across
    /// await points or pass between threads.
    fn list_targets(&self) -> Vec<TargetSnapshot>;

    /// Get a summary of the overall health status.
    fn health_summary(&self) -> HealthSummary;

    /// Check if any target is currently available for operations.
    fn has_available(&self) -> bool;
}

/// Point-in-time snapshot of a transport target's state.
///
/// This struct captures all relevant metadata about a target at the moment
/// of query. It is:
/// - **Cloneable**: Safe to store, pass around, or serialize
/// - **Thread-safe**: Can be held across await points without blocking
/// - **Disconnected**: Changes to the actual target are not reflected
///
/// Use this for UI display, monitoring, and logging.
#[derive(Debug, Clone)]
pub struct TargetSnapshot {
    /// Unique identifier for this target.
    pub id: TargetId,

    /// Human-readable label (for display).
    pub label: Option<String>,

    /// Target classification.
    pub kind: TargetKind,

    /// Current health state.
    pub health: HealthState,

    /// Priority for routing (higher = preferred).
    pub priority: u8,

    /// Average latency in milliseconds (0 if unknown).
    pub avg_latency_ms: u32,

    /// Number of consecutive failures.
    pub consecutive_failures: u32,

    /// Time since last successful operation.
    pub since_last_success: Option<Duration>,

    /// Time since last failed operation.
    pub since_last_failure: Option<Duration>,
}

impl TargetSnapshot {
    /// Create a snapshot from a transport target.
    ///
    /// This captures the current state of the target including health data.
    /// The target's internal locks are released before this method returns.
    pub fn from_target<T: TransportTarget>(target: &T) -> Self {
        let config = target.config();
        let health_data = target.health_data();
        Self {
            id: config.id.clone(),
            label: config.label.clone(),
            kind: config.kind,
            health: health_data.state,
            priority: config.priority,
            avg_latency_ms: health_data.avg_latency_ms,
            consecutive_failures: health_data.consecutive_failures,
            since_last_success: health_data.since_last_success,
            since_last_failure: health_data.since_last_failure,
        }
    }

    /// Create a snapshot directly from configuration and health data.
    ///
    /// Use this for embedded or synthetic targets where you have direct
    /// access to the raw data.
    pub fn from_config(
        config: &TargetConfig,
        health: HealthState,
        avg_latency_ms: u32,
        consecutive_failures: u32,
        since_last_success: Option<Duration>,
        since_last_failure: Option<Duration>,
    ) -> Self {
        Self {
            id: config.id.clone(),
            label: config.label.clone(),
            kind: config.kind,
            health,
            priority: config.priority,
            avg_latency_ms,
            consecutive_failures,
            since_last_success,
            since_last_failure,
        }
    }

    /// Check if this target is currently available for operations.
    pub fn is_available(&self) -> bool {
        matches!(self.health, HealthState::Healthy | HealthState::Degraded)
    }

    /// Get a human-readable display label.
    ///
    /// Returns the configured label if present, otherwise the target ID.
    pub fn display_label(&self) -> &str {
        self.label.as_deref().unwrap_or(self.id.as_str())
    }

    /// Get the transport type from the ID (e.g., "http", "mqtt", "embedded").
    pub fn transport_type(&self) -> &str {
        self.id.as_str().split(':').next().unwrap_or("unknown")
    }

    /// Get the URL/address portion of the ID (after the type prefix).
    pub fn address(&self) -> &str {
        self.id
            .as_str()
            .split_once(':')
            .map_or(self.id.as_str(), |(_, addr)| addr)
    }
}

/// Summary of overall health status across all targets.
#[derive(Debug, Clone, Default)]
pub struct HealthSummary {
    /// Total number of targets.
    pub total: usize,
    /// Number of healthy targets.
    pub healthy: usize,
    /// Number of degraded targets.
    pub degraded: usize,
    /// Number of unhealthy targets.
    pub unhealthy: usize,
    /// Number of targets with unknown health (e.g., composite-only without tracking).
    pub unknown: usize,
}

impl HealthSummary {
    /// Create a new empty health summary.
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge another summary into this one.
    pub fn merge(&mut self, other: &HealthSummary) {
        self.total += other.total;
        self.healthy += other.healthy;
        self.degraded += other.degraded;
        self.unhealthy += other.unhealthy;
        self.unknown += other.unknown;
    }

    /// Calculate the percentage of healthy targets.
    pub fn healthy_percentage(&self) -> f32 {
        if self.total == 0 {
            0.0
        } else {
            (self.healthy as f32 / self.total as f32) * 100.0
        }
    }

    /// Check if all targets are healthy.
    pub fn all_healthy(&self) -> bool {
        self.total > 0 && self.healthy == self.total
    }

    /// Check if any target is available (healthy or degraded).
    pub fn any_available(&self) -> bool {
        self.healthy > 0 || self.degraded > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{TargetConfig, TargetId};

    #[test]
    fn test_target_snapshot_from_config() {
        let config =
            TargetConfig::stable(TargetId::http("https://example.com")).with_label("Test Node");

        let snapshot = TargetSnapshot::from_config(
            &config,
            HealthState::Healthy,
            150,
            0,
            Some(Duration::from_secs(5)),
            None,
        );

        assert_eq!(snapshot.label.as_deref(), Some("Test Node"));
        assert_eq!(snapshot.kind, TargetKind::Stable);
        assert_eq!(snapshot.health, HealthState::Healthy);
        assert_eq!(snapshot.avg_latency_ms, 150);
        assert!(snapshot.is_available());
        assert_eq!(snapshot.transport_type(), "http");
    }

    #[test]
    fn test_target_snapshot_display_label() {
        let config = TargetConfig::stable(TargetId::http("https://example.com"));
        let snapshot = TargetSnapshot::from_config(&config, HealthState::Healthy, 0, 0, None, None);

        // No label set, should use ID
        assert!(snapshot.display_label().contains("example.com"));

        // With label
        let config_with_label =
            TargetConfig::stable(TargetId::http("https://example.com")).with_label("Primary");
        let snapshot_with_label =
            TargetSnapshot::from_config(&config_with_label, HealthState::Healthy, 0, 0, None, None);
        assert_eq!(snapshot_with_label.display_label(), "Primary");
    }

    #[test]
    fn test_target_snapshot_address() {
        let config = TargetConfig::stable(TargetId::http("https://example.com:23003/api"));
        let snapshot = TargetSnapshot::from_config(&config, HealthState::Healthy, 0, 0, None, None);

        assert_eq!(snapshot.transport_type(), "http");
        assert_eq!(snapshot.address(), "https://example.com:23003/api");
    }

    #[test]
    fn test_health_summary() {
        let mut summary = HealthSummary {
            total: 5,
            healthy: 3,
            degraded: 1,
            unhealthy: 1,
            unknown: 0,
        };

        assert!(!summary.all_healthy());
        assert!(summary.any_available());
        assert!((summary.healthy_percentage() - 60.0).abs() < 0.001);

        let other = HealthSummary {
            total: 3,
            healthy: 2,
            degraded: 1,
            unhealthy: 0,
            unknown: 0,
        };

        summary.merge(&other);
        assert_eq!(summary.total, 8);
        assert_eq!(summary.healthy, 5);
        assert_eq!(summary.degraded, 2);
        assert_eq!(summary.unhealthy, 1);
    }

    #[test]
    fn test_health_summary_edge_cases() {
        let empty = HealthSummary::new();
        assert_eq!(empty.healthy_percentage(), 0.0);
        assert!(!empty.all_healthy());
        assert!(!empty.any_available());

        let all_healthy = HealthSummary {
            total: 3,
            healthy: 3,
            degraded: 0,
            unhealthy: 0,
            unknown: 0,
        };
        assert!(all_healthy.all_healthy());
        assert!(all_healthy.any_available());
    }
}
