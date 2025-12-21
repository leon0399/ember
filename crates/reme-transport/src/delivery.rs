//! Tiered delivery types with quorum semantics.
//!
//! This module defines the types for the tiered delivery system:
//! - Tier 1 (P2P): Race all ephemeral targets, exit on any success
//! - Tier 2 (Internet): Broadcast to all stable targets, require quorum
//! - Tier 3 (Radio): Best effort delivery (future)

use std::time::Duration;

use crate::target::TargetId;
use crate::TransportError;

/// Delivery tiers in priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryTier {
    /// Direct peer-to-peer delivery (mDNS, DHT, Iroh).
    /// Highest priority - if successful, recipient has the message.
    P2P,

    /// Internet-based store-and-forward (HTTP mailboxes, MQTT brokers).
    /// Requires quorum for reliability.
    Internet,

    /// Local radio delivery (BLE mesh, LoRa/Meshtastic).
    /// Best effort, no confirmation expected.
    Radio,
}

/// Quorum strategy for determining delivery success.
#[derive(Debug, Clone, PartialEq)]
pub enum QuorumStrategy {
    /// Any single transport success (legacy behavior).
    Any,

    /// Fixed count: at least N transports must succeed.
    Count(u32),

    /// Fraction of configured stable transports (e.g., 0.5 = majority).
    Fraction(f32),

    /// All configured stable transports must succeed.
    All,
}

impl Default for QuorumStrategy {
    fn default() -> Self {
        // Default to "any" for backward compatibility
        QuorumStrategy::Any
    }
}

impl QuorumStrategy {
    /// Check if quorum is satisfied given success count and total targets.
    pub fn is_satisfied(&self, success: u32, total: u32) -> bool {
        if total == 0 {
            return false;
        }
        let required = self.required_count(total);
        success >= required
    }

    /// Get the required count for this strategy given total targets.
    pub fn required_count(&self, total: u32) -> u32 {
        match self {
            QuorumStrategy::Any => 1,
            QuorumStrategy::Count(n) => (*n).min(total),
            QuorumStrategy::Fraction(f) => {
                let required = (total as f32 * f).ceil() as u32;
                required.max(1).min(total)
            }
            QuorumStrategy::All => total,
        }
    }

    /// Create a smart default based on transport count.
    /// - 1-2 transports: Any
    /// - 3+ transports: Count(2)
    pub fn smart_default(total: u32) -> Self {
        if total <= 2 {
            QuorumStrategy::Any
        } else {
            QuorumStrategy::Count(2)
        }
    }
}

/// Confidence level of message delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryConfidence {
    /// Message reached N stable transports (store-and-forward).
    /// Recipient will get it when they poll.
    QuorumReached {
        /// Number of transports that accepted the message.
        count: u32,
        /// Required quorum count.
        required: u32,
    },

    /// Message delivered directly to recipient or their peer.
    /// Highest confidence - recipient (or their proxy) has it.
    DirectDelivery {
        /// The target that accepted the direct delivery.
        target: TargetId,
    },
}

impl DeliveryConfidence {
    /// Check if this is direct delivery (higher confidence than quorum).
    pub fn is_direct(&self) -> bool {
        matches!(self, DeliveryConfidence::DirectDelivery { .. })
    }

    /// Check if quorum was reached.
    pub fn is_quorum_reached(&self) -> bool {
        match self {
            DeliveryConfidence::QuorumReached { count, required } => count >= required,
            DeliveryConfidence::DirectDelivery { .. } => true,
        }
    }
}

/// Outcome of a delivery attempt to a single target.
#[derive(Debug, Clone)]
pub enum TargetOutcome {
    /// Target accepted the message.
    Success,

    /// Target rejected or failed.
    Failed(TransportError),

    /// Target was skipped (unhealthy or already succeeded).
    Skipped,

    /// Target timed out.
    Timeout,
}

impl TargetOutcome {
    /// Check if this outcome represents success.
    pub fn is_success(&self) -> bool {
        matches!(self, TargetOutcome::Success)
    }

    /// Check if this outcome represents a failure that should be retried.
    pub fn should_retry(&self) -> bool {
        match self {
            TargetOutcome::Success => false,
            TargetOutcome::Failed(e) => e.is_transient(),
            TargetOutcome::Skipped => false,
            TargetOutcome::Timeout => true,
        }
    }
}

/// Result of a delivery attempt to a single target.
#[derive(Debug, Clone)]
pub struct TargetResult {
    /// The target that was attempted.
    pub target_id: TargetId,

    /// Which tier this target belongs to.
    pub tier: DeliveryTier,

    /// The outcome of the attempt.
    pub outcome: TargetOutcome,

    /// Latency of the attempt (if completed).
    pub latency: Option<Duration>,
}

impl TargetResult {
    /// Create a success result.
    pub fn success(target_id: TargetId, tier: DeliveryTier, latency: Duration) -> Self {
        Self {
            target_id,
            tier,
            outcome: TargetOutcome::Success,
            latency: Some(latency),
        }
    }

    /// Create a failure result.
    pub fn failed(target_id: TargetId, tier: DeliveryTier, error: TransportError) -> Self {
        Self {
            target_id,
            tier,
            outcome: TargetOutcome::Failed(error),
            latency: None,
        }
    }

    /// Create a skipped result.
    pub fn skipped(target_id: TargetId, tier: DeliveryTier) -> Self {
        Self {
            target_id,
            tier,
            outcome: TargetOutcome::Skipped,
            latency: None,
        }
    }

    /// Create a timeout result.
    pub fn timeout(target_id: TargetId, tier: DeliveryTier) -> Self {
        Self {
            target_id,
            tier,
            outcome: TargetOutcome::Timeout,
            latency: None,
        }
    }
}

/// Result of attempting a single delivery tier.
#[derive(Debug, Clone)]
pub struct TierResult {
    /// Which tier was attempted.
    pub tier: DeliveryTier,

    /// Results from each target in this tier.
    pub results: Vec<TargetResult>,
}

impl TierResult {
    /// Create a new tier result.
    pub fn new(tier: DeliveryTier) -> Self {
        Self {
            tier,
            results: Vec::new(),
        }
    }

    /// Add a target result.
    pub fn push(&mut self, result: TargetResult) {
        self.results.push(result);
    }

    /// Check if any target succeeded.
    pub fn any_success(&self) -> bool {
        self.results.iter().any(|r| r.outcome.is_success())
    }

    /// Count successful targets.
    pub fn success_count(&self) -> u32 {
        self.results
            .iter()
            .filter(|r| r.outcome.is_success())
            .count() as u32
    }

    /// Get the first successful target ID.
    pub fn first_success_target(&self) -> Option<TargetId> {
        self.results
            .iter()
            .find(|r| r.outcome.is_success())
            .map(|r| r.target_id.clone())
    }

    /// Get all successful target IDs.
    pub fn successful_targets(&self) -> impl Iterator<Item = &TargetId> {
        self.results
            .iter()
            .filter(|r| r.outcome.is_success())
            .map(|r| &r.target_id)
    }

    /// Get all failed target IDs.
    pub fn failed_targets(&self) -> impl Iterator<Item = &TargetId> {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, TargetOutcome::Failed(_) | TargetOutcome::Timeout))
            .map(|r| &r.target_id)
    }
}

/// Result of a full delivery attempt through all tiers.
#[derive(Debug, Clone)]
pub struct DeliveryResult {
    /// Whether quorum was reached (or direct delivery succeeded).
    pub quorum_reached: bool,

    /// Confidence level of delivery.
    pub confidence: DeliveryConfidence,

    /// Per-target results from all attempted tiers.
    pub target_results: Vec<TargetResult>,

    /// Which tier completed the delivery (if successful).
    pub completed_tier: Option<DeliveryTier>,
}

impl DeliveryResult {
    /// Create a successful P2P delivery result.
    pub fn direct_delivery(target: TargetId, results: Vec<TargetResult>) -> Self {
        Self {
            quorum_reached: true,
            confidence: DeliveryConfidence::DirectDelivery { target },
            target_results: results,
            completed_tier: Some(DeliveryTier::P2P),
        }
    }

    /// Create a successful quorum delivery result.
    pub fn quorum_delivery(
        count: u32,
        required: u32,
        tier: DeliveryTier,
        results: Vec<TargetResult>,
    ) -> Self {
        Self {
            quorum_reached: true,
            confidence: DeliveryConfidence::QuorumReached { count, required },
            target_results: results,
            completed_tier: Some(tier),
        }
    }

    /// Create a partial (quorum not reached) delivery result.
    pub fn partial(count: u32, required: u32, results: Vec<TargetResult>) -> Self {
        Self {
            quorum_reached: false,
            confidence: DeliveryConfidence::QuorumReached { count, required },
            target_results: results,
            completed_tier: None,
        }
    }

    /// Count successful targets.
    pub fn success_count(&self) -> u32 {
        self.target_results
            .iter()
            .filter(|r| r.outcome.is_success())
            .count() as u32
    }

    /// Get all successful target IDs.
    pub fn successful_targets(&self) -> impl Iterator<Item = &TargetId> {
        self.target_results
            .iter()
            .filter(|r| r.outcome.is_success())
            .map(|r| &r.target_id)
    }

    /// Get all failed target IDs.
    pub fn failed_targets(&self) -> impl Iterator<Item = &TargetId> {
        self.target_results
            .iter()
            .filter(|r| matches!(r.outcome, TargetOutcome::Failed(_) | TargetOutcome::Timeout))
            .map(|r| &r.target_id)
    }

    /// Get successful targets as owned set.
    pub fn successful_target_set(&self) -> std::collections::HashSet<TargetId> {
        self.successful_targets().cloned().collect()
    }
}

/// Configuration for tiered delivery.
#[derive(Debug, Clone)]
pub struct TieredDeliveryConfig {
    /// Quorum strategy for Internet tier.
    pub quorum: QuorumStrategy,

    /// Phase 1 (Urgent) retry settings.
    pub urgent_initial_delay: Duration,
    pub urgent_max_delay: Duration,
    pub urgent_backoff_multiplier: f32,

    /// Phase 2 (Maintenance) settings.
    pub maintenance_interval: Duration,
    pub maintenance_enabled: bool,

    /// Per-tier timeouts (how long to wait before trying next tier).
    pub p2p_tier_timeout: Duration,
    pub internet_tier_timeout: Duration,

    /// Targets to exclude from delivery (used for replication to avoid echo).
    pub excluded_targets: std::collections::HashSet<TargetId>,
}

impl Default for TieredDeliveryConfig {
    fn default() -> Self {
        Self {
            quorum: QuorumStrategy::default(),
            urgent_initial_delay: Duration::from_secs(5),
            urgent_max_delay: Duration::from_secs(60),
            urgent_backoff_multiplier: 2.0,
            maintenance_interval: Duration::from_secs(4 * 60 * 60), // 4 hours
            maintenance_enabled: true,
            p2p_tier_timeout: Duration::from_millis(500),
            internet_tier_timeout: Duration::from_secs(5),
            excluded_targets: std::collections::HashSet::new(),
        }
    }
}

impl TieredDeliveryConfig {
    /// Create config with a specific quorum strategy.
    pub fn with_quorum(mut self, quorum: QuorumStrategy) -> Self {
        self.quorum = quorum;
        self
    }

    /// Add a target to exclude from delivery.
    pub fn with_excluded_target(mut self, target: TargetId) -> Self {
        self.excluded_targets.insert(target);
        self
    }

    /// Set P2P tier timeout.
    pub fn with_p2p_timeout(mut self, timeout: Duration) -> Self {
        self.p2p_tier_timeout = timeout;
        self
    }

    /// Set Internet tier timeout.
    pub fn with_internet_timeout(mut self, timeout: Duration) -> Self {
        self.internet_tier_timeout = timeout;
        self
    }

    /// Set maintenance interval.
    pub fn with_maintenance_interval(mut self, interval: Duration) -> Self {
        self.maintenance_interval = interval;
        self
    }

    /// Disable maintenance refreshes.
    pub fn without_maintenance(mut self) -> Self {
        self.maintenance_enabled = false;
        self
    }

    /// Check if a target should be excluded.
    pub fn is_excluded(&self, target: &TargetId) -> bool {
        self.excluded_targets.contains(target)
    }

    /// Calculate next retry delay using exponential backoff.
    pub fn calculate_retry_delay(&self, attempt: u32) -> Duration {
        let delay = self.urgent_initial_delay.as_secs_f32()
            * self.urgent_backoff_multiplier.powi(attempt as i32);
        let capped = delay.min(self.urgent_max_delay.as_secs_f32());
        Duration::from_secs_f32(capped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_any() {
        let strategy = QuorumStrategy::Any;
        assert!(strategy.is_satisfied(1, 5));
        assert!(strategy.is_satisfied(5, 5));
        assert!(!strategy.is_satisfied(0, 5));
        assert_eq!(strategy.required_count(5), 1);
    }

    #[test]
    fn test_quorum_count() {
        let strategy = QuorumStrategy::Count(2);
        assert!(!strategy.is_satisfied(1, 5));
        assert!(strategy.is_satisfied(2, 5));
        assert!(strategy.is_satisfied(3, 5));
        assert_eq!(strategy.required_count(5), 2);

        // Count is capped at total
        let strategy = QuorumStrategy::Count(10);
        assert_eq!(strategy.required_count(3), 3);
    }

    #[test]
    fn test_quorum_fraction() {
        let strategy = QuorumStrategy::Fraction(0.5);
        assert!(!strategy.is_satisfied(2, 5)); // 2/5 = 40% < 50%
        assert!(strategy.is_satisfied(3, 5)); // 3/5 = 60% >= 50%
        assert_eq!(strategy.required_count(5), 3); // ceil(5 * 0.5) = 3

        let strategy = QuorumStrategy::Fraction(0.34);
        assert_eq!(strategy.required_count(3), 2); // ceil(3 * 0.34) = ceil(1.02) = 2
    }

    #[test]
    fn test_quorum_all() {
        let strategy = QuorumStrategy::All;
        assert!(!strategy.is_satisfied(4, 5));
        assert!(strategy.is_satisfied(5, 5));
        assert_eq!(strategy.required_count(5), 5);
    }

    #[test]
    fn test_smart_default() {
        assert_eq!(QuorumStrategy::smart_default(1), QuorumStrategy::Any);
        assert_eq!(QuorumStrategy::smart_default(2), QuorumStrategy::Any);
        assert_eq!(QuorumStrategy::smart_default(3), QuorumStrategy::Count(2));
        assert_eq!(QuorumStrategy::smart_default(10), QuorumStrategy::Count(2));
    }

    #[test]
    fn test_tier_result() {
        let mut tier = TierResult::new(DeliveryTier::Internet);

        let target1 = TargetId::http("https://node1.example.com");
        let target2 = TargetId::http("https://node2.example.com");
        let target3 = TargetId::http("https://node3.example.com");

        tier.push(TargetResult::success(
            target1.clone(),
            DeliveryTier::Internet,
            Duration::from_millis(100),
        ));
        tier.push(TargetResult::failed(
            target2.clone(),
            DeliveryTier::Internet,
            TransportError::Timeout,
        ));
        tier.push(TargetResult::success(
            target3.clone(),
            DeliveryTier::Internet,
            Duration::from_millis(150),
        ));

        assert!(tier.any_success());
        assert_eq!(tier.success_count(), 2);
        assert_eq!(tier.first_success_target(), Some(target1.clone()));

        let successful: Vec<_> = tier.successful_targets().collect();
        assert_eq!(successful.len(), 2);

        let failed: Vec<_> = tier.failed_targets().collect();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0], &target2);
    }

    #[test]
    fn test_delivery_confidence() {
        let quorum = DeliveryConfidence::QuorumReached {
            count: 2,
            required: 2,
        };
        assert!(!quorum.is_direct());
        assert!(quorum.is_quorum_reached());

        let direct = DeliveryConfidence::DirectDelivery {
            target: TargetId::http("https://peer.local"),
        };
        assert!(direct.is_direct());
        assert!(direct.is_quorum_reached());
    }

    #[test]
    fn test_retry_delay_calculation() {
        let config = TieredDeliveryConfig::default();

        // First attempt: 5s
        assert_eq!(config.calculate_retry_delay(0), Duration::from_secs(5));

        // Second attempt: 10s
        assert_eq!(config.calculate_retry_delay(1), Duration::from_secs(10));

        // Third attempt: 20s
        assert_eq!(config.calculate_retry_delay(2), Duration::from_secs(20));

        // Fourth attempt: 40s
        assert_eq!(config.calculate_retry_delay(3), Duration::from_secs(40));

        // Fifth attempt: capped at 60s
        assert_eq!(config.calculate_retry_delay(4), Duration::from_secs(60));

        // Further attempts stay at cap
        assert_eq!(config.calculate_retry_delay(10), Duration::from_secs(60));
    }

    #[test]
    fn test_excluded_targets() {
        let excluded = TargetId::http("https://excluded.example.com");
        let config =
            TieredDeliveryConfig::default().with_excluded_target(excluded.clone());

        assert!(config.is_excluded(&excluded));
        assert!(!config.is_excluded(&TargetId::http("https://other.example.com")));
    }
}
