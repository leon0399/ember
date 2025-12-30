//! Tiered delivery types with quorum semantics.
//!
//! This module defines the types for the tiered delivery system:
//! - Tier 1 (Direct): Race all ephemeral targets, exit on any success
//! - Tier 2 (Quorum): Broadcast to all stable targets, require quorum
//! - Tier 3 (Best-Effort): Fire-and-forget delivery (future)

use std::time::Duration;

use derivative::Derivative;
use strum::{Display, EnumIter};

use crate::target::TargetId;
use crate::TransportError;

// =============================================================================
// Default value helpers for TieredDeliveryConfig
// =============================================================================

/// 4 hours - maintenance refresh interval
const fn default_maintenance_interval() -> Duration {
    Duration::from_secs(4 * 60 * 60)
}

/// 500ms - direct tier timeout
const fn default_direct_tier_timeout() -> Duration {
    Duration::from_millis(500)
}

/// Error type for invalid quorum strategy configuration.
#[derive(Debug, Clone, PartialEq)]
pub enum QuorumStrategyError {
    /// Invalid fraction value. Must be in range (0.0, 1.0].
    InvalidFraction(f32),
    /// Invalid count value. Must be > 0.
    InvalidCount(u32),
}

impl std::fmt::Display for QuorumStrategyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuorumStrategyError::InvalidFraction(v) => {
                write!(
                    f,
                    "Invalid quorum fraction {}: must be in range (0.0, 1.0]",
                    v
                )
            }
            QuorumStrategyError::InvalidCount(v) => {
                write!(f, "Invalid quorum count {}: must be > 0", v)
            }
        }
    }
}

impl std::error::Error for QuorumStrategyError {}

/// Delivery tiers in priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumIter)]
pub enum DeliveryTier {
    /// Direct delivery to recipient or their peer (mDNS, DHT, Iroh).
    /// Highest priority - if successful, recipient has the message.
    Direct,

    /// Store-and-forward delivery with quorum (HTTP mailboxes, MQTT brokers).
    /// Requires configurable quorum for reliability.
    Quorum,

    /// Best-effort delivery over constrained networks (BLE mesh, LoRa/Meshtastic).
    /// Fire and forget, no confirmation expected.
    BestEffort,
}

/// Quorum strategy for determining delivery success.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum QuorumStrategy {
    /// Any single transport success (legacy behavior).
    #[default]
    Any,

    /// Fixed count: at least N transports must succeed.
    Count(u32),

    /// Fraction of configured stable transports (e.g., 0.5 = majority).
    Fraction(f32),

    /// All configured stable transports must succeed.
    All,
}

impl QuorumStrategy {
    /// Create a new Fraction strategy with validation.
    ///
    /// # Errors
    /// Returns an error if the fraction is not in the range (0.0, 1.0].
    pub fn fraction(f: f32) -> Result<Self, QuorumStrategyError> {
        if f.is_nan() || f.is_infinite() {
            return Err(QuorumStrategyError::InvalidFraction(f));
        }
        if f <= 0.0 || f > 1.0 {
            return Err(QuorumStrategyError::InvalidFraction(f));
        }
        Ok(QuorumStrategy::Fraction(f))
    }

    /// Create a new Count strategy with validation.
    ///
    /// # Errors
    /// Returns an error if count is 0.
    pub fn count(n: u32) -> Result<Self, QuorumStrategyError> {
        if n == 0 {
            return Err(QuorumStrategyError::InvalidCount(n));
        }
        Ok(QuorumStrategy::Count(n))
    }

    /// Validate the quorum strategy.
    ///
    /// # Errors
    /// Returns an error if the strategy contains invalid values.
    pub fn validate(&self) -> Result<(), QuorumStrategyError> {
        match self {
            QuorumStrategy::Any | QuorumStrategy::All => Ok(()),
            QuorumStrategy::Count(n) if *n == 0 => Err(QuorumStrategyError::InvalidCount(*n)),
            QuorumStrategy::Count(_) => Ok(()),
            QuorumStrategy::Fraction(f) if f.is_nan() || f.is_infinite() => {
                Err(QuorumStrategyError::InvalidFraction(*f))
            }
            QuorumStrategy::Fraction(f) if *f <= 0.0 || *f > 1.0 => {
                Err(QuorumStrategyError::InvalidFraction(*f))
            }
            QuorumStrategy::Fraction(_) => Ok(()),
        }
    }

    /// Check if quorum is satisfied given success count and total targets.
    pub fn is_satisfied(&self, success: u32, total: u32) -> bool {
        if total == 0 {
            return false;
        }
        let required = self.required_count(total);
        success >= required
    }

    /// Get the required count for this strategy given total targets.
    ///
    /// Returns 0 when `total` is 0 (you can't require anything from nothing).
    pub fn required_count(&self, total: u32) -> u32 {
        if total == 0 {
            return 0;
        }
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
    ///
    /// Returns `false` when `required == 0` (no quorum targets configured).
    /// This keeps semantics consistent with `DeliveryResult.quorum_reached`.
    pub fn is_quorum_reached(&self) -> bool {
        match self {
            DeliveryConfidence::QuorumReached { count, required } => {
                // Treat "no required quorum" (required == 0) as not reached.
                *required > 0 && *count >= *required
            }
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
    /// Create a successful Direct tier delivery result.
    pub fn direct_delivery(target: TargetId, results: Vec<TargetResult>) -> Self {
        Self {
            quorum_reached: true,
            confidence: DeliveryConfidence::DirectDelivery { target },
            target_results: results,
            completed_tier: Some(DeliveryTier::Direct),
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
#[derive(Debug, Clone, Derivative)]
#[derivative(Default)]
pub struct TieredDeliveryConfig {
    /// Quorum strategy for Quorum tier.
    pub quorum: QuorumStrategy,

    /// Phase 1 (Urgent) retry settings.
    #[derivative(Default(value = "Duration::from_secs(5)"))]
    pub urgent_initial_delay: Duration,
    #[derivative(Default(value = "Duration::from_secs(60)"))]
    pub urgent_max_delay: Duration,
    #[derivative(Default(value = "2.0"))]
    pub urgent_backoff_multiplier: f32,

    /// Phase 2 (Maintenance) settings.
    #[derivative(Default(value = "default_maintenance_interval()"))]
    pub maintenance_interval: Duration,
    #[derivative(Default(value = "true"))]
    pub maintenance_enabled: bool,

    /// Per-tier timeouts (how long to wait before trying next tier).
    #[derivative(Default(value = "default_direct_tier_timeout()"))]
    pub direct_tier_timeout: Duration,
    #[derivative(Default(value = "Duration::from_secs(5)"))]
    pub quorum_tier_timeout: Duration,

    /// Targets to exclude from delivery (used for replication to avoid echo).
    pub excluded_targets: std::collections::HashSet<TargetId>,
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

    /// Set Direct tier timeout.
    pub fn with_direct_timeout(mut self, timeout: Duration) -> Self {
        self.direct_tier_timeout = timeout;
        self
    }

    /// Set Quorum tier timeout.
    pub fn with_quorum_timeout(mut self, timeout: Duration) -> Self {
        self.quorum_tier_timeout = timeout;
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
        let mut tier = TierResult::new(DeliveryTier::Quorum);

        let target1 = TargetId::http("https://node1.example.com");
        let target2 = TargetId::http("https://node2.example.com");
        let target3 = TargetId::http("https://node3.example.com");

        tier.push(TargetResult::success(
            target1.clone(),
            DeliveryTier::Quorum,
            Duration::from_millis(100),
        ));
        tier.push(TargetResult::failed(
            target2.clone(),
            DeliveryTier::Quorum,
            TransportError::Timeout,
        ));
        tier.push(TargetResult::success(
            target3.clone(),
            DeliveryTier::Quorum,
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

        // Edge case: 0/0 should NOT be considered quorum reached
        // (consistent with DeliveryResult.quorum_reached = false for partial results)
        let zero_zero = DeliveryConfidence::QuorumReached {
            count: 0,
            required: 0,
        };
        assert!(
            !zero_zero.is_quorum_reached(),
            "0/0 should not be considered quorum reached"
        );

        // Partial quorum (not enough successes)
        let partial = DeliveryConfidence::QuorumReached {
            count: 1,
            required: 2,
        };
        assert!(
            !partial.is_quorum_reached(),
            "1/2 should not be considered quorum reached"
        );
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
        let config = TieredDeliveryConfig::default().with_excluded_target(excluded.clone());

        assert!(config.is_excluded(&excluded));
        assert!(!config.is_excluded(&TargetId::http("https://other.example.com")));
    }
}
