//! Configuration types for outbox retry behavior.

use std::time::Duration;

use derivative::Derivative;

// =============================================================================
// Default value helpers (for derivative Default)
// =============================================================================

/// 5 minutes - backoff cap for retry delays
const fn default_max_delay() -> Duration {
    Duration::from_secs(5 * 60)
}

/// 7 days in milliseconds - default message TTL
#[allow(clippy::unnecessary_wraps)] // Required for derivative Default macro
const fn default_ttl_ms() -> Option<u64> {
    Some(7 * 24 * 60 * 60 * 1000)
}

/// 1 day in milliseconds - cleanup delay for confirmed/expired entries
const fn default_cleanup_after_ms() -> u64 {
    24 * 60 * 60 * 1000
}

/// 1 minute in milliseconds - in-flight attempt timeout
const fn default_attempt_timeout_ms() -> u64 {
    60 * 1000
}

/// Configuration for retry triggers.
///
/// Controls which events automatically trigger message retries.
#[derive(Debug, Clone, Derivative)]
#[derivative(Default)]
pub struct RetryTriggerConfig {
    /// Timer-based retry check interval.
    ///
    /// - `None`: Timer-based retries disabled
    /// - `Some(duration)`: Check for pending retries every `duration`
    #[derivative(Default(value = "Some(Duration::from_secs(30))"))]
    pub timer: Option<Duration>,

    /// Retry when gap detected in peer's `observed_heads`.
    ///
    /// When we receive a message from a peer and detect they haven't
    /// `ACKed` messages we sent, immediately retry those messages.
    #[derivative(Default(value = "true"))]
    pub on_gap_detected: bool,

    /// Retry when a transport becomes available.
    ///
    /// When a transport (`LoRa`, BLE, P2P) becomes available,
    /// retry pending messages that can use that transport.
    #[derivative(Default(value = "true"))]
    pub on_transport_available: bool,
}

impl RetryTriggerConfig {
    /// Create config with all automatic retries disabled.
    pub fn manual_only() -> Self {
        Self {
            timer: None,
            on_gap_detected: false,
            on_transport_available: false,
        }
    }

    /// Create config with only timer-based retries.
    pub fn timer_only(interval: Duration) -> Self {
        Self {
            timer: Some(interval),
            on_gap_detected: false,
            on_transport_available: false,
        }
    }
}

/// Per-transport retry policy.
///
/// Different transports have different characteristics:
/// - HTTP: fast retry, exponential backoff
/// - `LoRa`: slow retry, longer intervals, mesh propagation
/// - BLE: medium retry, device discovery dependent
#[derive(Debug, Clone, Derivative)]
#[derivative(Default)]
pub struct TransportRetryPolicy {
    /// Initial delay before first retry.
    #[derivative(Default(value = "Duration::from_secs(5)"))]
    pub initial_delay: Duration,

    /// Maximum delay (backoff cap).
    #[derivative(Default(value = "default_max_delay()"))]
    pub max_delay: Duration,

    /// Backoff multiplier (e.g., 2.0 for doubling).
    #[derivative(Default(value = "2.0"))]
    pub backoff_multiplier: f32,

    /// Maximum attempts before giving up on this transport.
    ///
    /// `None` means no limit (keep retrying until TTL).
    pub max_attempts: Option<u32>,
}

impl TransportRetryPolicy {
    /// Create a policy for HTTP transports.
    ///
    /// Fast initial retry with aggressive backoff.
    pub fn http() -> Self {
        Self {
            initial_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(300),
            backoff_multiplier: 2.0,
            max_attempts: None,
        }
    }

    /// Create a policy for LoRa/Meshtastic transports.
    ///
    /// Slower retry with longer intervals due to mesh propagation time.
    pub fn lora() -> Self {
        Self {
            initial_delay: Duration::from_secs(60),
            max_delay: Duration::from_secs(3600), // 1 hour
            backoff_multiplier: 1.5,
            max_attempts: None,
        }
    }

    /// Create a policy for BLE transports.
    ///
    /// Medium retry with device discovery considerations.
    pub fn ble() -> Self {
        Self {
            initial_delay: Duration::from_secs(10),
            max_delay: Duration::from_secs(600), // 10 minutes
            backoff_multiplier: 2.0,
            max_attempts: None,
        }
    }

    /// Create a policy for direct P2P transports.
    ///
    /// Fast retry when peer is directly reachable.
    pub fn p2p() -> Self {
        Self {
            initial_delay: Duration::from_secs(2),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            max_attempts: Some(10),
        }
    }

    /// Calculate the delay for the nth retry attempt.
    #[allow(
        clippy::cast_possible_wrap,      // attempt count won't exceed i32::MAX
        clippy::cast_precision_loss,     // delay calculation doesn't need full precision
        clippy::cast_possible_truncation, // delay capped at max_delay
        clippy::cast_sign_loss           // delay_ms is always positive
    )]
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        let multiplier = self
            .backoff_multiplier
            .powi(attempt.saturating_sub(1) as i32);
        let delay_ms = self.initial_delay.as_millis() as f32 * multiplier;
        let delay = Duration::from_millis(delay_ms as u64);

        delay.min(self.max_delay)
    }

    /// Check if we should give up after the given number of attempts.
    pub fn should_give_up(&self, attempts: u32) -> bool {
        self.max_attempts.is_some_and(|max| attempts >= max)
    }
}

/// Main outbox configuration.
#[derive(Debug, Clone, Derivative)]
#[derivative(Default)]
pub struct OutboxConfig {
    /// Retry trigger configuration.
    pub retry_triggers: RetryTriggerConfig,

    /// Default message TTL in milliseconds.
    ///
    /// `None` means messages never expire.
    #[derivative(Default(value = "default_ttl_ms()"))]
    pub default_ttl_ms: Option<u64>,

    /// How long to keep confirmed/expired entries before cleanup (ms).
    #[derivative(Default(value = "default_cleanup_after_ms()"))]
    pub cleanup_after_ms: u64,

    /// How long a "Sent" attempt stays in-flight before timing out (ms).
    ///
    /// After this, the message transitions from `InFlight` to `AwaitingRetry`.
    #[derivative(Default(value = "default_attempt_timeout_ms()"))]
    pub attempt_timeout_ms: u64,
}

impl OutboxConfig {
    /// Create config with manual-only retries (for testing).
    pub fn manual_only() -> Self {
        Self {
            retry_triggers: RetryTriggerConfig::manual_only(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_policy_delay() {
        let policy = TransportRetryPolicy::default();

        // First attempt (attempt 0) has no delay
        assert_eq!(policy.delay_for_attempt(0), Duration::ZERO);

        // Second attempt (attempt 1) uses initial delay
        assert_eq!(policy.delay_for_attempt(1), Duration::from_secs(5));

        // Third attempt doubles
        assert_eq!(policy.delay_for_attempt(2), Duration::from_secs(10));

        // Fourth attempt doubles again
        assert_eq!(policy.delay_for_attempt(3), Duration::from_secs(20));
    }

    #[test]
    fn test_retry_policy_max_delay() {
        let policy = TransportRetryPolicy {
            initial_delay: Duration::from_secs(10),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            max_attempts: None,
        };

        // Should cap at max_delay
        assert_eq!(policy.delay_for_attempt(10), Duration::from_secs(30));
    }

    #[test]
    fn test_retry_policy_max_attempts() {
        let policy = TransportRetryPolicy {
            max_attempts: Some(5),
            ..Default::default()
        };

        assert!(!policy.should_give_up(4));
        assert!(policy.should_give_up(5));
        assert!(policy.should_give_up(6));
    }

    #[test]
    fn test_retry_policy_no_max_attempts() {
        let policy = TransportRetryPolicy::default();

        assert!(!policy.should_give_up(100));
        assert!(!policy.should_give_up(1000));
    }
}
