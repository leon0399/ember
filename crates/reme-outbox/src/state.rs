//! Delivery state types for outbox tracking.

use std::collections::HashSet;

use reme_identity::PublicID;
use reme_message::{ContentId, MessageID};

// Re-export delivery types from reme-transport for convenience
pub use reme_transport::{
    DeliveryConfidence, DeliveryResult, DeliveryTier, QuorumStrategy, TargetId, TargetOutcome,
    TargetResult, TierResult, TieredDeliveryConfig,
};

/// Unique identifier for an outbox entry (database row ID)
pub type OutboxEntryId = i64;

/// Identifies a transport instance for attempt tracking.
///
/// Format: `"{type}:{identifier}"` where:
/// - `type`: transport type (http, lora, ble, p2p)
/// - `identifier`: transport-specific identifier (node URL, device ID, etc.)
///
/// Examples:
/// - `"http:node1.example.com"`
/// - `"lora:meshtastic"`
/// - `"ble:direct"`
/// - `"p2p:abcd1234"` (peer's short ID)
pub type TransportId = String;

/// Why a delivery attempt failed.
///
/// Includes `is_transient` flag to help the outbox decide whether to retry.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AttemptError {
    /// Network-level failure (connection refused, timeout, DNS, etc.)
    #[error("network error: {message}")]
    Network {
        message: String,
        /// Whether this error is likely transient (worth retrying)
        is_transient: bool,
    },

    /// Transport rejected the message (validation, rate limit, etc.)
    #[error("transport rejected: {message}")]
    Rejected {
        message: String,
        /// Whether this error is likely transient (worth retrying)
        is_transient: bool,
    },

    /// Transport unavailable (not connected, disabled, etc.)
    #[error("transport unavailable: {message}")]
    Unavailable { message: String },

    /// Serialization/encoding failure
    #[error("encoding error: {message}")]
    Encoding { message: String },

    /// No response within timeout
    #[error("timed out after {timeout_ms}ms")]
    TimedOut { timeout_ms: u64 },
}

impl AttemptError {
    /// Whether this error is likely transient (worth retrying).
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Network { is_transient, .. } => *is_transient,
            Self::Rejected { is_transient, .. } => *is_transient,
            Self::Unavailable { .. } => true, // May become available later
            Self::Encoding { .. } => false,   // Won't fix itself
            Self::TimedOut { .. } => true,
        }
    }

    /// Create a transient network error.
    pub fn network_transient(message: impl Into<String>) -> Self {
        Self::Network {
            message: message.into(),
            is_transient: true,
        }
    }

    /// Create a permanent network error.
    pub fn network_permanent(message: impl Into<String>) -> Self {
        Self::Network {
            message: message.into(),
            is_transient: false,
        }
    }

    /// Create a transient rejection error.
    pub fn rejected_transient(message: impl Into<String>) -> Self {
        Self::Rejected {
            message: message.into(),
            is_transient: true,
        }
    }

    /// Create a permanent rejection error.
    pub fn rejected_permanent(message: impl Into<String>) -> Self {
        Self::Rejected {
            message: message.into(),
            is_transient: false,
        }
    }
}

/// Result of a delivery attempt.
#[derive(Debug, Clone)]
pub enum AttemptResult {
    /// Successfully submitted to transport.
    ///
    /// Note: This means the transport accepted the message, not that
    /// it was delivered to the recipient.
    Sent,
    /// Transport rejected or failed.
    Failed(AttemptError),
}

impl AttemptResult {
    /// Returns true if this attempt was successful.
    pub fn is_sent(&self) -> bool {
        matches!(self, Self::Sent)
    }

    /// Returns the error if this attempt failed.
    pub fn error(&self) -> Option<&AttemptError> {
        match self {
            Self::Sent => None,
            Self::Failed(e) => Some(e),
        }
    }
}

/// Record of a single delivery attempt.
#[derive(Debug, Clone)]
pub struct TransportAttempt {
    /// Which transport was used (e.g., "http:node1.example.com")
    pub transport_id: TransportId,
    /// When this attempt was made (ms since epoch)
    pub attempted_at_ms: u64,
    /// Result of the attempt
    pub result: AttemptResult,
}

/// How delivery was confirmed.
///
/// Extensible enum for different confirmation mechanisms.
#[derive(Debug, Clone)]
pub enum DeliveryConfirmation {
    /// Peer's message included our content_id in their `observed_heads`.
    ///
    /// This is the primary confirmation mechanism using the Merkle DAG.
    Dag {
        /// The content_id of the peer's message that contained our ACK
        observed_in_message_id: ContentId,
    },
    // Future variants:
    // /// Zero-knowledge receipt proving delivery
    // ZkReceipt { receipt_hash: [u8; 16] },
    // /// Direct P2P acknowledgment
    // P2PAck { ack_timestamp_ms: u64 },
}

/// Derived delivery state for UI and logic.
///
/// Computed from attempt history and confirmation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryState {
    /// No attempts yet, waiting for first send
    Pending,
    /// Active attempt within timeout window
    InFlight,
    /// Last attempt failed/timed out, waiting for next retry
    AwaitingRetry,
    /// Delivery confirmed (via DAG or other mechanism)
    Confirmed,
    /// TTL exceeded without confirmation, giving up
    Expired,
}

/// Three-phase tiered delivery model.
///
/// Messages progress through these phases:
/// 1. **Urgent**: Aggressive retry until quorum reached or direct delivery
/// 2. **Distributed**: Periodic maintenance refresh, awaiting recipient ACK
/// 3. **Confirmed**: Recipient acknowledged, ready for cleanup
///
/// Key guarantee: Client NEVER gives up. Message stays in outbox until recipient ACK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TieredDeliveryPhase {
    /// Phase 1: Quorum not yet reached, aggressive retries.
    ///
    /// Full pipeline retry: P2P → Internet → Radio.
    /// Skip already-successful Internet targets.
    Urgent,

    /// Phase 2: Distributed (quorum OR direct delivery), periodic maintenance.
    ///
    /// Full pipeline refresh: P2P → Internet (refresh ALL targets).
    /// Recipient may come online for direct delivery.
    Distributed {
        /// How confident are we in delivery?
        confidence: DeliveryConfidence,
        /// When we reached this phase (ms since epoch)
        reached_at_ms: u64,
        /// Last maintenance refresh time (ms since epoch)
        last_maintenance_ms: Option<u64>,
    },

    /// Phase 3: Recipient confirmed receipt via DAG/tombstone.
    ///
    /// Ready for cleanup after delay.
    Confirmed {
        /// When confirmation was received (ms since epoch)
        confirmed_at_ms: u64,
    },
}

impl TieredDeliveryPhase {
    /// Check if this message is in the urgent phase (needs aggressive retry).
    pub fn is_urgent(&self) -> bool {
        matches!(self, Self::Urgent)
    }

    /// Check if this message is distributed (needs periodic maintenance).
    pub fn is_distributed(&self) -> bool {
        matches!(self, Self::Distributed { .. })
    }

    /// Check if this message is confirmed (ready for cleanup).
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
    }

    /// Get confidence level if distributed.
    pub fn confidence(&self) -> Option<&DeliveryConfidence> {
        match self {
            Self::Distributed { confidence, .. } => Some(confidence),
            _ => None,
        }
    }

    /// Check if maintenance is due based on interval.
    pub fn is_maintenance_due(&self, now_ms: u64, maintenance_interval_ms: u64) -> bool {
        match self {
            Self::Distributed {
                last_maintenance_ms,
                reached_at_ms,
                ..
            } => {
                let last = last_maintenance_ms.unwrap_or(*reached_at_ms);
                now_ms.saturating_sub(last) >= maintenance_interval_ms
            }
            _ => false,
        }
    }
}

/// A message pending delivery confirmation.
#[derive(Debug, Clone)]
pub struct PendingMessage {
    /// Database ID
    pub id: OutboxEntryId,
    /// Recipient's public ID
    pub recipient: PublicID,
    /// Content ID for DAG tracking (used to detect confirmation)
    pub content_id: ContentId,
    /// Wire message ID
    pub message_id: MessageID,
    /// Serialized OuterEnvelope for fast retry
    pub envelope_bytes: Vec<u8>,
    /// Serialized InnerEnvelope for re-encryption if needed
    pub inner_bytes: Vec<u8>,
    /// When the message was created (ms since epoch)
    pub created_at_ms: u64,
    /// TTL expiry (None = no expiry)
    pub expires_at_ms: Option<u64>,
    /// When this entry was marked as expired (None = not expired)
    pub expired_at_ms: Option<u64>,
    /// All delivery attempts
    pub attempts: Vec<TransportAttempt>,
    /// When next retry is allowed (None = immediate)
    pub next_retry_at_ms: Option<u64>,
    /// Confirmation if delivered
    pub confirmation: Option<DeliveryConfirmation>,
    /// Targets that have successfully received the message.
    ///
    /// Used for:
    /// - Skipping already-successful targets in urgent retry
    /// - Tracking quorum progress
    /// - Determining which targets need refresh in maintenance
    pub successful_targets: HashSet<TargetId>,
    /// Current tiered delivery phase.
    ///
    /// Tracks the three-phase delivery model:
    /// 1. Urgent: Aggressive retry until quorum/direct delivery
    /// 2. Distributed: Periodic maintenance, awaiting ACK
    /// 3. Confirmed: Ready for cleanup
    pub tiered_phase: TieredDeliveryPhase,
}

impl PendingMessage {
    /// Compute current delivery state from attempts + confirmation.
    ///
    /// # Arguments
    /// * `now_ms` - Current timestamp in milliseconds
    /// * `attempt_timeout_ms` - How long a "Sent" attempt stays in-flight before timing out
    pub fn state(&self, now_ms: u64, attempt_timeout_ms: u64) -> DeliveryState {
        // Check confirmation first
        if self.confirmation.is_some() {
            return DeliveryState::Confirmed;
        }

        // Check if explicitly marked expired
        if self.expired_at_ms.is_some() {
            return DeliveryState::Expired;
        }

        // Check TTL expiry
        if self.expires_at_ms.map(|e| now_ms > e).unwrap_or(false) {
            return DeliveryState::Expired;
        }

        // Derive state from attempts
        match self.attempts.last() {
            None => DeliveryState::Pending,
            Some(attempt) => match &attempt.result {
                AttemptResult::Sent => {
                    let elapsed = now_ms.saturating_sub(attempt.attempted_at_ms);
                    if elapsed < attempt_timeout_ms {
                        DeliveryState::InFlight
                    } else {
                        DeliveryState::AwaitingRetry
                    }
                }
                AttemptResult::Failed(_) => DeliveryState::AwaitingRetry,
            },
        }
    }

    /// Get the number of attempts made.
    pub fn attempt_count(&self) -> usize {
        self.attempts.len()
    }

    /// Get the number of attempts for a specific transport.
    pub fn attempts_for_transport(&self, transport_prefix: &str) -> usize {
        self.attempts
            .iter()
            .filter(|a| a.transport_id.starts_with(transport_prefix))
            .count()
    }

    /// Check if this message is due for retry.
    pub fn is_due_for_retry(&self, now_ms: u64) -> bool {
        self.next_retry_at_ms.map(|t| t <= now_ms).unwrap_or(true)
    }

    /// Get the last attempt for a specific transport, if any.
    pub fn last_attempt_for(&self, transport_prefix: &str) -> Option<&TransportAttempt> {
        self.attempts
            .iter()
            .rev()
            .find(|a| a.transport_id.starts_with(transport_prefix))
    }

    /// Get the number of successful targets.
    pub fn success_count(&self) -> usize {
        self.successful_targets.len()
    }

    /// Check if a specific target has successfully received the message.
    pub fn is_target_successful(&self, target_id: &TargetId) -> bool {
        self.successful_targets.contains(target_id)
    }

    /// Get failed targets from a set of known targets.
    ///
    /// Returns targets that are NOT in the successful set.
    pub fn failed_targets<'a>(
        &self,
        all_targets: impl Iterator<Item = &'a TargetId>,
    ) -> Vec<TargetId> {
        all_targets
            .filter(|t| !self.successful_targets.contains(*t))
            .cloned()
            .collect()
    }

    /// Check if in urgent phase and due for retry.
    pub fn is_urgent_retry_due(&self, now_ms: u64) -> bool {
        self.tiered_phase.is_urgent()
            && self.confirmation.is_none()
            && self.expired_at_ms.is_none()
            && self.is_due_for_retry(now_ms)
    }

    /// Check if in distributed phase and due for maintenance.
    pub fn is_maintenance_due(&self, now_ms: u64, maintenance_interval_ms: u64) -> bool {
        self.tiered_phase
            .is_maintenance_due(now_ms, maintenance_interval_ms)
            && self.confirmation.is_none()
            && self.expired_at_ms.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pending_message(id: OutboxEntryId) -> PendingMessage {
        PendingMessage {
            id,
            recipient: PublicID::try_from_bytes(&[1u8; 32]).unwrap(),
            content_id: [0u8; 8],
            message_id: MessageID::new(),
            envelope_bytes: vec![],
            inner_bytes: vec![],
            created_at_ms: 1000,
            expires_at_ms: Some(100_000),
            expired_at_ms: None,
            attempts: vec![],
            next_retry_at_ms: None,
            confirmation: None,
            successful_targets: HashSet::new(),
            tiered_phase: TieredDeliveryPhase::Urgent,
        }
    }

    #[test]
    fn test_state_pending() {
        let msg = make_pending_message(1);
        assert_eq!(msg.state(1000, 60_000), DeliveryState::Pending);
    }

    #[test]
    fn test_state_in_flight() {
        let mut msg = make_pending_message(1);
        msg.attempts.push(TransportAttempt {
            transport_id: "http:test".to_string(),
            attempted_at_ms: 1000,
            result: AttemptResult::Sent,
        });

        // Within timeout window
        assert_eq!(msg.state(30_000, 60_000), DeliveryState::InFlight);
    }

    #[test]
    fn test_state_awaiting_retry_timeout() {
        let mut msg = make_pending_message(1);
        msg.attempts.push(TransportAttempt {
            transport_id: "http:test".to_string(),
            attempted_at_ms: 1000,
            result: AttemptResult::Sent,
        });

        // Past timeout window
        assert_eq!(msg.state(70_000, 60_000), DeliveryState::AwaitingRetry);
    }

    #[test]
    fn test_state_awaiting_retry_failed() {
        let mut msg = make_pending_message(1);
        msg.attempts.push(TransportAttempt {
            transport_id: "http:test".to_string(),
            attempted_at_ms: 1000,
            result: AttemptResult::Failed(AttemptError::network_transient("connection refused")),
        });

        assert_eq!(msg.state(2000, 60_000), DeliveryState::AwaitingRetry);
    }

    #[test]
    fn test_state_confirmed() {
        let mut msg = make_pending_message(1);
        msg.confirmation = Some(DeliveryConfirmation::Dag {
            observed_in_message_id: [1u8; 8],
        });

        assert_eq!(msg.state(1000, 60_000), DeliveryState::Confirmed);
    }

    #[test]
    fn test_state_expired() {
        let mut msg = make_pending_message(1);
        msg.expires_at_ms = Some(50_000);

        assert_eq!(msg.state(60_000, 60_000), DeliveryState::Expired);
    }

    #[test]
    fn test_attempt_error_transient() {
        assert!(AttemptError::network_transient("test").is_transient());
        assert!(!AttemptError::network_permanent("test").is_transient());
        assert!(AttemptError::Unavailable { message: "test".into() }.is_transient());
        assert!(!AttemptError::Encoding { message: "test".into() }.is_transient());
        assert!(AttemptError::TimedOut { timeout_ms: 1000 }.is_transient());
    }

    // ========== Tiered Delivery Phase Tests ==========

    #[test]
    fn test_tiered_phase_urgent() {
        let phase = TieredDeliveryPhase::Urgent;
        assert!(phase.is_urgent());
        assert!(!phase.is_distributed());
        assert!(!phase.is_confirmed());
        assert!(phase.confidence().is_none());
    }

    #[test]
    fn test_tiered_phase_distributed() {
        let phase = TieredDeliveryPhase::Distributed {
            confidence: DeliveryConfidence::QuorumReached {
                count: 2,
                required: 2,
            },
            reached_at_ms: 1000,
            last_maintenance_ms: None,
        };
        assert!(!phase.is_urgent());
        assert!(phase.is_distributed());
        assert!(!phase.is_confirmed());
        assert!(phase.confidence().is_some());
    }

    #[test]
    fn test_tiered_phase_confirmed() {
        let phase = TieredDeliveryPhase::Confirmed {
            confirmed_at_ms: 5000,
        };
        assert!(!phase.is_urgent());
        assert!(!phase.is_distributed());
        assert!(phase.is_confirmed());
    }

    #[test]
    fn test_maintenance_due() {
        let phase = TieredDeliveryPhase::Distributed {
            confidence: DeliveryConfidence::QuorumReached {
                count: 2,
                required: 2,
            },
            reached_at_ms: 1000,
            last_maintenance_ms: None,
        };

        // Not due yet (only 1 hour elapsed, need 4 hours)
        let maintenance_interval = 4 * 60 * 60 * 1000; // 4 hours
        assert!(!phase.is_maintenance_due(3_600_000, maintenance_interval)); // 1 hour

        // Due (5 hours elapsed)
        assert!(phase.is_maintenance_due(5 * 3_600_000, maintenance_interval));
    }

    #[test]
    fn test_maintenance_due_with_last_maintenance() {
        let phase = TieredDeliveryPhase::Distributed {
            confidence: DeliveryConfidence::QuorumReached {
                count: 2,
                required: 2,
            },
            reached_at_ms: 1000,
            last_maintenance_ms: Some(10_000_000), // Last maintenance at 10,000 seconds
        };

        let maintenance_interval = 4 * 60 * 60 * 1000; // 4 hours

        // Not due (only 1 hour since last maintenance)
        assert!(!phase.is_maintenance_due(10_000_000 + 3_600_000, maintenance_interval));

        // Due (5 hours since last maintenance)
        assert!(phase.is_maintenance_due(10_000_000 + 5 * 3_600_000, maintenance_interval));
    }

    #[test]
    fn test_successful_targets() {
        let mut msg = make_pending_message(1);
        assert_eq!(msg.success_count(), 0);

        let node1 = TargetId::http("https://node1.example.com");
        let node2 = TargetId::http("https://node2.example.com");
        let node3 = TargetId::http("https://node3.example.com");

        msg.successful_targets.insert(node1.clone());
        msg.successful_targets.insert(node2.clone());

        assert_eq!(msg.success_count(), 2);
        assert!(msg.is_target_successful(&node1));
        assert!(msg.is_target_successful(&node2));
        assert!(!msg.is_target_successful(&node3));
    }

    #[test]
    fn test_failed_targets() {
        let mut msg = make_pending_message(1);

        let node1 = TargetId::http("https://node1.example.com");
        let node2 = TargetId::http("https://node2.example.com");
        let node3 = TargetId::http("https://node3.example.com");

        msg.successful_targets.insert(node1.clone());

        let all_targets = vec![node1.clone(), node2.clone(), node3.clone()];

        let failed = msg.failed_targets(all_targets.iter());
        assert_eq!(failed.len(), 2);
        assert!(failed.contains(&node2));
        assert!(failed.contains(&node3));
    }

    #[test]
    fn test_urgent_retry_due() {
        let mut msg = make_pending_message(1);
        msg.tiered_phase = TieredDeliveryPhase::Urgent;
        msg.next_retry_at_ms = Some(1000);

        // Due for retry
        assert!(msg.is_urgent_retry_due(2000));

        // Not due yet
        assert!(!msg.is_urgent_retry_due(500));

        // Distributed phase - not urgent
        msg.tiered_phase = TieredDeliveryPhase::Distributed {
            confidence: DeliveryConfidence::QuorumReached {
                count: 2,
                required: 2,
            },
            reached_at_ms: 1000,
            last_maintenance_ms: None,
        };
        assert!(!msg.is_urgent_retry_due(2000));
    }

    #[test]
    fn test_maintenance_due_pending_message() {
        let mut msg = make_pending_message(1);
        let maintenance_interval = 4 * 60 * 60 * 1000;

        // Urgent phase - no maintenance
        assert!(!msg.is_maintenance_due(10_000_000, maintenance_interval));

        // Distributed phase - maintenance due
        msg.tiered_phase = TieredDeliveryPhase::Distributed {
            confidence: DeliveryConfidence::QuorumReached {
                count: 2,
                required: 2,
            },
            reached_at_ms: 1000,
            last_maintenance_ms: None,
        };
        assert!(msg.is_maintenance_due(5 * 3_600_000, maintenance_interval));
    }
}
