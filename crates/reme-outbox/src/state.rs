//! Delivery state types for outbox tracking.

use reme_identity::PublicID;
use reme_message::{ContentId, MessageID};

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
}
