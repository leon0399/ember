//! reme-outbox: Client-side outbox for resilient message delivery
//!
//! This crate provides:
//! - Persistent tracking of outgoing messages until delivery confirmation
//! - Per-transport attempt tracking with configurable retry policies
//! - DAG-based implicit confirmation via peer's `observed_heads`
//! - Extensible confirmation model for future ZK receipts, P2P ACKs
//!
//! # Architecture
//!
//! The main entry point is [`ClientOutbox`], which coordinates:
//! - Message enqueueing with envelope storage for fast retry
//! - Per-transport retry scheduling with configurable policies
//! - DAG-based delivery confirmation (peer's observed_heads includes our content_id)
//! - Gap detection and automatic retry triggering
//!
//! # Example
//!
//! ```ignore
//! use reme_outbox::{ClientOutbox, OutboxConfig, TransportRetryPolicy};
//!
//! // Create outbox with storage backend
//! let outbox = ClientOutbox::new(storage, OutboxConfig::default());
//!
//! // Configure transport-specific retry policies
//! outbox.set_transport_policy("lora", TransportRetryPolicy::lora());
//! outbox.set_transport_policy("ble", TransportRetryPolicy::ble());
//!
//! // Enqueue a message
//! let entry_id = outbox.enqueue(&recipient, content_id, message_id, &envelope, &inner, None)?;
//!
//! // Record attempt result
//! outbox.record_attempt(entry_id, "http:node1.example.com", AttemptResult::Sent)?;
//!
//! // When peer message arrives, check for confirmations
//! outbox.on_peer_message_received(&peer_id, &observed_heads, received_content_id)?;
//! ```

pub mod config;
pub mod state;
pub mod store;

pub use config::*;
pub use state::*;
pub use store::*;

use reme_identity::PublicID;
use reme_message::ContentId;
use std::collections::HashMap;
use std::time::Duration;

/// Client-side outbox coordinator for resilient message delivery.
///
/// The `ClientOutbox` is the main entry point for the outbox subsystem.
/// It manages message delivery lifecycle including:
///
/// - Enqueueing messages with stored envelopes for retry
/// - Tracking per-transport delivery attempts
/// - Computing retry schedules based on transport policies
/// - Detecting delivery confirmation via DAG (observed_heads)
/// - Finding messages that need retry due to gaps
///
/// # Thread Safety
///
/// Most `ClientOutbox` operations use `&self` with interior mutability handled
/// by the storage backend. Only `set_transport_policy` requires `&mut self`.
pub struct ClientOutbox<S: OutboxStore> {
    /// Storage backend (implements OutboxStore)
    store: S,
    /// Outbox configuration
    config: OutboxConfig,
    /// Per-transport retry policies (keyed by transport prefix)
    transport_policies: HashMap<String, TransportRetryPolicy>,
}

impl<S: OutboxStore> ClientOutbox<S> {
    /// Create a new outbox coordinator.
    ///
    /// # Arguments
    /// * `store` - Storage backend implementing [`OutboxStore`]
    /// * `config` - Outbox configuration
    pub fn new(store: S, config: OutboxConfig) -> Self {
        Self {
            store,
            config,
            transport_policies: HashMap::new(),
        }
    }

    /// Set retry policy for a transport type.
    ///
    /// # Arguments
    /// * `transport_prefix` - Transport type prefix (e.g., "http", "lora", "ble", "p2p")
    /// * `policy` - Retry policy for this transport type
    ///
    /// # Example
    ///
    /// ```ignore
    /// outbox.set_transport_policy("lora", TransportRetryPolicy::lora());
    /// outbox.set_transport_policy("ble", TransportRetryPolicy::ble());
    /// ```
    pub fn set_transport_policy(&mut self, transport_prefix: &str, policy: TransportRetryPolicy) {
        self.transport_policies
            .insert(transport_prefix.to_string(), policy);
    }

    /// Get retry policy for a transport.
    ///
    /// Returns the policy for the transport prefix, or the default policy if none is set.
    pub fn get_transport_policy(&self, transport_id: &str) -> &TransportRetryPolicy {
        // Extract prefix from transport_id (e.g., "http:node1" -> "http")
        let prefix = transport_id.split(':').next().unwrap_or(transport_id);

        self.transport_policies
            .get(prefix)
            .unwrap_or_else(|| {
                // Check for full transport_id match as fallback
                self.transport_policies
                    .get(transport_id)
                    .unwrap_or(&DEFAULT_RETRY_POLICY)
            })
    }

    /// Get current configuration.
    pub fn config(&self) -> &OutboxConfig {
        &self.config
    }

    /// Get reference to the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Enqueue a new message for delivery.
    ///
    /// Stores both the outer envelope (for fast retry) and inner envelope
    /// (for re-encryption if needed, e.g., different transport).
    ///
    /// # Arguments
    /// * `recipient` - Recipient's public ID
    /// * `content_id` - Content ID for DAG tracking
    /// * `message_id` - Wire message ID
    /// * `envelope_bytes` - Serialized OuterEnvelope
    /// * `inner_bytes` - Serialized InnerEnvelope
    /// * `ttl_ms` - Optional TTL override (uses config default if None)
    ///
    /// # Returns
    /// The database ID for the new outbox entry
    pub fn enqueue(
        &self,
        recipient: &PublicID,
        content_id: ContentId,
        message_id: reme_message::MessageID,
        envelope_bytes: &[u8],
        inner_bytes: &[u8],
        ttl_ms: Option<u64>,
    ) -> Result<OutboxEntryId, S::Error> {
        let now_ms = now_ms();
        let expires_at_ms = ttl_ms
            .or(self.config.default_ttl_ms)
            .map(|ttl| now_ms + ttl);

        self.store.outbox_enqueue(
            recipient,
            content_id,
            message_id,
            envelope_bytes,
            inner_bytes,
            expires_at_ms,
        )
    }

    /// Get messages that are ready for retry.
    ///
    /// Returns messages where:
    /// - Not confirmed
    /// - Not expired
    /// - `next_retry_at_ms <= now` (or no retry scheduled yet)
    pub fn get_ready_for_retry(&self) -> Result<Vec<PendingMessage>, S::Error> {
        let now = now_ms();
        self.store.outbox_get_due_for_retry(now)
    }

    /// Get pending messages for a specific recipient.
    pub fn get_pending_for(&self, recipient: &PublicID) -> Result<Vec<PendingMessage>, S::Error> {
        self.store.outbox_get_for_recipient(recipient)
    }

    /// Get all pending messages (for diagnostics/UI).
    pub fn get_all_pending(&self) -> Result<Vec<PendingMessage>, S::Error> {
        self.store.outbox_get_pending()
    }

    /// Get a specific outbox entry by ID.
    pub fn get_by_id(&self, entry_id: OutboxEntryId) -> Result<Option<PendingMessage>, S::Error> {
        self.store.outbox_get_by_id(entry_id)
    }

    /// Get entry by content_id (for DAG confirmation lookup).
    pub fn get_by_content_id(
        &self,
        content_id: ContentId,
    ) -> Result<Option<PendingMessage>, S::Error> {
        self.store.outbox_get_by_content_id(content_id)
    }

    /// Record a delivery attempt.
    ///
    /// Updates the outbox entry with the attempt result and schedules
    /// the next retry based on the transport's retry policy.
    ///
    /// # Arguments
    /// * `entry_id` - Outbox entry ID
    /// * `transport_id` - Transport identifier (e.g., "http:node1.example.com")
    /// * `result` - Result of the attempt
    pub fn record_attempt(
        &self,
        entry_id: OutboxEntryId,
        transport_id: &str,
        result: AttemptResult,
    ) -> Result<(), S::Error> {
        let now = now_ms();
        let attempt = TransportAttempt {
            transport_id: transport_id.to_string(),
            attempted_at_ms: now,
            result: result.clone(),
        };

        // Calculate next retry time
        let next_retry_at_ms = match &result {
            AttemptResult::Sent => {
                // For successful sends, schedule retry after attempt timeout
                // (in case we don't get DAG confirmation)
                Some(now + self.config.attempt_timeout_ms)
            }
            AttemptResult::Failed(error) => {
                if error.is_transient() {
                    // Get attempt count for this transport to calculate backoff
                    let pending = self.store.outbox_get_by_id(entry_id)?;
                    let attempt_count = pending
                        .map(|p| p.attempts_for_transport(transport_id.split(':').next().unwrap_or(transport_id)))
                        .unwrap_or(0) as u32;

                    let policy = self.get_transport_policy(transport_id);
                    if policy.should_give_up(attempt_count + 1) {
                        // No more retries for this transport
                        None
                    } else {
                        let delay = policy.delay_for_attempt(attempt_count + 1);
                        Some(now + delay.as_millis() as u64)
                    }
                } else {
                    // Non-transient error - no automatic retry
                    None
                }
            }
        };

        self.store
            .outbox_record_attempt(entry_id, &attempt, next_retry_at_ms)
    }

    /// Process a received message from a peer for potential confirmations.
    ///
    /// When we receive a message, check if the peer's `observed_heads` includes
    /// any of our pending messages' content_ids. If so, mark them as confirmed.
    ///
    /// # Arguments
    /// * `from` - Sender's public ID
    /// * `observed_heads` - Content IDs the sender has observed from us
    /// * `received_content_id` - Content ID of the received message (for DAG confirmation tracking)
    ///
    /// # Returns
    /// List of entry IDs that were confirmed by this message
    pub fn on_peer_message_received(
        &self,
        from: &PublicID,
        observed_heads: &[ContentId],
        received_content_id: ContentId,
    ) -> Result<Vec<OutboxEntryId>, S::Error> {
        let mut confirmed = Vec::new();

        // Look up each observed_head to see if it's one of our pending messages
        for &content_id in observed_heads {
            if let Some(pending) = self.store.outbox_get_by_content_id(content_id)? {
                // Verify recipient matches (sanity check)
                if pending.recipient == *from && pending.confirmation.is_none() {
                    let confirmation = DeliveryConfirmation::Dag {
                        observed_in_message_id: received_content_id,
                    };
                    self.store.outbox_mark_confirmed(pending.id, &confirmation)?;
                    confirmed.push(pending.id);
                }
            }
        }

        Ok(confirmed)
    }

    /// Find messages the peer hasn't acknowledged.
    ///
    /// Compares our pending messages for this recipient against their
    /// reported `observed_heads` to find gaps.
    ///
    /// # Arguments
    /// * `recipient` - Peer's public ID
    /// * `peer_observed_heads` - Content IDs the peer has observed from us
    ///
    /// # Returns
    /// List of pending message IDs that the peer hasn't acknowledged
    pub fn find_unacked_messages(
        &self,
        recipient: &PublicID,
        peer_observed_heads: &[ContentId],
    ) -> Result<Vec<OutboxEntryId>, S::Error> {
        let pending = self.store.outbox_get_for_recipient(recipient)?;

        // Find messages whose content_id is not in peer's observed_heads
        let observed_set: std::collections::HashSet<_> = peer_observed_heads.iter().collect();

        let unacked: Vec<_> = pending
            .into_iter()
            .filter(|msg| {
                msg.confirmation.is_none() && !observed_set.contains(&msg.content_id)
            })
            .map(|msg| msg.id)
            .collect();

        Ok(unacked)
    }

    /// Schedule immediate retry for specific entries.
    ///
    /// Use this when:
    /// - Gap detection finds unacknowledged messages
    /// - User manually requests retry
    /// - Transport becomes available
    ///
    /// # Arguments
    /// * `entry_ids` - Entry IDs to schedule for immediate retry
    pub fn schedule_immediate_retry(&self, entry_ids: &[OutboxEntryId]) -> Result<(), S::Error> {
        if entry_ids.is_empty() {
            return Ok(());
        }
        let now = now_ms();
        self.store.outbox_schedule_retry(entry_ids, now)
    }

    /// Calculate the next retry time for a transport.
    ///
    /// # Arguments
    /// * `transport_id` - Transport identifier
    /// * `attempt_count` - Number of previous attempts
    ///
    /// # Returns
    /// Duration until next retry, or None if max attempts exceeded
    pub fn calculate_next_retry(
        &self,
        transport_id: &str,
        attempt_count: u32,
    ) -> Option<Duration> {
        let policy = self.get_transport_policy(transport_id);

        if policy.should_give_up(attempt_count) {
            return None;
        }

        Some(policy.delay_for_attempt(attempt_count))
    }

    /// Mark a message as expired.
    pub fn mark_expired(&self, entry_id: OutboxEntryId) -> Result<(), S::Error> {
        self.store.outbox_mark_expired(entry_id)
    }

    /// Clean up old confirmed/expired entries.
    ///
    /// Removes entries that have been confirmed/expired for longer than
    /// `cleanup_after_ms` (from config).
    ///
    /// # Returns
    /// Number of entries removed
    pub fn cleanup(&self) -> Result<u64, S::Error> {
        let now = now_ms();
        let cutoff = now.saturating_sub(self.config.cleanup_after_ms);
        self.store.outbox_cleanup(cutoff)
    }

    /// Check for and mark expired messages.
    ///
    /// Marks all messages that have exceeded their TTL as expired in a single
    /// database operation.
    ///
    /// # Returns
    /// Number of messages marked as expired
    pub fn check_expirations(&self) -> Result<u64, S::Error> {
        let now = now_ms();
        self.store.outbox_expire_due(now)
    }
}

/// Default retry policy (used when no transport-specific policy is set)
static DEFAULT_RETRY_POLICY: TransportRetryPolicy = TransportRetryPolicy {
    initial_delay: Duration::from_secs(5),
    max_delay: Duration::from_secs(300),
    backoff_multiplier: 2.0,
    max_attempts: None,
};

/// Get current time in milliseconds since epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_message::MessageID;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// Mock storage for testing
    struct MockOutboxStore {
        entries: RefCell<HashMap<OutboxEntryId, PendingMessage>>,
        next_id: RefCell<OutboxEntryId>,
    }

    impl MockOutboxStore {
        fn new() -> Self {
            Self {
                entries: RefCell::new(HashMap::new()),
                next_id: RefCell::new(1),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct MockError(String);

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for MockError {}

    impl OutboxStore for MockOutboxStore {
        type Error = MockError;

        fn outbox_enqueue(
            &self,
            recipient: &PublicID,
            content_id: ContentId,
            message_id: MessageID,
            envelope_bytes: &[u8],
            inner_bytes: &[u8],
            expires_at_ms: Option<u64>,
        ) -> Result<OutboxEntryId, Self::Error> {
            let mut next_id = self.next_id.borrow_mut();
            let id = *next_id;
            *next_id += 1;

            let msg = PendingMessage {
                id,
                recipient: *recipient,
                content_id,
                message_id,
                envelope_bytes: envelope_bytes.to_vec(),
                inner_bytes: inner_bytes.to_vec(),
                created_at_ms: now_ms(),
                expires_at_ms,
                expired_at_ms: None,
                attempts: Vec::new(),
                next_retry_at_ms: None,
                confirmation: None,
            };

            self.entries.borrow_mut().insert(id, msg);
            Ok(id)
        }

        fn outbox_get_pending(&self) -> Result<Vec<PendingMessage>, Self::Error> {
            Ok(self
                .entries
                .borrow()
                .values()
                .filter(|m| m.confirmation.is_none() && m.expired_at_ms.is_none())
                .cloned()
                .collect())
        }

        fn outbox_get_for_recipient(
            &self,
            recipient: &PublicID,
        ) -> Result<Vec<PendingMessage>, Self::Error> {
            Ok(self
                .entries
                .borrow()
                .values()
                .filter(|m| {
                    m.recipient == *recipient
                        && m.confirmation.is_none()
                        && m.expired_at_ms.is_none()
                })
                .cloned()
                .collect())
        }

        fn outbox_get_due_for_retry(&self, now_ms: u64) -> Result<Vec<PendingMessage>, Self::Error> {
            Ok(self
                .entries
                .borrow()
                .values()
                .filter(|m| {
                    m.confirmation.is_none()
                        && m.expired_at_ms.is_none()
                        && m.expires_at_ms.map(|e| e > now_ms).unwrap_or(true)
                        && m.next_retry_at_ms.map(|t| t <= now_ms).unwrap_or(true)
                })
                .cloned()
                .collect())
        }

        fn outbox_get_by_id(
            &self,
            entry_id: OutboxEntryId,
        ) -> Result<Option<PendingMessage>, Self::Error> {
            Ok(self.entries.borrow().get(&entry_id).cloned())
        }

        fn outbox_get_by_content_id(
            &self,
            content_id: ContentId,
        ) -> Result<Option<PendingMessage>, Self::Error> {
            Ok(self
                .entries
                .borrow()
                .values()
                .find(|m| m.content_id == content_id)
                .cloned())
        }

        fn outbox_record_attempt(
            &self,
            entry_id: OutboxEntryId,
            attempt: &TransportAttempt,
            next_retry_at_ms: Option<u64>,
        ) -> Result<(), Self::Error> {
            if let Some(msg) = self.entries.borrow_mut().get_mut(&entry_id) {
                msg.attempts.push(attempt.clone());
                msg.next_retry_at_ms = next_retry_at_ms;
            }
            Ok(())
        }

        fn outbox_mark_confirmed(
            &self,
            entry_id: OutboxEntryId,
            confirmation: &DeliveryConfirmation,
        ) -> Result<(), Self::Error> {
            if let Some(msg) = self.entries.borrow_mut().get_mut(&entry_id) {
                msg.confirmation = Some(confirmation.clone());
            }
            Ok(())
        }

        fn outbox_mark_expired(&self, entry_id: OutboxEntryId) -> Result<(), Self::Error> {
            if let Some(msg) = self.entries.borrow_mut().get_mut(&entry_id) {
                msg.expired_at_ms = Some(now_ms());
                msg.next_retry_at_ms = None;
            }
            Ok(())
        }

        fn outbox_schedule_retry(
            &self,
            entry_ids: &[OutboxEntryId],
            now_ms: u64,
        ) -> Result<(), Self::Error> {
            let mut entries = self.entries.borrow_mut();
            for &id in entry_ids {
                if let Some(msg) = entries.get_mut(&id) {
                    msg.next_retry_at_ms = Some(now_ms);
                }
            }
            Ok(())
        }

        fn outbox_cleanup(&self, confirmed_before_ms: u64) -> Result<u64, Self::Error> {
            // Remove confirmed and expired entries older than cutoff
            let mut entries = self.entries.borrow_mut();
            let before = entries.len();
            entries.retain(|_, m| {
                // Keep if neither confirmed nor expired, or if more recent than cutoff
                let is_confirmed_old = m
                    .confirmation
                    .is_some()
                    && m.created_at_ms < confirmed_before_ms;
                let is_expired_old = m
                    .expired_at_ms
                    .map(|exp| exp < confirmed_before_ms)
                    .unwrap_or(false);
                !is_confirmed_old && !is_expired_old
            });
            Ok((before - entries.len()) as u64)
        }

        fn outbox_expire_due(&self, now_ms: u64) -> Result<u64, Self::Error> {
            // Mark expired entries (matching SQLite behavior)
            let mut entries = self.entries.borrow_mut();
            let mut count = 0u64;
            for msg in entries.values_mut() {
                // Only expire if: not confirmed, not already expired, has TTL that passed
                if msg.confirmation.is_none()
                    && msg.expired_at_ms.is_none()
                    && msg.expires_at_ms.map(|e| e < now_ms).unwrap_or(false)
                {
                    msg.expired_at_ms = Some(now_ms);
                    msg.next_retry_at_ms = None;
                    count += 1;
                }
            }
            Ok(count)
        }
    }

    fn make_test_public_id(seed: u8) -> PublicID {
        PublicID::try_from_bytes(&[seed; 32]).unwrap()
    }

    #[test]
    fn test_enqueue_and_retrieve() {
        let store = MockOutboxStore::new();
        let outbox = ClientOutbox::new(store, OutboxConfig::default());

        let recipient = make_test_public_id(1);
        let content_id = [1u8; 8];
        let message_id = MessageID::new();

        let entry_id = outbox
            .enqueue(
                &recipient,
                content_id,
                message_id,
                b"envelope",
                b"inner",
                None,
            )
            .unwrap();

        let pending = outbox.get_by_id(entry_id).unwrap().unwrap();
        assert_eq!(pending.recipient, recipient);
        assert_eq!(pending.content_id, content_id);
    }

    #[test]
    fn test_record_attempt_success() {
        let store = MockOutboxStore::new();
        let outbox = ClientOutbox::new(store, OutboxConfig::default());

        let recipient = make_test_public_id(1);
        let entry_id = outbox
            .enqueue(
                &recipient,
                [1u8; 8],
                MessageID::new(),
                b"envelope",
                b"inner",
                None,
            )
            .unwrap();

        outbox
            .record_attempt(entry_id, "http:test", AttemptResult::Sent)
            .unwrap();

        let pending = outbox.get_by_id(entry_id).unwrap().unwrap();
        assert_eq!(pending.attempts.len(), 1);
        assert!(pending.attempts[0].result.is_sent());
    }

    #[test]
    fn test_record_attempt_failure_schedules_retry() {
        let store = MockOutboxStore::new();
        let outbox = ClientOutbox::new(store, OutboxConfig::default());

        let recipient = make_test_public_id(1);
        let entry_id = outbox
            .enqueue(
                &recipient,
                [1u8; 8],
                MessageID::new(),
                b"envelope",
                b"inner",
                None,
            )
            .unwrap();

        outbox
            .record_attempt(
                entry_id,
                "http:test",
                AttemptResult::Failed(AttemptError::network_transient("connection refused")),
            )
            .unwrap();

        let pending = outbox.get_by_id(entry_id).unwrap().unwrap();
        assert!(pending.next_retry_at_ms.is_some());
    }

    #[test]
    fn test_dag_confirmation() {
        let store = MockOutboxStore::new();
        let outbox = ClientOutbox::new(store, OutboxConfig::default());

        let recipient = make_test_public_id(1);
        let content_id = [1u8; 8];
        let entry_id = outbox
            .enqueue(
                &recipient,
                content_id,
                MessageID::new(),
                b"envelope",
                b"inner",
                None,
            )
            .unwrap();

        // Simulate receiving a message where peer observed our content_id
        let received_content_id = [2u8; 8];
        let confirmed = outbox
            .on_peer_message_received(&recipient, &[content_id], received_content_id)
            .unwrap();

        assert_eq!(confirmed, vec![entry_id]);

        let pending = outbox.get_by_id(entry_id).unwrap().unwrap();
        assert!(pending.confirmation.is_some());
    }

    #[test]
    fn test_find_unacked_messages() {
        let store = MockOutboxStore::new();
        let outbox = ClientOutbox::new(store, OutboxConfig::default());

        let recipient = make_test_public_id(1);
        let content_id1 = [1u8; 8];
        let content_id2 = [2u8; 8];

        let entry1 = outbox
            .enqueue(
                &recipient,
                content_id1,
                MessageID::new(),
                b"envelope1",
                b"inner1",
                None,
            )
            .unwrap();

        let entry2 = outbox
            .enqueue(
                &recipient,
                content_id2,
                MessageID::new(),
                b"envelope2",
                b"inner2",
                None,
            )
            .unwrap();

        // Peer has only observed content_id1
        let unacked = outbox
            .find_unacked_messages(&recipient, &[content_id1])
            .unwrap();

        // entry2 should be unacked
        assert_eq!(unacked.len(), 1);
        assert!(unacked.contains(&entry2));
        assert!(!unacked.contains(&entry1));
    }

    #[test]
    fn test_transport_policy() {
        let store = MockOutboxStore::new();
        let mut outbox = ClientOutbox::new(store, OutboxConfig::default());

        // Set custom policy for LoRa
        outbox.set_transport_policy("lora", TransportRetryPolicy::lora());

        // Get policy for specific transport
        let lora_policy = outbox.get_transport_policy("lora:meshtastic");
        assert_eq!(lora_policy.initial_delay, Duration::from_secs(60));

        // Default policy for unknown transport
        let http_policy = outbox.get_transport_policy("http:node1");
        assert_eq!(http_policy.initial_delay, Duration::from_secs(5));
    }

    #[test]
    fn test_schedule_immediate_retry() {
        let store = MockOutboxStore::new();
        let outbox = ClientOutbox::new(store, OutboxConfig::default());

        let recipient = make_test_public_id(1);
        let entry_id = outbox
            .enqueue(
                &recipient,
                [1u8; 8],
                MessageID::new(),
                b"envelope",
                b"inner",
                None,
            )
            .unwrap();

        // Set far future retry time
        outbox
            .record_attempt(
                entry_id,
                "http:test",
                AttemptResult::Failed(AttemptError::network_transient("timeout")),
            )
            .unwrap();

        // Schedule immediate retry
        outbox.schedule_immediate_retry(&[entry_id]).unwrap();

        // Should now be due for retry
        let due = outbox.get_ready_for_retry().unwrap();
        assert!(due.iter().any(|m| m.id == entry_id));
    }
}
