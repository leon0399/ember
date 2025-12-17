//! Storage trait for outbox persistence.

use crate::state::*;
use reme_identity::PublicID;
use reme_message::{ContentId, MessageID};

/// Storage operations for the outbox.
///
/// This trait is implemented by `reme-storage::Storage` to provide
/// SQLite persistence for the outbox.
pub trait OutboxStore {
    /// Error type for storage operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Add a new message to the outbox.
    ///
    /// Returns the database ID for the new entry.
    fn outbox_enqueue(
        &self,
        recipient: &PublicID,
        content_id: ContentId,
        message_id: MessageID,
        envelope_bytes: &[u8],
        inner_bytes: &[u8],
        expires_at_ms: Option<u64>,
    ) -> Result<OutboxEntryId, Self::Error>;

    /// Get all pending messages (not confirmed, not expired).
    fn outbox_get_pending(&self) -> Result<Vec<PendingMessage>, Self::Error>;

    /// Get pending messages for a specific recipient.
    fn outbox_get_for_recipient(&self, recipient: &PublicID) -> Result<Vec<PendingMessage>, Self::Error>;

    /// Get pending messages that are due for retry (`next_retry_at <= now`).
    fn outbox_get_due_for_retry(&self, now_ms: u64) -> Result<Vec<PendingMessage>, Self::Error>;

    /// Get a specific outbox entry by ID.
    fn outbox_get_by_id(&self, entry_id: OutboxEntryId) -> Result<Option<PendingMessage>, Self::Error>;

    /// Get entry by content_id (for DAG confirmation lookup).
    fn outbox_get_by_content_id(&self, content_id: ContentId) -> Result<Option<PendingMessage>, Self::Error>;

    /// Record a delivery attempt.
    ///
    /// # Arguments
    /// * `entry_id` - The outbox entry to update
    /// * `attempt` - The attempt record
    /// * `next_retry_at_ms` - When next retry should occur (`None` = no auto-retry)
    fn outbox_record_attempt(
        &self,
        entry_id: OutboxEntryId,
        attempt: &TransportAttempt,
        next_retry_at_ms: Option<u64>,
    ) -> Result<(), Self::Error>;

    /// Mark message as confirmed.
    fn outbox_mark_confirmed(
        &self,
        entry_id: OutboxEntryId,
        confirmation: &DeliveryConfirmation,
    ) -> Result<(), Self::Error>;

    /// Mark message as expired.
    fn outbox_mark_expired(&self, entry_id: OutboxEntryId) -> Result<(), Self::Error>;

    /// Schedule immediate retry for specific entries.
    ///
    /// Sets `next_retry_at_ms` to `now_ms` for the given entries.
    fn outbox_schedule_retry(&self, entry_ids: &[OutboxEntryId], now_ms: u64) -> Result<(), Self::Error>;

    /// Remove confirmed/expired entries older than given timestamp.
    ///
    /// Returns the number of entries removed.
    fn outbox_cleanup(&self, confirmed_before_ms: u64) -> Result<u64, Self::Error>;

    /// Mark all entries with `expires_at_ms < now_ms` as expired.
    ///
    /// Returns the number of entries expired.
    /// This is more efficient than loading all pending and calling mark_expired individually.
    fn outbox_expire_due(&self, now_ms: u64) -> Result<u64, Self::Error>;
}
