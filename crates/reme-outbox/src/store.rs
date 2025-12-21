//! Storage trait for outbox persistence.

use crate::state::*;
use reme_identity::PublicID;
use reme_message::{ContentId, MessageID};
use std::sync::Arc;

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

    // ========== Tiered Delivery Methods ==========

    /// Update the tiered delivery phase for an entry.
    ///
    /// Used to transition between Urgent → Distributed → Confirmed phases.
    fn outbox_update_tiered_phase(
        &self,
        entry_id: OutboxEntryId,
        phase: &TieredDeliveryPhase,
    ) -> Result<(), Self::Error>;

    /// Add a successful target to an entry.
    ///
    /// Used to track which targets have successfully received the message.
    fn outbox_add_successful_target(
        &self,
        entry_id: OutboxEntryId,
        target_id: &TargetId,
    ) -> Result<(), Self::Error>;

    /// Get urgent phase messages due for retry.
    ///
    /// Returns messages where:
    /// - `tiered_phase` is `Urgent`
    /// - Not confirmed, not expired
    /// - `next_retry_at_ms <= now` (or no retry scheduled)
    fn outbox_get_urgent_retry_due(&self, now_ms: u64) -> Result<Vec<PendingMessage>, Self::Error>;

    /// Get distributed phase messages due for maintenance.
    ///
    /// Returns messages where:
    /// - `tiered_phase` is `Distributed`
    /// - Not confirmed, not expired
    /// - Last maintenance was >= `maintenance_interval_ms` ago
    fn outbox_get_maintenance_due(
        &self,
        now_ms: u64,
        maintenance_interval_ms: u64,
    ) -> Result<Vec<PendingMessage>, Self::Error>;

    /// Update last maintenance time for an entry.
    fn outbox_update_last_maintenance(
        &self,
        entry_id: OutboxEntryId,
        last_maintenance_ms: u64,
    ) -> Result<(), Self::Error>;
}

/// Blanket implementation for Arc<T> where T: OutboxStore.
///
/// This enables sharing storage between Client and ClientOutbox
/// without requiring Clone on the storage implementation.
impl<T: OutboxStore> OutboxStore for Arc<T> {
    type Error = T::Error;

    fn outbox_enqueue(
        &self,
        recipient: &PublicID,
        content_id: ContentId,
        message_id: MessageID,
        envelope_bytes: &[u8],
        inner_bytes: &[u8],
        expires_at_ms: Option<u64>,
    ) -> Result<OutboxEntryId, Self::Error> {
        (**self).outbox_enqueue(recipient, content_id, message_id, envelope_bytes, inner_bytes, expires_at_ms)
    }

    fn outbox_get_pending(&self) -> Result<Vec<PendingMessage>, Self::Error> {
        (**self).outbox_get_pending()
    }

    fn outbox_get_for_recipient(&self, recipient: &PublicID) -> Result<Vec<PendingMessage>, Self::Error> {
        (**self).outbox_get_for_recipient(recipient)
    }

    fn outbox_get_due_for_retry(&self, now_ms: u64) -> Result<Vec<PendingMessage>, Self::Error> {
        (**self).outbox_get_due_for_retry(now_ms)
    }

    fn outbox_get_by_id(&self, entry_id: OutboxEntryId) -> Result<Option<PendingMessage>, Self::Error> {
        (**self).outbox_get_by_id(entry_id)
    }

    fn outbox_get_by_content_id(&self, content_id: ContentId) -> Result<Option<PendingMessage>, Self::Error> {
        (**self).outbox_get_by_content_id(content_id)
    }

    fn outbox_record_attempt(
        &self,
        entry_id: OutboxEntryId,
        attempt: &TransportAttempt,
        next_retry_at_ms: Option<u64>,
    ) -> Result<(), Self::Error> {
        (**self).outbox_record_attempt(entry_id, attempt, next_retry_at_ms)
    }

    fn outbox_mark_confirmed(
        &self,
        entry_id: OutboxEntryId,
        confirmation: &DeliveryConfirmation,
    ) -> Result<(), Self::Error> {
        (**self).outbox_mark_confirmed(entry_id, confirmation)
    }

    fn outbox_mark_expired(&self, entry_id: OutboxEntryId) -> Result<(), Self::Error> {
        (**self).outbox_mark_expired(entry_id)
    }

    fn outbox_schedule_retry(&self, entry_ids: &[OutboxEntryId], now_ms: u64) -> Result<(), Self::Error> {
        (**self).outbox_schedule_retry(entry_ids, now_ms)
    }

    fn outbox_cleanup(&self, confirmed_before_ms: u64) -> Result<u64, Self::Error> {
        (**self).outbox_cleanup(confirmed_before_ms)
    }

    fn outbox_expire_due(&self, now_ms: u64) -> Result<u64, Self::Error> {
        (**self).outbox_expire_due(now_ms)
    }

    fn outbox_update_tiered_phase(
        &self,
        entry_id: OutboxEntryId,
        phase: &TieredDeliveryPhase,
    ) -> Result<(), Self::Error> {
        (**self).outbox_update_tiered_phase(entry_id, phase)
    }

    fn outbox_add_successful_target(
        &self,
        entry_id: OutboxEntryId,
        target_id: &TargetId,
    ) -> Result<(), Self::Error> {
        (**self).outbox_add_successful_target(entry_id, target_id)
    }

    fn outbox_get_urgent_retry_due(&self, now_ms: u64) -> Result<Vec<PendingMessage>, Self::Error> {
        (**self).outbox_get_urgent_retry_due(now_ms)
    }

    fn outbox_get_maintenance_due(
        &self,
        now_ms: u64,
        maintenance_interval_ms: u64,
    ) -> Result<Vec<PendingMessage>, Self::Error> {
        (**self).outbox_get_maintenance_due(now_ms, maintenance_interval_ms)
    }

    fn outbox_update_last_maintenance(
        &self,
        entry_id: OutboxEntryId,
        last_maintenance_ms: u64,
    ) -> Result<(), Self::Error> {
        (**self).outbox_update_last_maintenance(entry_id, last_maintenance_ms)
    }
}
