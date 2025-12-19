//! Storage trait for mailbox operations.
//!
//! The `MailboxStorage` trait abstracts storage operations, allowing
//! the embedded node to work with different storage backends.

use async_trait::async_trait;
use reme_message::{MessageID, OuterEnvelope, RoutingKey};

/// Error type for storage operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum StorageError {
    /// Database or I/O error.
    #[error("Database error: {0}")]
    Database(String),

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Mailbox is full (capacity limit reached).
    #[error("Mailbox full")]
    MailboxFull,

    /// Lock poisoned (internal concurrency error).
    #[error("Lock poisoned")]
    LockPoisoned,
}

/// Trait for mailbox storage operations.
///
/// Implementations must be thread-safe and can use internal synchronization
/// (e.g., `Mutex<Connection>` for SQLite).
#[async_trait]
pub trait MailboxStorage {
    /// Enqueue a message for a routing key.
    ///
    /// Returns `Ok(())` on success, or an error if storage fails.
    /// Duplicate message IDs should be silently ignored (idempotent).
    async fn mailbox_enqueue(
        &self,
        routing_key: RoutingKey,
        envelope: OuterEnvelope,
    ) -> Result<(), StorageError>;

    /// Fetch all messages for a routing key.
    ///
    /// This does NOT delete messages - use `mailbox_delete_message` for that.
    async fn mailbox_fetch(&self, routing_key: &RoutingKey) -> Result<Vec<OuterEnvelope>, StorageError>;

    /// Check if a message with the given ID exists.
    async fn mailbox_has_message(
        &self,
        routing_key: &RoutingKey,
        message_id: &MessageID,
    ) -> Result<bool, StorageError>;

    /// Delete a specific message by routing key and message ID.
    ///
    /// Returns `true` if a message was deleted, `false` if not found.
    async fn mailbox_delete_message(
        &self,
        routing_key: &RoutingKey,
        message_id: &MessageID,
    ) -> Result<bool, StorageError>;

    /// Cleanup expired messages across all mailboxes.
    ///
    /// Returns the number of messages deleted.
    async fn mailbox_cleanup_expired(&self) -> Result<usize, StorageError>;
}
