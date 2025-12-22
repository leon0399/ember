//! Mailbox storage trait and implementations
//!
//! This module defines the `MailboxStore` trait and provides a SQLite-backed
//! implementation `PersistentMailboxStore`.

use reme_message::{MessageID, OuterEnvelope, RoutingKey};

use crate::error::NodeResult;

/// Configuration for the persistent store
#[derive(Debug, Clone)]
pub struct PersistentStoreConfig {
    /// Maximum messages per routing key (mailbox)
    pub max_messages_per_mailbox: usize,
    /// Default TTL for messages without explicit TTL (seconds)
    pub default_ttl_secs: u64,
}

impl Default for PersistentStoreConfig {
    fn default() -> Self {
        Self {
            max_messages_per_mailbox: 1000,
            default_ttl_secs: 7 * 24 * 60 * 60, // 7 days
        }
    }
}

/// Trait for mailbox storage backends
///
/// This trait abstracts the storage layer for mailbox nodes, allowing
/// different implementations (SQLite, in-memory, etc.)
pub trait MailboxStore: Send + Sync {
    /// Store a message in the mailbox for the given routing key
    fn enqueue(&self, routing_key: &RoutingKey, envelope: OuterEnvelope) -> NodeResult<()>;

    /// Fetch and remove all messages for the given routing key
    fn fetch(&self, routing_key: &RoutingKey) -> NodeResult<Vec<OuterEnvelope>>;

    /// Check if a message with the given ID already exists
    fn contains(&self, message_id: &MessageID) -> NodeResult<bool>;

    /// Remove expired messages
    fn cleanup_expired(&self) -> NodeResult<usize>;
}
