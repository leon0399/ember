//! In-memory mailbox storage
//!
//! This module provides storage for message envelopes and prekey bundles.
//! Currently in-memory only; designed for future distributed storage.

use reme_message::{OuterEnvelope, RoutingKey};
use reme_prekeys::SignedPrekeyBundle;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Mailbox full")]
    MailboxFull,

    #[error("Prekeys not found")]
    PrekeysNotFound,

    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),
}

/// Entry in the message queue with expiration
struct MessageEntry {
    envelope: OuterEnvelope,
    expires_at: Instant,
}

/// In-memory mailbox store
///
/// Thread-safe storage for messages and prekeys.
/// Messages are automatically expired based on TTL.
pub struct MailboxStore {
    /// Messages indexed by routing key
    messages: RwLock<HashMap<RoutingKey, Vec<MessageEntry>>>,

    /// Prekey bundles indexed by routing key
    prekeys: RwLock<HashMap<RoutingKey, SignedPrekeyBundle>>,

    /// Maximum messages per mailbox
    max_messages: usize,

    /// Default TTL for messages without explicit TTL
    default_ttl: Duration,
}

impl MailboxStore {
    pub fn new(max_messages: usize, default_ttl_secs: u32) -> Self {
        Self {
            messages: RwLock::new(HashMap::new()),
            prekeys: RwLock::new(HashMap::new()),
            max_messages,
            default_ttl: Duration::from_secs(default_ttl_secs as u64),
        }
    }

    /// Enqueue a message for a routing key
    pub fn enqueue(&self, routing_key: RoutingKey, envelope: OuterEnvelope) -> Result<(), StoreError> {
        let ttl = envelope
            .ttl
            .map(|t| Duration::from_secs(t as u64))
            .unwrap_or(self.default_ttl);

        let entry = MessageEntry {
            envelope,
            expires_at: Instant::now() + ttl,
        };

        let mut messages = self.messages.write().map_err(|e| {
            StoreError::LockPoisoned(e.to_string())
        })?;

        let queue = messages.entry(routing_key).or_insert_with(Vec::new);

        // Remove expired messages
        let now = Instant::now();
        queue.retain(|e| e.expires_at > now);

        // Check capacity
        if queue.len() >= self.max_messages {
            return Err(StoreError::MailboxFull);
        }

        queue.push(entry);
        Ok(())
    }

    /// Fetch and remove all messages for a routing key
    pub fn fetch(&self, routing_key: &RoutingKey) -> Result<Vec<OuterEnvelope>, StoreError> {
        let mut messages = self.messages.write().map_err(|e| {
            StoreError::LockPoisoned(e.to_string())
        })?;

        let now = Instant::now();

        if let Some(queue) = messages.get_mut(routing_key) {
            // Filter out expired and drain
            let valid: Vec<OuterEnvelope> = queue
                .drain(..)
                .filter(|e| e.expires_at > now)
                .map(|e| e.envelope)
                .collect();

            Ok(valid)
        } else {
            Ok(Vec::new())
        }
    }

    /// Store a prekey bundle
    pub fn store_prekeys(
        &self,
        routing_key: RoutingKey,
        bundle: SignedPrekeyBundle,
    ) -> Result<(), StoreError> {
        let mut prekeys = self.prekeys.write().map_err(|e| {
            StoreError::LockPoisoned(e.to_string())
        })?;

        prekeys.insert(routing_key, bundle);
        Ok(())
    }

    /// Fetch a prekey bundle
    pub fn fetch_prekeys(&self, routing_key: &RoutingKey) -> Result<SignedPrekeyBundle, StoreError> {
        let prekeys = self.prekeys.read().map_err(|e| {
            StoreError::LockPoisoned(e.to_string())
        })?;

        prekeys
            .get(routing_key)
            .cloned()
            .ok_or(StoreError::PrekeysNotFound)
    }

    /// Get statistics about the store
    pub fn stats(&self) -> StoreStats {
        let messages = self.messages.read().unwrap();
        let prekeys = self.prekeys.read().unwrap();

        let total_messages: usize = messages.values().map(|q| q.len()).sum();

        StoreStats {
            mailbox_count: messages.len(),
            total_messages,
            prekey_bundles: prekeys.len(),
        }
    }
}

/// Statistics about the store
#[derive(Debug, Clone)]
pub struct StoreStats {
    pub mailbox_count: usize,
    pub total_messages: usize,
    pub prekey_bundles: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_message::{MessageID, CURRENT_VERSION};

    fn create_test_envelope(routing_key: RoutingKey) -> OuterEnvelope {
        OuterEnvelope {
            version: CURRENT_VERSION,
            flags: 0,
            routing_key,
            created_at_ms: Some(1234567890),
            ttl: Some(3600), // 1 hour
            message_id: MessageID::new(),
            inner_ciphertext: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn test_enqueue_and_fetch() {
        let store = MailboxStore::new(100, 3600);
        let routing_key = [1u8; 16];

        let envelope = create_test_envelope(routing_key);
        store.enqueue(routing_key, envelope).unwrap();

        let fetched = store.fetch(&routing_key).unwrap();
        assert_eq!(fetched.len(), 1);

        // Should be empty after fetch
        let fetched_again = store.fetch(&routing_key).unwrap();
        assert!(fetched_again.is_empty());
    }

    #[test]
    fn test_prekeys() {
        use reme_identity::Identity;
        use reme_prekeys::generate_prekey_bundle;

        let store = MailboxStore::new(100, 3600);
        let routing_key = [3u8; 16];

        let identity = Identity::generate();
        let (_, bundle) = generate_prekey_bundle(&identity, 5);

        store.store_prekeys(routing_key, bundle.clone()).unwrap();

        let fetched = store.fetch_prekeys(&routing_key).unwrap();
        assert_eq!(fetched.id_pub(), bundle.id_pub());
    }

    #[test]
    fn test_mailbox_capacity() {
        let store = MailboxStore::new(2, 3600);
        let routing_key = [4u8; 16];

        store.enqueue(routing_key, create_test_envelope(routing_key)).unwrap();
        store.enqueue(routing_key, create_test_envelope(routing_key)).unwrap();

        // Third should fail
        let result = store.enqueue(routing_key, create_test_envelope(routing_key));
        assert!(result.is_err());
    }
}
