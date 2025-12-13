//! In-memory mailbox storage
//!
//! This module provides storage for message envelopes, prekey bundles, and tombstones.
//! Currently in-memory only; designed for future distributed storage.
//!
//! ## Tombstone Security Mitigations
//!
//! - **Rate limiting**: Max 1000 tombstones per recipient per hour
//! - **Sequence tracking**: Monotonic sequence numbers per (recipient, device)
//! - **Orphan cache**: Handles tombstones that arrive before their target message

use reme_message::{DeviceID, MessageID, OuterEnvelope, RoutingKey, TombstoneEnvelope};
use reme_prekeys::SignedPrekeyBundle;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, warn};

/// Default maximum tombstones per recipient per hour
const DEFAULT_MAX_TOMBSTONES_PER_HOUR: usize = 1000;

/// Default orphan tombstone TTL (24 hours)
const DEFAULT_ORPHAN_TTL_SECS: u64 = 24 * 60 * 60;

/// Default maximum orphan tombstones to cache
const DEFAULT_MAX_ORPHANS: usize = 10_000;

/// Default tombstone retention period (10 days)
const DEFAULT_TOMBSTONE_TTL_SECS: u64 = 10 * 24 * 60 * 60;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Mailbox full")]
    MailboxFull,

    #[error("Prekeys not found")]
    PrekeysNotFound,

    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Sequence not monotonic")]
    SequenceNotMonotonic,

    #[error("Message not found")]
    MessageNotFound,
}

/// Entry in the message queue with expiration
struct MessageEntry {
    envelope: OuterEnvelope,
    expires_at: Instant,
}

/// Entry for stored tombstones
struct TombstoneEntry {
    tombstone: TombstoneEnvelope,
    received_at: Instant,
}

/// Entry for orphan tombstones (arrived before message)
struct OrphanTombstoneEntry {
    tombstone: TombstoneEnvelope,
    received_at: Instant,
}

/// Rate limiter state per recipient
struct RateLimitState {
    count: usize,
    window_start: Instant,
}

/// Key for sequence tracking: (recipient_id_pub, device_id)
type SequenceKey = ([u8; 32], DeviceID);

/// In-memory mailbox store
///
/// Thread-safe storage for messages, prekeys, and tombstones.
/// Messages are automatically expired based on TTL.
pub struct MailboxStore {
    /// Messages indexed by routing key
    messages: RwLock<HashMap<RoutingKey, Vec<MessageEntry>>>,

    /// Prekey bundles indexed by routing key
    prekeys: RwLock<HashMap<RoutingKey, SignedPrekeyBundle>>,

    /// Tombstones indexed by target message ID
    tombstones: RwLock<HashMap<MessageID, TombstoneEntry>>,

    /// Orphan tombstones (arrived before message)
    orphan_tombstones: RwLock<HashMap<MessageID, OrphanTombstoneEntry>>,

    /// Rate limiting per recipient
    rate_limits: RwLock<HashMap<[u8; 32], RateLimitState>>,

    /// Sequence tracking for replay prevention
    sequences: RwLock<HashMap<SequenceKey, u64>>,

    /// Maximum messages per mailbox
    max_messages: usize,

    /// Default TTL for messages without explicit TTL
    default_ttl: Duration,

    /// Tombstone retention period
    tombstone_ttl: Duration,

    /// Orphan tombstone TTL
    orphan_ttl: Duration,

    /// Maximum orphan tombstones to cache
    max_orphans: usize,

    /// Maximum tombstones per recipient per hour
    max_tombstones_per_hour: usize,
}

impl MailboxStore {
    pub fn new(max_messages: usize, default_ttl_secs: u32) -> Self {
        Self {
            messages: RwLock::new(HashMap::new()),
            prekeys: RwLock::new(HashMap::new()),
            tombstones: RwLock::new(HashMap::new()),
            orphan_tombstones: RwLock::new(HashMap::new()),
            rate_limits: RwLock::new(HashMap::new()),
            sequences: RwLock::new(HashMap::new()),
            max_messages,
            default_ttl: Duration::from_secs(default_ttl_secs as u64),
            tombstone_ttl: Duration::from_secs(DEFAULT_TOMBSTONE_TTL_SECS),
            orphan_ttl: Duration::from_secs(DEFAULT_ORPHAN_TTL_SECS),
            max_orphans: DEFAULT_MAX_ORPHANS,
            max_tombstones_per_hour: DEFAULT_MAX_TOMBSTONES_PER_HOUR,
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

    /// Check if a message with the given ID already exists for the routing key
    pub fn has_message(&self, routing_key: &RoutingKey, message_id: &MessageID) -> Result<bool, StoreError> {
        let messages = self.messages.read().map_err(|e| {
            StoreError::LockPoisoned(e.to_string())
        })?;

        if let Some(queue) = messages.get(routing_key) {
            let now = Instant::now();
            Ok(queue.iter().any(|e| e.expires_at > now && e.envelope.message_id == *message_id))
        } else {
            Ok(false)
        }
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
        let tombstones = self.tombstones.read().unwrap();
        let orphans = self.orphan_tombstones.read().unwrap();

        let total_messages: usize = messages.values().map(|q| q.len()).sum();

        StoreStats {
            mailbox_count: messages.len(),
            total_messages,
            prekey_bundles: prekeys.len(),
            tombstone_count: tombstones.len(),
            orphan_tombstone_count: orphans.len(),
        }
    }

    // =========================================
    // Tombstone Methods
    // =========================================

    /// Store a tombstone with full validation
    ///
    /// Performs:
    /// 1. Signature and timestamp validation
    /// 2. Rate limit check
    /// 3. Sequence monotonicity check
    /// 4. Either applies tombstone (if message exists) or stores in orphan cache
    pub fn store_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), StoreError> {
        // 1. Validate signature and timestamp
        tombstone
            .validate()
            .map_err(|e| StoreError::ValidationError(e.to_string()))?;

        // 2. Check rate limit
        self.check_rate_limit(&tombstone.recipient_id_pub)?;

        // 3. Check sequence monotonicity
        self.check_and_update_sequence(&tombstone)?;

        // 4. Check if we have the message
        let has_message = self.has_message_by_id(&tombstone.target_message_id)?;

        if has_message {
            // Message exists - apply tombstone immediately
            debug!(
                "Applying tombstone for message {:?}",
                tombstone.target_message_id
            );
            self.apply_tombstone(tombstone)?;
        } else {
            // No message - store in orphan cache
            debug!(
                "Storing orphan tombstone for message {:?}",
                tombstone.target_message_id
            );
            self.store_orphan_tombstone(tombstone)?;
        }

        Ok(())
    }

    /// Check if a tombstone already exists for a message
    pub fn has_tombstone(&self, message_id: &MessageID) -> Result<bool, StoreError> {
        let tombstones = self
            .tombstones
            .read()
            .map_err(|e| StoreError::LockPoisoned(e.to_string()))?;
        Ok(tombstones.contains_key(message_id))
    }

    /// Get a tombstone for a message (if it exists)
    pub fn get_tombstone(&self, message_id: &MessageID) -> Result<Option<TombstoneEnvelope>, StoreError> {
        let tombstones = self
            .tombstones
            .read()
            .map_err(|e| StoreError::LockPoisoned(e.to_string()))?;
        Ok(tombstones.get(message_id).map(|e| e.tombstone.clone()))
    }

    /// Check rate limit for a recipient
    fn check_rate_limit(&self, recipient_id: &[u8; 32]) -> Result<(), StoreError> {
        let mut limits = self
            .rate_limits
            .write()
            .map_err(|e| StoreError::LockPoisoned(e.to_string()))?;

        let state = limits.entry(*recipient_id).or_insert(RateLimitState {
            count: 0,
            window_start: Instant::now(),
        });

        // Reset window every hour
        if state.window_start.elapsed() > Duration::from_secs(3600) {
            state.count = 0;
            state.window_start = Instant::now();
        }

        if state.count >= self.max_tombstones_per_hour {
            warn!(
                "Rate limit exceeded for recipient {:?}",
                &recipient_id[..4]
            );
            return Err(StoreError::RateLimitExceeded);
        }

        state.count += 1;
        Ok(())
    }

    /// Check and update sequence number for replay prevention
    fn check_and_update_sequence(&self, tombstone: &TombstoneEnvelope) -> Result<(), StoreError> {
        let mut sequences = self
            .sequences
            .write()
            .map_err(|e| StoreError::LockPoisoned(e.to_string()))?;

        let key = (tombstone.recipient_id_pub, tombstone.device_id);

        if let Some(&last_seq) = sequences.get(&key) {
            if tombstone.sequence <= last_seq {
                warn!(
                    "Non-monotonic sequence {} <= {} for recipient {:?}",
                    tombstone.sequence,
                    last_seq,
                    &tombstone.recipient_id_pub[..4]
                );
                return Err(StoreError::SequenceNotMonotonic);
            }
        }

        sequences.insert(key, tombstone.sequence);
        Ok(())
    }

    /// Check if a message exists by ID (across all routing keys)
    fn has_message_by_id(&self, message_id: &MessageID) -> Result<bool, StoreError> {
        let messages = self
            .messages
            .read()
            .map_err(|e| StoreError::LockPoisoned(e.to_string()))?;

        let now = Instant::now();

        for queue in messages.values() {
            if queue
                .iter()
                .any(|e| e.expires_at > now && e.envelope.message_id == *message_id)
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Delete a message by ID
    fn delete_message_by_id(&self, message_id: &MessageID) -> Result<bool, StoreError> {
        let mut messages = self
            .messages
            .write()
            .map_err(|e| StoreError::LockPoisoned(e.to_string()))?;

        for queue in messages.values_mut() {
            let len_before = queue.len();
            queue.retain(|e| e.envelope.message_id != *message_id);
            if queue.len() < len_before {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Apply a tombstone (store it and delete the target message)
    fn apply_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), StoreError> {
        // Store tombstone
        let mut tombstones = self
            .tombstones
            .write()
            .map_err(|e| StoreError::LockPoisoned(e.to_string()))?;

        tombstones.insert(
            tombstone.target_message_id,
            TombstoneEntry {
                tombstone: tombstone.clone(),
                received_at: Instant::now(),
            },
        );

        drop(tombstones);

        // Delete the original message
        self.delete_message_by_id(&tombstone.target_message_id)?;

        Ok(())
    }

    /// Store an orphan tombstone (message not yet received)
    fn store_orphan_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), StoreError> {
        let mut orphans = self
            .orphan_tombstones
            .write()
            .map_err(|e| StoreError::LockPoisoned(e.to_string()))?;

        // Evict oldest if at capacity
        if orphans.len() >= self.max_orphans {
            // Find and remove oldest
            if let Some((oldest_id, _)) = orphans
                .iter()
                .min_by_key(|(_, e)| e.received_at)
                .map(|(id, e)| (*id, e.received_at))
            {
                debug!("Evicting oldest orphan tombstone {:?}", oldest_id);
                orphans.remove(&oldest_id);
            }
        }

        orphans.insert(
            tombstone.target_message_id,
            OrphanTombstoneEntry {
                tombstone,
                received_at: Instant::now(),
            },
        );

        Ok(())
    }

    /// Check for a pending orphan tombstone when storing a new message
    ///
    /// Returns true if an orphan tombstone was found and applied
    /// (meaning the message should not be stored).
    pub fn check_orphan_tombstone(&self, message_id: &MessageID) -> Result<bool, StoreError> {
        let mut orphans = self
            .orphan_tombstones
            .write()
            .map_err(|e| StoreError::LockPoisoned(e.to_string()))?;

        if let Some(orphan) = orphans.remove(message_id) {
            // Tombstone was waiting - apply it now
            debug!(
                "Found orphan tombstone for message {:?}, applying",
                message_id
            );
            drop(orphans);

            // Store the tombstone (but don't try to delete message since we haven't stored it yet)
            let mut tombstones = self
                .tombstones
                .write()
                .map_err(|e| StoreError::LockPoisoned(e.to_string()))?;

            tombstones.insert(
                orphan.tombstone.target_message_id,
                TombstoneEntry {
                    tombstone: orphan.tombstone,
                    received_at: Instant::now(),
                },
            );

            return Ok(true);
        }

        Ok(false)
    }

    /// Cleanup expired tombstones and orphan tombstones
    ///
    /// Returns the number of items cleaned up.
    pub fn cleanup_tombstones(&self) -> Result<usize, StoreError> {
        let mut cleaned = 0;

        // Cleanup expired tombstones
        {
            let mut tombstones = self
                .tombstones
                .write()
                .map_err(|e| StoreError::LockPoisoned(e.to_string()))?;

            let before = tombstones.len();
            tombstones.retain(|_, entry| entry.received_at.elapsed() < self.tombstone_ttl);
            cleaned += before - tombstones.len();
        }

        // Cleanup expired orphan tombstones
        {
            let mut orphans = self
                .orphan_tombstones
                .write()
                .map_err(|e| StoreError::LockPoisoned(e.to_string()))?;

            let before = orphans.len();
            orphans.retain(|_, entry| entry.received_at.elapsed() < self.orphan_ttl);
            cleaned += before - orphans.len();
        }

        if cleaned > 0 {
            debug!("Cleaned up {} expired tombstones/orphans", cleaned);
        }

        Ok(cleaned)
    }

    /// Cleanup expired rate limit states
    pub fn cleanup_rate_limits(&self) -> Result<usize, StoreError> {
        let mut limits = self
            .rate_limits
            .write()
            .map_err(|e| StoreError::LockPoisoned(e.to_string()))?;

        let before = limits.len();
        limits.retain(|_, state| state.window_start.elapsed() < Duration::from_secs(3600));
        let cleaned = before - limits.len();

        if cleaned > 0 {
            debug!("Cleaned up {} expired rate limit states", cleaned);
        }

        Ok(cleaned)
    }

    /// Cleanup expired messages across all mailboxes
    ///
    /// This is an explicit sweep that removes messages whose TTL has expired.
    /// Returns the number of messages cleaned up.
    pub fn cleanup_expired_messages(&self) -> Result<usize, StoreError> {
        let mut messages = self
            .messages
            .write()
            .map_err(|e| StoreError::LockPoisoned(e.to_string()))?;

        let now = Instant::now();
        let mut cleaned = 0;

        for queue in messages.values_mut() {
            let before = queue.len();
            queue.retain(|e| e.expires_at > now);
            cleaned += before - queue.len();
        }

        // Remove empty mailboxes to free memory
        messages.retain(|_, queue| !queue.is_empty());

        if cleaned > 0 {
            debug!("Cleaned up {} expired messages", cleaned);
        }

        Ok(cleaned)
    }

    /// Update the tombstone TTL (for configurable cleanup delays)
    pub fn set_tombstone_ttl(&mut self, ttl_secs: u64) {
        self.tombstone_ttl = Duration::from_secs(ttl_secs);
    }

    /// Update the orphan TTL (for configurable cleanup delays)
    pub fn set_orphan_ttl(&mut self, ttl_secs: u64) {
        self.orphan_ttl = Duration::from_secs(ttl_secs);
    }
}

/// Statistics about the store
#[derive(Debug, Clone)]
pub struct StoreStats {
    pub mailbox_count: usize,
    pub total_messages: usize,
    pub prekey_bundles: usize,
    pub tombstone_count: usize,
    pub orphan_tombstone_count: usize,
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
            session_init: None,
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
