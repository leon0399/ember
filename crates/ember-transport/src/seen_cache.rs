//! Message ID deduplication cache for loop prevention.
//!
//! Tracks seen message IDs with TTL expiry to prevent infinite loops
//! when messages traverse multiple nodes and MQTT brokers.

use ember_message::MessageID;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default TTL for seen entries (1 hour).
pub const DEFAULT_TTL: Duration = Duration::from_secs(3600);

/// Default maximum cache size (100,000 entries).
pub const DEFAULT_MAX_SIZE: usize = 100_000;

/// Time-bounded cache for tracking seen message IDs.
///
/// Used for loop prevention in mesh topologies where messages
/// may traverse multiple nodes and MQTT brokers.
pub struct SeenCache {
    /// Map from `message_id` to when it was first seen
    seen: HashMap<MessageID, Instant>,
    /// Time-to-live for entries
    ttl: Duration,
    /// Maximum number of entries (FIFO eviction when exceeded)
    max_size: usize,
    /// Timestamp of last cleanup
    last_cleanup: Instant,
    /// Cleanup interval (time-based cleanup of expired entries)
    cleanup_interval: Duration,
}

impl SeenCache {
    /// Create a new `SeenCache` with specified TTL and max size.
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        Self {
            seen: HashMap::with_capacity(max_size.min(1000)),
            ttl,
            max_size,
            last_cleanup: Instant::now(),
            cleanup_interval: Duration::from_secs(60), // Cleanup every minute
        }
    }

    /// Create a `SeenCache` with default settings.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_MAX_SIZE)
    }

    /// Check if a message was seen before and mark it as seen.
    ///
    /// Returns `true` if the message was NOT seen before (first time).
    /// Returns `false` if the message was already seen (duplicate).
    ///
    /// This is the primary operation for deduplication.
    pub fn check_and_mark(&mut self, message_id: &MessageID) -> bool {
        let now = Instant::now();

        // Periodic cleanup
        if now.duration_since(self.last_cleanup) > self.cleanup_interval {
            self.cleanup_expired(now);
        }

        // Check if already seen (and not expired)
        if let Some(&seen_at) = self.seen.get(message_id) {
            if now.duration_since(seen_at) < self.ttl {
                return false; // Already seen
            }
            // Expired, will be updated below
        }

        // Mark as seen
        self.seen.insert(*message_id, now);

        // Evict oldest entries if over capacity
        if self.seen.len() > self.max_size {
            self.evict_oldest();
        }

        true // First time seeing this message
    }

    /// Check if a message was seen without marking it.
    pub fn was_seen(&self, message_id: &MessageID) -> bool {
        if let Some(&seen_at) = self.seen.get(message_id) {
            Instant::now().duration_since(seen_at) < self.ttl
        } else {
            false
        }
    }

    /// Mark a message as seen without checking first.
    ///
    /// Use this after successfully publishing a message to prevent duplicates.
    pub fn mark(&mut self, message_id: &MessageID) {
        let now = Instant::now();

        // Periodic cleanup
        if now.duration_since(self.last_cleanup) > self.cleanup_interval {
            self.cleanup_expired(now);
        }

        self.seen.insert(*message_id, now);

        // Evict oldest entries if over capacity
        if self.seen.len() > self.max_size {
            self.evict_oldest();
        }
    }

    /// Remove expired entries from the cache.
    pub fn cleanup_expired(&mut self, now: Instant) {
        self.seen
            .retain(|_, &mut seen_at| now.duration_since(seen_at) < self.ttl);
        self.last_cleanup = now;
    }

    /// Evict oldest entries until under `max_size`.
    ///
    /// Uses `select_nth_unstable_by_key` for O(N) average performance
    /// instead of O(N log N) full sort.
    fn evict_oldest(&mut self) {
        // Remove 10% when over capacity
        let target_size = self.max_size * 9 / 10;

        if self.seen.len() <= target_size {
            return;
        }

        let to_remove = self.seen.len() - target_size;

        // Collect (id, seen_at) pairs
        let mut entries: Vec<_> = self.seen.iter().map(|(k, v)| (*k, *v)).collect();

        // Partial sort: partition around the Nth oldest element (O(N) average)
        // After this, entries[..to_remove] contains the oldest entries (unordered)
        entries.select_nth_unstable_by_key(to_remove - 1, |(_, seen_at)| *seen_at);

        // Remove the oldest entries
        for (id, _) in entries.into_iter().take(to_remove) {
            self.seen.remove(&id);
        }
    }

    /// Get the current number of entries.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.seen.clear();
    }
}

impl Default for SeenCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Thread-safe wrapper around `SeenCache`.
pub struct SharedSeenCache(Mutex<SeenCache>);

impl SharedSeenCache {
    /// Create a new `SharedSeenCache`.
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        Self(Mutex::new(SeenCache::new(ttl, max_size)))
    }

    /// Create with default settings.
    pub fn with_defaults() -> Self {
        Self(Mutex::new(SeenCache::with_defaults()))
    }

    /// Check if a message was seen before and mark it as seen.
    ///
    /// Returns `true` if the message was NOT seen before.
    /// Returns `false` if the message was already seen.
    /// On lock poisoning: fail-open (returns `true`) to avoid dropping messages.
    pub fn check_and_mark(&self, message_id: &MessageID) -> bool {
        let Ok(mut guard) = self.0.lock() else {
            tracing::warn!("SeenCache lock poisoned, fail-open: treating message as unseen");
            return true;
        };
        guard.check_and_mark(message_id)
    }

    /// Check if a message was seen without marking it.
    pub fn was_seen(&self, message_id: &MessageID) -> bool {
        let Ok(guard) = self.0.lock() else {
            return false;
        };
        guard.was_seen(message_id)
    }

    /// Mark a message as seen without checking first.
    ///
    /// Use this after successfully publishing a message to prevent duplicates.
    pub fn mark(&self, message_id: &MessageID) {
        let Ok(mut guard) = self.0.lock() else {
            return;
        };
        guard.mark(message_id);
    }

    /// Get the current number of entries.
    pub fn len(&self) -> usize {
        let Ok(guard) = self.0.lock() else {
            return 0;
        };
        guard.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all entries.
    pub fn clear(&self) {
        let Ok(mut guard) = self.0.lock() else {
            return;
        };
        guard.clear();
    }
}

impl Default for SharedSeenCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_message_id(n: u8) -> MessageID {
        MessageID::from_bytes([n; 16])
    }

    #[test]
    fn test_first_time_returns_true() {
        let mut cache = SeenCache::with_defaults();
        let id = make_message_id(1);

        assert!(cache.check_and_mark(&id));
    }

    #[test]
    fn test_duplicate_returns_false() {
        let mut cache = SeenCache::with_defaults();
        let id = make_message_id(1);

        assert!(cache.check_and_mark(&id));
        assert!(!cache.check_and_mark(&id)); // Second time
        assert!(!cache.check_and_mark(&id)); // Third time
    }

    #[test]
    fn test_different_ids_all_return_true() {
        let mut cache = SeenCache::with_defaults();

        for i in 0..100 {
            let id = make_message_id(i);
            assert!(cache.check_and_mark(&id));
        }
    }

    #[test]
    fn test_was_seen() {
        let mut cache = SeenCache::with_defaults();
        let id = make_message_id(1);

        assert!(!cache.was_seen(&id));
        cache.check_and_mark(&id);
        assert!(cache.was_seen(&id));
    }

    #[test]
    fn test_ttl_expiry() {
        let mut cache = SeenCache::new(Duration::from_millis(10), 1000);
        let id = make_message_id(1);

        assert!(cache.check_and_mark(&id));
        assert!(!cache.check_and_mark(&id));

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));

        // Should be treated as new after expiry
        assert!(cache.check_and_mark(&id));
    }

    #[test]
    fn test_max_size_eviction() {
        let mut cache = SeenCache::new(Duration::from_secs(3600), 10);

        // Add 20 entries
        for i in 0..20 {
            cache.check_and_mark(&make_message_id(i));
        }

        // Should have evicted down to 9 (10 * 90%)
        assert!(cache.len() <= 10);
    }

    #[test]
    fn test_shared_cache() {
        let cache = SharedSeenCache::with_defaults();
        let id = make_message_id(1);

        assert!(cache.check_and_mark(&id));
        assert!(!cache.check_and_mark(&id));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_clear() {
        let mut cache = SeenCache::with_defaults();

        for i in 0..10 {
            cache.check_and_mark(&make_message_id(i));
        }

        assert_eq!(cache.len(), 10);
        cache.clear();
        assert!(cache.is_empty());
    }
}
