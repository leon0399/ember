//! Persistent mailbox storage using `SQLite`
//!
//! This module provides durable storage for message envelopes that survives
//! node restarts.
//!
//! ## Design Decisions
//!
//! - **`SQLite` with WAL mode**: Enables fast writes and crash recovery
//! - **Bincode serialization**: Compact binary format for envelopes
//! - **Unix timestamps**: Portable, no `Instant` serialization issues
//! - **Serialized access**: A `Mutex` ensures thread-safe access to the database connection
//! - **Per-mailbox self-healing**: The `enqueue` operation performs lightweight cleanup
//!   of expired messages for the target mailbox only, preventing unbounded growth even
//!   if the background cleanup task is delayed.

use bincode::config;
use derivative::Derivative;
use reme_message::{MessageID, OuterEnvelope, RoutingKey};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, info, trace, warn};

use crate::error::NodeError;
use crate::time::{now_secs, timestamp_to_i64};

/// 7 days in seconds - default message TTL
const fn default_ttl_secs() -> u64 {
    7 * 24 * 60 * 60
}

/// `SQLite` commonly defaults to 999 bound parameters per statement.
const SQLITE_MAX_BOUND_VARIABLES: usize = 999;

/// Configuration for the persistent store
#[derive(Debug, Clone, Derivative)]
#[derivative(Default)]
pub struct PersistentStoreConfig {
    /// Maximum messages per routing key (mailbox). Must be > 0.
    #[derivative(Default(value = "1000"))]
    pub max_messages_per_mailbox: usize,
    /// Default TTL for messages without explicit TTL (seconds). Must be > 0.
    #[derivative(Default(value = "default_ttl_secs()"))]
    pub default_ttl_secs: u64,
}

impl PersistentStoreConfig {
    /// Create a new configuration with validation.
    ///
    /// # Errors
    /// Returns `NodeError::InvalidConfig` if:
    /// - `max_messages_per_mailbox` is 0
    /// - `default_ttl_secs` is 0
    pub fn new(max_messages_per_mailbox: usize, default_ttl_secs: u64) -> Result<Self, NodeError> {
        let config = Self {
            max_messages_per_mailbox,
            default_ttl_secs,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration.
    ///
    /// # Errors
    /// Returns `NodeError::InvalidConfig` with all validation errors combined.
    pub fn validate(&self) -> Result<(), NodeError> {
        let mut errors = Vec::new();

        if self.max_messages_per_mailbox == 0 {
            errors.push("max_messages_per_mailbox must be greater than 0");
        }
        if self.default_ttl_secs == 0 {
            errors.push("default_ttl_secs must be greater than 0");
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(NodeError::InvalidConfig(errors.join(", ")))
        }
    }
}

/// A single paginated fetch entry from mailbox storage.
#[derive(Debug, Clone)]
pub struct FetchPageEntry {
    pub row_id: i64,
    pub envelope: OuterEnvelope,
}

/// A bounded page of mailbox messages with an explicit continuation flag.
#[derive(Debug, Clone)]
pub struct FetchPage {
    pub entries: Vec<FetchPageEntry>,
    pub has_more: bool,
}

/// Trait for mailbox storage backends
///
/// This trait abstracts the storage layer for mailbox nodes, allowing
/// different implementations (`SQLite`, in-memory, etc.)
pub trait MailboxStore: Send + Sync {
    /// Store a message in the mailbox for the given routing key
    fn enqueue(&self, routing_key: RoutingKey, envelope: OuterEnvelope) -> Result<(), NodeError>;

    /// Fetch all messages for the given routing key
    fn fetch(&self, routing_key: &RoutingKey) -> Result<Vec<OuterEnvelope>, NodeError>;

    /// Fetch a bounded page of messages for the given routing key.
    ///
    /// Ordering is defined by mailbox row id (`id ASC`), which is the server-owned
    /// insertion order and the continuation contract for paginated fetches.
    fn fetch_page(
        &self,
        routing_key: &RoutingKey,
        limit: usize,
        after: Option<i64>,
    ) -> Result<FetchPage, NodeError>;

    /// Check if a message with the given ID exists for the routing key
    fn has_message(
        &self,
        routing_key: &RoutingKey,
        message_id: &MessageID,
    ) -> Result<bool, NodeError>;

    /// Delete a message by ID (for tombstone support)
    ///
    /// Returns `Ok(true)` if a message was deleted, `Ok(false)` if not found.
    fn delete_message(&self, message_id: &MessageID) -> Result<bool, NodeError>;

    /// Get the `ack_hash` for a message (for tombstone verification)
    ///
    /// Returns the `ack_hash` from the stored message, or None if the message
    /// doesn't exist or has expired.
    fn get_ack_hash(&self, message_id: &MessageID) -> Result<Option<[u8; 16]>, NodeError>;

    /// Remove expired messages
    fn cleanup_expired(&self) -> Result<usize, NodeError>;
}

/// Statistics about the persistent store
#[derive(Debug, Clone)]
pub struct PersistentStoreStats {
    pub mailbox_count: usize,
    pub total_messages: usize,
    pub expired_pending_cleanup: usize,
}

/// Persistent mailbox store backed by `SQLite`
pub struct PersistentMailboxStore {
    conn: Mutex<Connection>,
    config: PersistentStoreConfig,
}

impl PersistentMailboxStore {
    /// Open or create a persistent store at the given path
    pub fn open<P: AsRef<Path>>(path: P, config: PersistentStoreConfig) -> Result<Self, NodeError> {
        let path = path.as_ref();
        info!(path = %path.display(), "opening persistent mailbox store");

        let conn = Connection::open(path)?;
        let store = Self {
            conn: Mutex::new(conn),
            config,
        };
        store.configure_connection()?;
        store.init_schema()?;

        // Log initial stats
        let stats = store.stats()?;
        info!(
            mailboxes = stats.mailbox_count,
            messages = stats.total_messages,
            "persistent store opened"
        );

        Ok(store)
    }

    /// Create an in-memory store (for testing)
    pub fn in_memory(config: PersistentStoreConfig) -> Result<Self, NodeError> {
        trace!("creating in-memory persistent store");
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
            config,
        };
        store.configure_connection()?;
        store.init_schema()?;
        Ok(store)
    }

    /// Configure `SQLite` connection for optimal performance
    fn configure_connection(&self) -> Result<(), NodeError> {
        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

        // Enable WAL mode for better concurrent performance
        conn.execute_batch(
            r"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -64000;
            PRAGMA temp_store = MEMORY;
            PRAGMA mmap_size = 268435456;
            ",
        )?;

        Ok(())
    }

    /// Initialize database schema
    fn init_schema(&self) -> Result<(), NodeError> {
        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

        conn.execute_batch(
            r"
            CREATE TABLE IF NOT EXISTS mailbox_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                routing_key BLOB NOT NULL,
                message_id BLOB NOT NULL UNIQUE,
                envelope_data BLOB NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_mailbox_routing_key
                ON mailbox_messages(routing_key);

            CREATE INDEX IF NOT EXISTS idx_mailbox_expires_at
                ON mailbox_messages(expires_at);

            CREATE INDEX IF NOT EXISTS idx_mailbox_message_id
                ON mailbox_messages(message_id);

            -- Schema version for future migrations
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );

            INSERT OR IGNORE INTO schema_version (version) VALUES (1);
            ",
        )?;

        debug!("persistent store schema initialized");
        Ok(())
    }

    /// Serialize an `OuterEnvelope` to bytes
    fn serialize_envelope(envelope: &OuterEnvelope) -> Result<Vec<u8>, NodeError> {
        let bincode_config = config::standard();
        bincode::encode_to_vec(envelope, bincode_config)
            .map_err(|e| NodeError::Serialization(e.to_string()))
    }

    /// Deserialize bytes to an `OuterEnvelope`
    fn deserialize_envelope(data: &[u8]) -> Result<OuterEnvelope, NodeError> {
        let bincode_config = config::standard();
        let (envelope, _): (OuterEnvelope, _) = bincode::decode_from_slice(data, bincode_config)
            .map_err(|e| NodeError::Deserialization(e.to_string()))?;
        Ok(envelope)
    }

    fn delete_rows(conn: &Connection, ids: &[i64]) -> Result<(), NodeError> {
        for chunk in ids.chunks(SQLITE_MAX_BOUND_VARIABLES) {
            let placeholders: Vec<&str> = chunk.iter().map(|_| "?").collect();
            let sql = format!(
                "DELETE FROM mailbox_messages WHERE id IN ({})",
                placeholders.join(",")
            );

            let mut stmt = conn.prepare(&sql)?;
            let params: Vec<&dyn rusqlite::ToSql> =
                chunk.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
            stmt.execute(params.as_slice())?;
        }

        Ok(())
    }

    /// Get all message IDs for a routing key (for sync protocol)
    pub fn get_message_ids(&self, routing_key: &RoutingKey) -> Result<Vec<MessageID>, NodeError> {
        let now = now_secs();

        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

        let mut stmt = conn.prepare(
            "SELECT message_id FROM mailbox_messages
             WHERE routing_key = ? AND expires_at > ?",
        )?;

        let rows = stmt.query_map(params![&routing_key[..], timestamp_to_i64(now)], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            Ok(bytes)
        })?;

        let mut ids = Vec::new();
        for row in rows {
            let bytes = row?;
            if bytes.len() == 16 {
                let arr: [u8; 16] = bytes.try_into().unwrap();
                ids.push(MessageID::from_bytes(arr));
            } else {
                warn!(
                    len = bytes.len(),
                    "invalid message_id length in database, expected 16 bytes"
                );
            }
        }

        Ok(ids)
    }

    /// Get a specific message by ID (for sync protocol)
    pub fn get_message(&self, message_id: &MessageID) -> Result<Option<OuterEnvelope>, NodeError> {
        let now = now_secs();
        let message_id_bytes = message_id.as_bytes();

        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT envelope_data FROM mailbox_messages
                 WHERE message_id = ? AND expires_at > ?",
                params![&message_id_bytes[..], timestamp_to_i64(now)],
                |row| row.get(0),
            )
            .optional()?;

        match result {
            Some(data) => Ok(Some(Self::deserialize_envelope(&data)?)),
            None => Ok(None),
        }
    }

    /// Delete a message by ID (for tombstone support)
    pub fn delete_message(&self, message_id: &MessageID) -> Result<bool, NodeError> {
        let message_id_bytes = message_id.as_bytes();

        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

        let deleted = conn.execute(
            "DELETE FROM mailbox_messages WHERE message_id = ?",
            params![&message_id_bytes[..]],
        )?;

        Ok(deleted > 0)
    }

    /// Get the `ack_hash` for a message by ID (for Tombstone V2 verification)
    ///
    /// Returns the `ack_hash` from the stored message, or None if the message
    /// doesn't exist or has expired.
    pub fn get_ack_hash(&self, message_id: &MessageID) -> Result<Option<[u8; 16]>, NodeError> {
        match self.get_message(message_id)? {
            Some(envelope) => Ok(Some(envelope.ack_hash)),
            None => Ok(None),
        }
    }

    /// Get store statistics
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // SQLite COUNTs are non-negative
    pub fn stats(&self) -> Result<PersistentStoreStats, NodeError> {
        let now = now_secs();

        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

        let total_messages: i64 = conn.query_row(
            "SELECT COUNT(*) FROM mailbox_messages WHERE expires_at > ?",
            params![timestamp_to_i64(now)],
            |row| row.get(0),
        )?;

        let mailbox_count: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT routing_key) FROM mailbox_messages WHERE expires_at > ?",
            params![timestamp_to_i64(now)],
            |row| row.get(0),
        )?;

        let expired_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM mailbox_messages WHERE expires_at <= ?",
            params![timestamp_to_i64(now)],
            |row| row.get(0),
        )?;

        Ok(PersistentStoreStats {
            mailbox_count: mailbox_count as usize,
            total_messages: total_messages as usize,
            expired_pending_cleanup: expired_count as usize,
        })
    }

    /// Checkpoint WAL to main database file
    pub fn checkpoint(&self) -> Result<(), NodeError> {
        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        debug!("WAL checkpoint completed");
        Ok(())
    }
}

impl MailboxStore for PersistentMailboxStore {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // SQLite COUNT is non-negative
    fn enqueue(&self, routing_key: RoutingKey, envelope: OuterEnvelope) -> Result<(), NodeError> {
        let now = now_secs();

        // Calculate expiration
        let ttl_secs = envelope
            .ttl_hours
            .map_or(self.config.default_ttl_secs, |h| u64::from(h) * 3600);
        let expires_at = now + ttl_secs;

        let envelope_data = Self::serialize_envelope(&envelope)?;
        let message_id_bytes = envelope.message_id.as_bytes();

        let mut conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

        // Use a transaction to ensure atomicity of cleanup + capacity check + insert
        let tx = conn.transaction()?;

        // First, clean up expired messages for this routing key (self-healing)
        tx.execute(
            "DELETE FROM mailbox_messages WHERE routing_key = ? AND expires_at <= ?",
            params![&routing_key[..], timestamp_to_i64(now)],
        )?;

        // Check mailbox capacity
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM mailbox_messages WHERE routing_key = ?",
            params![&routing_key[..]],
            |row| row.get(0),
        )?;

        if count as usize >= self.config.max_messages_per_mailbox {
            warn!(
                routing_key = ?&routing_key[..4],
                count = count,
                "mailbox full"
            );
            return Err(NodeError::MailboxFull);
        }

        // Insert the message
        tx.execute(
            "INSERT OR IGNORE INTO mailbox_messages
             (routing_key, message_id, envelope_data, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?)",
            params![
                &routing_key[..],
                &message_id_bytes[..],
                &envelope_data,
                timestamp_to_i64(expires_at),
                timestamp_to_i64(now)
            ],
        )?;

        tx.commit()?;

        trace!(
            routing_key = ?&routing_key[..4],
            message_id = ?envelope.message_id,
            expires_at = expires_at,
            "message enqueued"
        );

        Ok(())
    }

    fn fetch(&self, routing_key: &RoutingKey) -> Result<Vec<OuterEnvelope>, NodeError> {
        let mut after = None;
        let mut envelopes = Vec::new();

        loop {
            let page = self.fetch_page(routing_key, self.config.max_messages_per_mailbox, after)?;
            let last_row_id = page.entries.last().map(|entry| entry.row_id);
            envelopes.extend(page.entries.into_iter().map(|entry| entry.envelope));

            if !page.has_more {
                break;
            }

            after = last_row_id;
        }

        debug!(
            routing_key = ?&routing_key[..4],
            count = envelopes.len(),
            "messages fetched"
        );

        Ok(envelopes)
    }

    fn fetch_page(
        &self,
        routing_key: &RoutingKey,
        limit: usize,
        after: Option<i64>,
    ) -> Result<FetchPage, NodeError> {
        if limit == 0 {
            return Err(NodeError::InvalidConfig(
                "fetch limit must be greater than 0".to_string(),
            ));
        }

        let now_i64 = timestamp_to_i64(now_secs());
        let scan_limit = limit.saturating_add(1);
        let mut last_scanned_id = after.unwrap_or(0);
        let mut entries = Vec::with_capacity(scan_limit);
        let mut invalid_ids_to_delete = Vec::new();
        let mut exhausted = false;

        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

        while entries.len() < scan_limit {
            let remaining_scan = scan_limit.saturating_sub(entries.len());
            let mut stmt = conn.prepare(
                "SELECT id, envelope_data FROM mailbox_messages
                 WHERE routing_key = ? AND expires_at > ? AND id > ?
                 ORDER BY id ASC
                 LIMIT ?",
            )?;

            let rows = stmt.query_map(
                params![&routing_key[..], now_i64, last_scanned_id, remaining_scan],
                |row| {
                    let id: i64 = row.get(0)?;
                    let data: Vec<u8> = row.get(1)?;
                    Ok((id, data))
                },
            )?;

            let mut fetched_row_count = 0usize;
            let mut batch_last_id = None;

            for row in rows {
                let (id, data) = row?;
                fetched_row_count += 1;
                batch_last_id = Some(id);

                match Self::deserialize_envelope(&data) {
                    Ok(envelope) => entries.push(FetchPageEntry {
                        row_id: id,
                        envelope,
                    }),
                    Err(e) => {
                        warn!(id = id, error = %e, "failed to deserialize envelope, deleting");
                        invalid_ids_to_delete.push(id);
                    }
                }

                if entries.len() >= scan_limit {
                    break;
                }
            }

            if let Some(id) = batch_last_id {
                last_scanned_id = id;
            }

            if fetched_row_count < remaining_scan || batch_last_id.is_none() {
                exhausted = true;
                break;
            }
        }

        if !invalid_ids_to_delete.is_empty() {
            Self::delete_rows(&conn, &invalid_ids_to_delete)?;
        }

        let has_more = entries.len() > limit || !exhausted;
        if entries.len() > limit {
            entries.truncate(limit);
        }

        Ok(FetchPage { entries, has_more })
    }

    fn has_message(
        &self,
        routing_key: &RoutingKey,
        message_id: &MessageID,
    ) -> Result<bool, NodeError> {
        let now = now_secs();
        let message_id_bytes = message_id.as_bytes();

        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM mailbox_messages
                 WHERE routing_key = ? AND message_id = ? AND expires_at > ?",
                params![
                    &routing_key[..],
                    &message_id_bytes[..],
                    timestamp_to_i64(now)
                ],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);

        Ok(exists)
    }

    fn delete_message(&self, message_id: &MessageID) -> Result<bool, NodeError> {
        // Delegate to the inherent method
        PersistentMailboxStore::delete_message(self, message_id)
    }

    fn get_ack_hash(&self, message_id: &MessageID) -> Result<Option<[u8; 16]>, NodeError> {
        // Delegate to the inherent method
        PersistentMailboxStore::get_ack_hash(self, message_id)
    }

    fn cleanup_expired(&self) -> Result<usize, NodeError> {
        let now = now_secs();

        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

        let deleted = conn.execute(
            "DELETE FROM mailbox_messages WHERE expires_at <= ?",
            params![timestamp_to_i64(now)],
        )?;

        if deleted > 0 {
            debug!(deleted = deleted, "expired messages cleaned up");
        }

        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_message::CURRENT_VERSION;

    fn insert_invalid_row(store: &PersistentMailboxStore, routing_key: RoutingKey) -> MessageID {
        let message_id = MessageID::new();
        let expires_at = timestamp_to_i64(now_secs() + 3600);
        let created_at = timestamp_to_i64(now_secs());

        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO mailbox_messages
             (routing_key, message_id, envelope_data, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?)",
            params![
                &routing_key[..],
                &message_id.as_bytes()[..],
                &[0xFFu8, 0x00, 0x01][..],
                expires_at,
                created_at
            ],
        )
        .unwrap();

        message_id
    }

    fn create_test_envelope(routing_key: RoutingKey, ttl_hours: Option<u16>) -> OuterEnvelope {
        OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: 482_253,
            ttl_hours,
            message_id: MessageID::new(),
            ephemeral_key: [0u8; 32],
            ack_hash: [0u8; 16],
            inner_ciphertext: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn test_fetch_is_non_destructive_until_delete() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([1u8; 16]);

        let envelope = create_test_envelope(routing_key, Some(1));
        let message_id = envelope.message_id;

        store.enqueue(routing_key, envelope).unwrap();

        assert!(store.has_message(&routing_key, &message_id).unwrap());

        let fetched = store.fetch(&routing_key).unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].message_id, message_id);

        // Fetch should not delete. Tombstones are the deletion path.
        let fetched_again = store.fetch(&routing_key).unwrap();
        assert_eq!(fetched_again.len(), 1);
        assert_eq!(fetched_again[0].message_id, message_id);

        // Explicit deletion should clear it.
        assert!(store.delete_message(&message_id).unwrap());
        let fetched_after_delete = store.fetch(&routing_key).unwrap();
        assert!(fetched_after_delete.is_empty());
    }

    #[test]
    fn test_mailbox_capacity() {
        let config = PersistentStoreConfig {
            max_messages_per_mailbox: 2,
            ..Default::default()
        };
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([4u8; 16]);

        store
            .enqueue(routing_key, create_test_envelope(routing_key, Some(1)))
            .unwrap();
        store
            .enqueue(routing_key, create_test_envelope(routing_key, Some(1)))
            .unwrap();

        // Third should fail
        let result = store.enqueue(routing_key, create_test_envelope(routing_key, Some(1)));
        assert!(matches!(result, Err(NodeError::MailboxFull)));
    }

    #[test]
    fn test_duplicate_message_id() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([5u8; 16]);

        let envelope = create_test_envelope(routing_key, Some(1));

        // First insert succeeds
        store.enqueue(routing_key, envelope.clone()).unwrap();

        // Second insert with same message_id is ignored (INSERT OR IGNORE)
        store.enqueue(routing_key, envelope).unwrap();

        // Should only have one message
        let fetched = store.fetch(&routing_key).unwrap();
        assert_eq!(fetched.len(), 1);
    }

    #[test]
    fn test_get_message_ids() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([6u8; 16]);

        let env1 = create_test_envelope(routing_key, Some(1));
        let env2 = create_test_envelope(routing_key, Some(1));
        let id1 = env1.message_id;
        let id2 = env2.message_id;

        store.enqueue(routing_key, env1).unwrap();
        store.enqueue(routing_key, env2).unwrap();

        let ids = store.get_message_ids(&routing_key).unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn test_delete_message() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([7u8; 16]);

        let envelope = create_test_envelope(routing_key, Some(1));
        let message_id = envelope.message_id;

        store.enqueue(routing_key, envelope).unwrap();
        assert!(store.has_message(&routing_key, &message_id).unwrap());

        let deleted = store.delete_message(&message_id).unwrap();
        assert!(deleted);

        assert!(!store.has_message(&routing_key, &message_id).unwrap());
    }

    #[test]
    fn test_fetch_deletes_invalid_rows_only() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([8u8; 16]);
        let message_id = MessageID::new();
        let expires_at = timestamp_to_i64(now_secs() + 3600);
        let created_at = timestamp_to_i64(now_secs());

        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO mailbox_messages
                 (routing_key, message_id, envelope_data, expires_at, created_at)
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    &routing_key[..],
                    &message_id.as_bytes()[..],
                    &[0xFFu8, 0x00, 0x01][..],
                    expires_at,
                    created_at
                ],
            )
            .unwrap();
        }

        assert!(store.has_message(&routing_key, &message_id).unwrap());

        let fetched = store.fetch(&routing_key).unwrap();
        assert!(fetched.is_empty());
        assert!(!store.has_message(&routing_key, &message_id).unwrap());
    }

    #[test]
    fn test_fetch_deletes_invalid_rows_in_batches() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([9u8; 16]);
        let expires_at = timestamp_to_i64(now_secs() + 3600);
        let created_at = timestamp_to_i64(now_secs());

        {
            let conn = store.conn.lock().unwrap();
            for _ in 0..1000 {
                let message_id = MessageID::new();
                conn.execute(
                    "INSERT INTO mailbox_messages
                     (routing_key, message_id, envelope_data, expires_at, created_at)
                     VALUES (?, ?, ?, ?, ?)",
                    params![
                        &routing_key[..],
                        &message_id.as_bytes()[..],
                        &[0xFFu8, 0x00, 0x01][..],
                        expires_at,
                        created_at
                    ],
                )
                .unwrap();
            }
        }

        let fetched = store.fetch(&routing_key).unwrap();
        assert!(fetched.is_empty());
        assert!(store.get_message_ids(&routing_key).unwrap().is_empty());
    }

    #[test]
    fn test_fetch_page_returns_oldest_rows_in_id_order() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([12u8; 16]);

        let env1 = create_test_envelope(routing_key, Some(1));
        let env2 = create_test_envelope(routing_key, Some(1));
        let env3 = create_test_envelope(routing_key, Some(1));
        let id1 = env1.message_id;
        let id2 = env2.message_id;
        let id3 = env3.message_id;

        store.enqueue(routing_key, env1).unwrap();
        store.enqueue(routing_key, env2).unwrap();
        store.enqueue(routing_key, env3).unwrap();

        let page = store.fetch_page(&routing_key, 2, None).unwrap();

        assert_eq!(page.entries.len(), 2);
        assert!(page.has_more);
        assert_eq!(page.entries[0].envelope.message_id, id1);
        assert_eq!(page.entries[1].envelope.message_id, id2);

        let next_page = store
            .fetch_page(&routing_key, 2, Some(page.entries[1].row_id))
            .unwrap();

        assert_eq!(next_page.entries.len(), 1);
        assert!(!next_page.has_more);
        assert_eq!(next_page.entries[0].envelope.message_id, id3);
        assert!(next_page.entries[0].row_id > page.entries[1].row_id);
    }

    #[test]
    fn test_fetch_page_skips_invalid_rows_and_keeps_scanning() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([13u8; 16]);

        let invalid_1 = insert_invalid_row(&store, routing_key);
        let invalid_2 = insert_invalid_row(&store, routing_key);

        let env1 = create_test_envelope(routing_key, Some(1));
        let env2 = create_test_envelope(routing_key, Some(1));
        let valid_1 = env1.message_id;
        let valid_2 = env2.message_id;

        store.enqueue(routing_key, env1).unwrap();
        store.enqueue(routing_key, env2).unwrap();

        let page = store.fetch_page(&routing_key, 2, None).unwrap();

        assert_eq!(page.entries.len(), 2);
        assert!(!page.has_more);
        assert_eq!(page.entries[0].envelope.message_id, valid_1);
        assert_eq!(page.entries[1].envelope.message_id, valid_2);
        assert!(!store.has_message(&routing_key, &invalid_1).unwrap());
        assert!(!store.has_message(&routing_key, &invalid_2).unwrap());
    }

    #[test]
    fn test_fetch_page_exhaustion_requires_restart_from_none() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([14u8; 16]);

        let env1 = create_test_envelope(routing_key, Some(1));
        let env2 = create_test_envelope(routing_key, Some(1));
        let first_id = env1.message_id;
        let second_id = env2.message_id;

        store.enqueue(routing_key, env1).unwrap();
        store.enqueue(routing_key, env2).unwrap();

        let first_page = store.fetch_page(&routing_key, 1, None).unwrap();
        assert_eq!(first_page.entries.len(), 1);
        assert_eq!(first_page.entries[0].envelope.message_id, first_id);
        assert!(first_page.has_more);

        let second_page = store
            .fetch_page(&routing_key, 1, Some(first_page.entries[0].row_id))
            .unwrap();
        assert_eq!(second_page.entries.len(), 1);
        assert_eq!(second_page.entries[0].envelope.message_id, second_id);
        assert!(!second_page.has_more);

        let exhausted = store
            .fetch_page(&routing_key, 1, Some(second_page.entries[0].row_id))
            .unwrap();
        assert!(exhausted.entries.is_empty());
        assert!(!exhausted.has_more);

        let restarted = store.fetch_page(&routing_key, 2, None).unwrap();
        assert_eq!(restarted.entries.len(), 2);
        assert_eq!(restarted.entries[0].envelope.message_id, first_id);
        assert_eq!(restarted.entries[1].envelope.message_id, second_id);
    }

    #[test]
    fn test_fetch_page_rejects_zero_limit() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([15u8; 16]);

        let error = store.fetch_page(&routing_key, 0, None).unwrap_err();
        match error {
            NodeError::InvalidConfig(message) => {
                assert!(
                    message.contains("fetch limit"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("expected invalid config, got {other:?}"),
        }
    }

    #[test]
    fn test_stats() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();

        let rk1 = RoutingKey::from_bytes([10u8; 16]);
        let rk2 = RoutingKey::from_bytes([11u8; 16]);

        store
            .enqueue(rk1, create_test_envelope(rk1, Some(1)))
            .unwrap();
        store
            .enqueue(rk1, create_test_envelope(rk1, Some(1)))
            .unwrap();
        store
            .enqueue(rk2, create_test_envelope(rk2, Some(1)))
            .unwrap();

        let stats = store.stats().unwrap();
        assert_eq!(stats.mailbox_count, 2);
        assert_eq!(stats.total_messages, 3);
    }

    #[test]
    fn test_get_message() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([20u8; 16]);

        let envelope = create_test_envelope(routing_key, Some(1));
        let message_id = envelope.message_id;

        store.enqueue(routing_key, envelope.clone()).unwrap();

        // Should find existing message
        let found = store.get_message(&message_id).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().message_id, message_id);

        // Should return None for non-existent ID
        let fake_id = MessageID::new();
        let not_found = store.get_message(&fake_id).unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_config_validation() {
        // Valid config should succeed
        let valid = PersistentStoreConfig::new(100, 3600);
        assert!(valid.is_ok());

        // Zero max_messages should fail
        let zero_capacity = PersistentStoreConfig::new(0, 3600);
        assert!(matches!(zero_capacity, Err(NodeError::InvalidConfig(_))));

        // Zero TTL should fail
        let zero_ttl = PersistentStoreConfig::new(100, 0);
        assert!(matches!(zero_ttl, Err(NodeError::InvalidConfig(_))));

        // Both zero should report combined errors
        let both_zero = PersistentStoreConfig::new(0, 0);
        match both_zero {
            Err(NodeError::InvalidConfig(msg)) => {
                assert!(msg.contains("max_messages_per_mailbox"));
                assert!(msg.contains("default_ttl_secs"));
            }
            _ => panic!("Expected InvalidConfig with both errors"),
        }

        // Default should always be valid
        let default_config = PersistentStoreConfig::default();
        assert!(default_config.validate().is_ok());
    }

    #[test]
    fn test_cleanup_expired() {
        // Use a very short TTL (1 second)
        let config = PersistentStoreConfig {
            max_messages_per_mailbox: 100,
            default_ttl_secs: 1,
        };
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([21u8; 16]);

        // Enqueue with default TTL (1 second)
        store
            .enqueue(routing_key, create_test_envelope(routing_key, None))
            .unwrap();

        // Should have 1 message initially
        let stats = store.stats().unwrap();
        assert_eq!(stats.total_messages, 1);

        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Message should now be expired
        let stats = store.stats().unwrap();
        assert_eq!(stats.expired_pending_cleanup, 1);

        // Cleanup should remove expired message
        let cleaned = store.cleanup_expired().unwrap();
        assert_eq!(cleaned, 1);

        // Should be empty now
        let stats = store.stats().unwrap();
        assert_eq!(stats.total_messages, 0);
        assert_eq!(stats.expired_pending_cleanup, 0);
    }

    #[test]
    fn test_expired_messages_excluded() {
        // Use a very short TTL (1 second)
        let config = PersistentStoreConfig {
            max_messages_per_mailbox: 100,
            default_ttl_secs: 1,
        };
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([22u8; 16]);

        // Enqueue with default TTL (1 second)
        let envelope = create_test_envelope(routing_key, None);
        let message_id = envelope.message_id;
        store.enqueue(routing_key, envelope).unwrap();

        // Should exist initially
        assert!(store.has_message(&routing_key, &message_id).unwrap());
        assert!(!store.get_message_ids(&routing_key).unwrap().is_empty());
        assert!(store.get_message(&message_id).unwrap().is_some());

        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Expired messages should be excluded from queries
        assert!(!store.has_message(&routing_key, &message_id).unwrap());
        assert!(store.get_message_ids(&routing_key).unwrap().is_empty());
        assert!(store.get_message(&message_id).unwrap().is_none());

        // Fetch should also exclude expired messages
        let fetched = store.fetch(&routing_key).unwrap();
        assert!(fetched.is_empty());
    }
}
