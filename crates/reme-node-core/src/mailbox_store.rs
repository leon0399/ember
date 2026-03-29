//! Persistent mailbox storage using `SQLite`
//!
//! This module provides durable storage for message envelopes that survives
//! node restarts.
//!
//! ## Design Decisions
//!
//! - **`SQLite` with WAL mode**: Enables fast writes and crash recovery
//! - **Postcard serialization**: Compact binary format for envelopes
//! - **Unix timestamps**: Portable, no `Instant` serialization issues
//! - **Serialized access**: A `Mutex` ensures thread-safe access to the database connection
//! - **Per-mailbox self-healing**: The `enqueue` operation performs lightweight cleanup
//!   of expired messages for the target mailbox only, preventing unbounded growth even
//!   if the background cleanup task is delayed.

use derivative::Derivative;
use reme_message::{MessageID, OuterEnvelope, RoutingKey};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, info, trace, warn};

use crate::error::NodeError;
use crate::time::{now_secs, timestamp_to_i64};

/// Raw DB row fields for a message, used to pass between helper functions.
struct RawMessageRow {
    id: i64,
    data: Vec<u8>,
    routing_key_bytes: Vec<u8>,
    expires_at: i64,
    created_at: i64,
}

/// Raw DB row fields for classification during fetch.
struct RawFetchRow {
    id: i64,
    data: Vec<u8>,
    msg_id: Option<Vec<u8>>,
    expires_at: i64,
    created_at: i64,
}

/// 7 days in seconds - default message TTL
const fn default_ttl_secs() -> u64 {
    7 * 24 * 60 * 60
}

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

    /// Remove expired messages and expired quarantined rows.
    ///
    /// Returns the total number of rows removed (mailbox + quarantine).
    fn cleanup_expired(&self) -> Result<usize, NodeError>;
}

/// Statistics about the persistent store
#[derive(Debug, Clone)]
pub struct PersistentStoreStats {
    pub mailbox_count: usize,
    pub total_messages: usize,
    pub expired_pending_cleanup: usize,
    pub quarantined_messages: usize,
}

/// Metadata needed to quarantine a corrupt row from `mailbox_messages`.
struct CorruptRow {
    id: i64,
    message_id: Option<Vec<u8>>,
    envelope_data: Vec<u8>,
    error: String,
    expires_at: i64,
    created_at: i64,
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

            CREATE TABLE IF NOT EXISTS quarantined_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_id INTEGER,
                routing_key BLOB NOT NULL,
                message_id BLOB,
                envelope_data BLOB NOT NULL,
                error TEXT NOT NULL,
                quarantined_at INTEGER NOT NULL,
                original_expires_at INTEGER,
                original_created_at INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_quarantine_expires
                ON quarantined_messages(original_expires_at);
            ",
        )?;

        debug!("persistent store schema initialized");
        Ok(())
    }

    /// Serialize an `OuterEnvelope` to bytes
    fn serialize_envelope(envelope: &OuterEnvelope) -> Result<Vec<u8>, NodeError> {
        postcard::to_allocvec(envelope).map_err(|e| NodeError::Serialization(e.to_string()))
    }

    /// Deserialize bytes to an `OuterEnvelope`
    fn deserialize_envelope(data: &[u8]) -> Result<OuterEnvelope, NodeError> {
        let envelope: OuterEnvelope =
            postcard::from_bytes(data).map_err(|e| NodeError::Deserialization(e.to_string()))?;
        Ok(envelope)
    }

    /// Move corrupt rows to the quarantine table and delete from `mailbox_messages`.
    ///
    /// If the quarantine INSERT fails, falls back to deleting the row (pre-quarantine
    /// behavior) and logs at error level.
    fn quarantine_rows(
        conn: &Connection,
        routing_key: &RoutingKey,
        rows: &[CorruptRow],
    ) -> Result<(), NodeError> {
        if rows.is_empty() {
            return Ok(());
        }

        let now = timestamp_to_i64(now_secs());

        // unchecked_transaction takes &self (not &mut) and auto-rollbacks on drop
        let tx = conn.unchecked_transaction()?;

        for row in rows {
            let result = tx.execute(
                "INSERT INTO quarantined_messages
                 (original_id, routing_key, message_id, envelope_data, error,
                  quarantined_at, original_expires_at, original_created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    row.id,
                    &routing_key[..],
                    row.message_id.as_deref(),
                    &row.envelope_data,
                    &row.error,
                    now,
                    row.expires_at,
                    row.created_at,
                ],
            );

            if let Err(e) = result {
                // Fallback: still delete the corrupt row (pre-quarantine behavior).
                tracing::error!(
                    id = row.id,
                    error = %e,
                    "failed to quarantine corrupt row, falling back to delete"
                );
            }

            tx.execute("DELETE FROM mailbox_messages WHERE id = ?", params![row.id])?;
        }

        tx.commit()?;

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
            let Ok(arr): Result<[u8; 16], _> = bytes.try_into() else {
                warn!("invalid message_id length in database, expected 16 bytes");
                continue;
            };
            ids.push(MessageID::from_bytes(arr));
        }

        Ok(ids)
    }

    /// Get a specific message by ID (for sync protocol)
    ///
    /// If the stored envelope fails deserialization, the corrupt row is quarantined
    /// and `Ok(None)` is returned.
    pub fn get_message(&self, message_id: &MessageID) -> Result<Option<OuterEnvelope>, NodeError> {
        let now = now_secs();
        let message_id_bytes = message_id.as_bytes();

        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

        #[allow(clippy::type_complexity)]
        let result: Option<(i64, Vec<u8>, Vec<u8>, i64, i64)> = conn
            .query_row(
                "SELECT id, envelope_data, routing_key, expires_at, created_at
                 FROM mailbox_messages
                 WHERE message_id = ? AND expires_at > ?",
                params![&message_id_bytes[..], timestamp_to_i64(now)],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;

        let Some((id, data, routing_key_bytes, expires_at, created_at)) = result else {
            return Ok(None);
        };

        match Self::deserialize_envelope(&data) {
            Ok(envelope) => Ok(Some(envelope)),
            Err(e) => {
                Self::quarantine_corrupt_message(
                    &conn,
                    &e,
                    message_id_bytes,
                    RawMessageRow {
                        id,
                        data,
                        routing_key_bytes,
                        expires_at,
                        created_at,
                    },
                )?;
                Ok(None)
            }
        }
    }

    /// Build a `CorruptRow` from raw DB fields and quarantine it.
    fn quarantine_corrupt_message(
        conn: &Connection,
        error: &NodeError,
        message_id_bytes: &[u8],
        row: RawMessageRow,
    ) -> Result<(), NodeError> {
        let RawMessageRow {
            id,
            data,
            routing_key_bytes,
            expires_at,
            created_at,
        } = row;
        warn!(message_id = ?message_id_bytes, error = %error, "corrupt message found, quarantining");

        let routing_key_arr: [u8; 16] = routing_key_bytes.try_into().unwrap_or_else(|_| {
            warn!("routing_key has unexpected length, using zeroed key for quarantine");
            [0u8; 16]
        });
        let routing_key = RoutingKey::from_bytes(routing_key_arr);

        let corrupt = CorruptRow {
            id,
            message_id: Some(message_id_bytes.to_vec()),
            envelope_data: data,
            error: error.to_string(),
            expires_at,
            created_at,
        };
        Self::quarantine_rows(conn, &routing_key, &[corrupt])
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

        let quarantined_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM quarantined_messages", [], |row| {
                row.get(0)
            })?;

        Ok(PersistentStoreStats {
            mailbox_count: mailbox_count as usize,
            total_messages: total_messages as usize,
            expired_pending_cleanup: expired_count as usize,
            quarantined_messages: quarantined_count as usize,
        })
    }

    /// Export messages with optional filters. Used by `reme-node export`.
    ///
    /// Returns non-expired envelopes matching the given filters, ordered by
    /// creation time (ascending).
    pub fn export_messages(
        &self,
        routing_key: Option<&RoutingKey>,
        since_secs: Option<i64>,
        limit: Option<usize>,
    ) -> Result<Vec<OuterEnvelope>, NodeError> {
        use std::fmt::Write;

        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;
        let now = timestamp_to_i64(now_secs());

        let mut sql =
            String::from("SELECT envelope_data FROM mailbox_messages WHERE expires_at > ?1");
        let mut param_count = 1;

        if routing_key.is_some() {
            param_count += 1;
            let _ = write!(sql, " AND routing_key = ?{param_count}");
        }
        if since_secs.is_some() {
            param_count += 1;
            let _ = write!(sql, " AND created_at >= ?{param_count}");
        }
        sql.push_str(" ORDER BY created_at ASC");
        if let Some(lim) = limit {
            let _ = write!(sql, " LIMIT {lim}");
        }

        let mut stmt = conn.prepare(&sql)?;

        // Build positional params dynamically
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(now)];
        if let Some(rk) = routing_key {
            params.push(Box::new(rk.0.to_vec()));
        }
        if let Some(since) = since_secs {
            params.push(Box::new(since));
        }
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(AsRef::as_ref).collect();

        let rows = stmt.query_map(param_refs.as_slice(), |row| row.get::<_, Vec<u8>>(0))?;

        let mut envelopes = Vec::new();
        for row in rows {
            let data = row?;
            match Self::deserialize_envelope(&data) {
                Ok(env) => envelopes.push(env),
                Err(e) => {
                    warn!("Skipping corrupt envelope in export: {e}");
                }
            }
        }
        Ok(envelopes)
    }

    /// Deserialize a row, pushing it to `entries` on success or `corrupt` on failure.
    fn classify_row(
        row: RawFetchRow,
        entries: &mut Vec<FetchPageEntry>,
        corrupt: &mut Vec<CorruptRow>,
    ) {
        let RawFetchRow {
            id,
            data,
            msg_id,
            expires_at,
            created_at,
        } = row;
        match Self::deserialize_envelope(&data) {
            Ok(envelope) => entries.push(FetchPageEntry {
                row_id: id,
                envelope,
            }),
            Err(e) => {
                warn!(id = id, error = %e, "failed to deserialize envelope, quarantining");
                corrupt.push(CorruptRow {
                    id,
                    message_id: msg_id,
                    envelope_data: data,
                    error: e.to_string(),
                    expires_at,
                    created_at,
                });
            }
        }
    }

    /// Checkpoint WAL to main database file
    pub fn checkpoint(&self) -> Result<(), NodeError> {
        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        debug!("WAL checkpoint completed");
        Ok(())
    }

    /// Delete expired messages and return the count.
    fn delete_expired_messages(conn: &Connection, now_i64: i64) -> Result<usize, NodeError> {
        let deleted = conn.execute(
            "DELETE FROM mailbox_messages WHERE expires_at <= ?",
            params![now_i64],
        )?;
        if deleted > 0 {
            debug!(deleted = deleted, "expired messages cleaned up");
        }
        Ok(deleted)
    }

    /// Delete expired quarantined rows and return the count.
    fn delete_expired_quarantined(
        conn: &Connection,
        now_i64: i64,
        default_ttl_secs: u64,
    ) -> Result<usize, NodeError> {
        let fallback_ttl = timestamp_to_i64(default_ttl_secs);
        let deleted = conn.execute(
            "DELETE FROM quarantined_messages
             WHERE COALESCE(original_expires_at, quarantined_at + ?) <= ?",
            params![fallback_ttl, now_i64],
        )?;
        if deleted > 0 {
            debug!(deleted = deleted, "expired quarantined rows cleaned up");
        }
        Ok(deleted)
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
        let mut corrupt_rows: Vec<CorruptRow> = Vec::new();
        let mut exhausted = false;

        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

        while entries.len() < scan_limit {
            let remaining_scan = scan_limit.saturating_sub(entries.len());
            let mut stmt = conn.prepare(
                "SELECT id, envelope_data, message_id, expires_at, created_at
                 FROM mailbox_messages
                 WHERE routing_key = ? AND expires_at > ? AND id > ?
                 ORDER BY id ASC
                 LIMIT ?",
            )?;

            let rows = stmt.query_map(
                params![&routing_key[..], now_i64, last_scanned_id, remaining_scan],
                |row| {
                    let id: i64 = row.get(0)?;
                    let data: Vec<u8> = row.get(1)?;
                    let msg_id: Option<Vec<u8>> = row.get(2)?;
                    let expires_at: i64 = row.get(3)?;
                    let created_at: i64 = row.get(4)?;
                    Ok((id, data, msg_id, expires_at, created_at))
                },
            )?;

            let mut fetched_row_count = 0usize;
            let mut batch_last_id = None;

            for row in rows {
                let (id, data, msg_id, expires_at, created_at) = row?;
                fetched_row_count += 1;
                batch_last_id = Some(id);

                Self::classify_row(
                    RawFetchRow {
                        id,
                        data,
                        msg_id,
                        expires_at,
                        created_at,
                    },
                    &mut entries,
                    &mut corrupt_rows,
                );

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

        if !corrupt_rows.is_empty() {
            Self::quarantine_rows(&conn, routing_key, &corrupt_rows)?;
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
        Self::delete_message(self, message_id)
    }

    fn get_ack_hash(&self, message_id: &MessageID) -> Result<Option<[u8; 16]>, NodeError> {
        // Delegate to the inherent method
        Self::get_ack_hash(self, message_id)
    }

    fn cleanup_expired(&self) -> Result<usize, NodeError> {
        let now_i64 = timestamp_to_i64(now_secs());
        let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

        let deleted = Self::delete_expired_messages(&conn, now_i64)?;
        let quarantine_deleted =
            Self::delete_expired_quarantined(&conn, now_i64, self.config.default_ttl_secs)?;

        Ok(deleted + quarantine_deleted)
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
    fn test_fetch_quarantines_invalid_rows() {
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

        // Verify row was quarantined, not just deleted
        let stats = store.stats().unwrap();
        assert_eq!(stats.quarantined_messages, 1);

        // Verify raw bytes preserved
        let conn = store.conn.lock().unwrap();
        let q_data: Vec<u8> = conn
            .query_row(
                "SELECT envelope_data FROM quarantined_messages LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(q_data, vec![0xFFu8, 0x00, 0x01]);
    }

    #[test]
    fn test_fetch_quarantines_invalid_rows_in_batches() {
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

        // All 1000 corrupt rows should be quarantined, not deleted
        let stats = store.stats().unwrap();
        assert_eq!(stats.quarantined_messages, 1000);
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

        store.enqueue(routing_key, envelope).unwrap();

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

    #[test]
    fn test_get_message_quarantines_corrupt_row() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([24u8; 16]);
        let message_id = insert_invalid_row(&store, routing_key);

        // get_message should return None (message is effectively gone)
        let result = store.get_message(&message_id);
        assert!(result.unwrap().is_none());

        // Row should be quarantined
        let stats = store.stats().unwrap();
        assert_eq!(stats.quarantined_messages, 1);

        // Original row should be gone
        assert!(!store.has_message(&routing_key, &message_id).unwrap());
    }

    #[test]
    fn test_quarantine_rows_moves_to_quarantine_table() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let routing_key = RoutingKey::from_bytes([23u8; 16]);

        let message_id = MessageID::new();
        let now = timestamp_to_i64(now_secs());
        let expires = timestamp_to_i64(now_secs() + 3600);
        let corrupt_data = vec![0xFFu8, 0x00, 0x01];

        let original_id;
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO mailbox_messages
                 (routing_key, message_id, envelope_data, expires_at, created_at)
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    &routing_key[..],
                    &message_id.as_bytes()[..],
                    &corrupt_data[..],
                    expires,
                    now
                ],
            )
            .unwrap();
            original_id = conn.last_insert_rowid();
        }

        {
            let conn = store.conn.lock().unwrap();
            let corrupt = CorruptRow {
                id: original_id,
                message_id: Some(message_id.as_bytes().to_vec()),
                envelope_data: corrupt_data.clone(),
                error: "test error".to_string(),
                expires_at: expires,
                created_at: now,
            };
            PersistentMailboxStore::quarantine_rows(&conn, &routing_key, &[corrupt]).unwrap();
        }

        // Original row should be gone
        assert!(!store.has_message(&routing_key, &message_id).unwrap());

        // Quarantine table should have the row
        let stats = store.stats().unwrap();
        assert_eq!(stats.quarantined_messages, 1);

        // Verify quarantine row contents
        let conn = store.conn.lock().unwrap();
        let (q_data, q_error, q_orig_id): (Vec<u8>, String, i64) = conn
            .query_row(
                "SELECT envelope_data, error, original_id FROM quarantined_messages LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(q_data, corrupt_data);
        assert_eq!(q_error, "test error");
        assert_eq!(q_orig_id, original_id);
    }

    #[test]
    fn test_stats_includes_quarantine_count() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();

        let stats = store.stats().unwrap();
        assert_eq!(stats.quarantined_messages, 0);
    }

    #[test]
    fn test_cleanup_removes_expired_quarantined_rows() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();

        // Insert a quarantined row with an already-expired timestamp
        let past = timestamp_to_i64(now_secs().saturating_sub(3600));
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO quarantined_messages
                 (original_id, routing_key, message_id, envelope_data, error,
                  quarantined_at, original_expires_at, original_created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    1i64,
                    &[1u8; 16][..],
                    &[2u8; 16][..],
                    &[0xFFu8][..],
                    "test error",
                    past,
                    past,
                    past,
                ],
            )
            .unwrap();
        }

        assert_eq!(store.stats().unwrap().quarantined_messages, 1);

        store.cleanup_expired().unwrap();

        assert_eq!(store.stats().unwrap().quarantined_messages, 0);
    }
}
