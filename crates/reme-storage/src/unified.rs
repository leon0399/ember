//! Unified storage for embedded node with thread-safe access.
//!
//! `UnifiedStorage` combines client storage (contacts, messages, outbox) with
//! node mailbox storage in a single SQLite database. Uses `Mutex<Connection>`
//! for thread-safe access required by async operations.

use async_trait::async_trait;
use reme_identity::{InvalidPublicKey, PublicID};
use reme_message::{Content, ContentId, MessageID, OuterEnvelope, RoutingKey};
use reme_node_core::{MailboxStorage, StorageError as NodeStorageError};
use reme_outbox::{
    AttemptError, AttemptResult, DeliveryConfirmation, OutboxEntryId, OutboxStore, PendingMessage,
    TransportAttempt,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, trace, warn};

/// Errors from unified storage operations.
#[derive(Debug, Error)]
pub enum UnifiedStorageError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(#[from] InvalidPublicKey),

    #[error("Not found")]
    NotFound,

    #[error("Already exists")]
    AlreadyExists,

    #[error("Lock poisoned")]
    LockPoisoned,

    #[error("Mailbox full")]
    MailboxFull,
}

impl From<UnifiedStorageError> for NodeStorageError {
    fn from(e: UnifiedStorageError) -> Self {
        match e {
            UnifiedStorageError::Database(e) => NodeStorageError::Database(e.to_string()),
            UnifiedStorageError::Serialization(msg) => NodeStorageError::Serialization(msg),
            UnifiedStorageError::InvalidPublicKey(e) => NodeStorageError::Database(e.to_string()),
            UnifiedStorageError::NotFound => NodeStorageError::Database("Not found".to_string()),
            UnifiedStorageError::AlreadyExists => {
                NodeStorageError::Database("Already exists".to_string())
            }
            UnifiedStorageError::LockPoisoned => NodeStorageError::LockPoisoned,
            UnifiedStorageError::MailboxFull => NodeStorageError::MailboxFull,
        }
    }
}

/// Thread-safe unified storage for client + node operations.
///
/// Combines:
/// - Contact storage
/// - Message storage
/// - Outbox storage (OutboxStore trait)
/// - Mailbox storage (MailboxStorage trait for embedded node)
pub struct UnifiedStorage {
    conn: Mutex<Connection>,
}

impl UnifiedStorage {
    /// Maximum messages per routing key (mailbox).
    const MAX_MESSAGES_PER_MAILBOX: usize = 1000;

    /// Default TTL for messages (7 days in seconds).
    const DEFAULT_TTL_SECS: u64 = 7 * 24 * 60 * 60;

    /// Open or create storage at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, UnifiedStorageError> {
        let path = path.as_ref();
        debug!(path = %path.display(), "opening unified storage");
        let conn = Connection::open(path)?;
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.init_schema()?;
        storage.configure_connection()?;
        debug!("unified storage initialized");
        Ok(storage)
    }

    /// Create an in-memory database (for testing).
    pub fn in_memory() -> Result<Self, UnifiedStorageError> {
        trace!("creating in-memory unified storage");
        let conn = Connection::open_in_memory()?;
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.init_schema()?;
        storage.configure_connection()?;
        Ok(storage)
    }

    /// Configure SQLite connection for optimal performance.
    fn configure_connection(&self) -> Result<(), UnifiedStorageError> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -64000;
            PRAGMA temp_store = MEMORY;
            "#,
        )?;
        Ok(())
    }

    /// Initialize database schema.
    fn init_schema(&self) -> Result<(), UnifiedStorageError> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        conn.execute_batch(
            r#"
            -- Contact storage
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id BLOB NOT NULL UNIQUE,
                name TEXT,
                created_at INTEGER NOT NULL
            );

            -- Message storage
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id BLOB NOT NULL UNIQUE,
                contact_id INTEGER NOT NULL,
                direction TEXT NOT NULL CHECK (direction IN ('sent', 'received')),
                content_type TEXT NOT NULL,
                body TEXT,
                created_at INTEGER NOT NULL,
                delivered_at INTEGER,
                read_at INTEGER,
                FOREIGN KEY (contact_id) REFERENCES contacts(id)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_contact ON messages(contact_id);
            CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);

            -- Outbox for pending outgoing messages
            CREATE TABLE IF NOT EXISTS outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_id BLOB NOT NULL,
                content_id BLOB NOT NULL,
                message_id BLOB NOT NULL,
                envelope_bytes BLOB NOT NULL,
                inner_bytes BLOB NOT NULL,
                created_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER,
                next_retry_at_ms INTEGER,
                confirmed_at_ms INTEGER,
                expired_at_ms INTEGER,
                confirmation_type TEXT,
                confirmation_data BLOB
            );

            CREATE INDEX IF NOT EXISTS idx_outbox_content_id ON outbox(content_id);
            CREATE INDEX IF NOT EXISTS idx_outbox_recipient ON outbox(recipient_id);
            CREATE INDEX IF NOT EXISTS idx_outbox_retry
                ON outbox(next_retry_at_ms)
                WHERE confirmed_at_ms IS NULL AND expired_at_ms IS NULL;

            -- Delivery attempts
            CREATE TABLE IF NOT EXISTS outbox_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                outbox_id INTEGER NOT NULL REFERENCES outbox(id) ON DELETE CASCADE,
                transport_id TEXT NOT NULL,
                attempted_at_ms INTEGER NOT NULL,
                result_type TEXT NOT NULL,
                error_type TEXT,
                error_message TEXT,
                error_transient INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_attempts_outbox ON outbox_attempts(outbox_id);

            -- Mailbox for embedded node
            CREATE TABLE IF NOT EXISTS mailbox_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                routing_key BLOB NOT NULL,
                message_id BLOB NOT NULL UNIQUE,
                envelope_data BLOB NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_mailbox_routing_key ON mailbox_messages(routing_key);
            CREATE INDEX IF NOT EXISTS idx_mailbox_expires_at ON mailbox_messages(expires_at);
            CREATE INDEX IF NOT EXISTS idx_mailbox_message_id ON mailbox_messages(message_id);
            "#,
        )?;
        Ok(())
    }

    // ============================================
    // Helper methods
    // ============================================

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn serialize_envelope(envelope: &OuterEnvelope) -> Result<Vec<u8>, UnifiedStorageError> {
        let config = bincode::config::standard();
        bincode::encode_to_vec(envelope, config)
            .map_err(|e| UnifiedStorageError::Serialization(e.to_string()))
    }

    fn deserialize_envelope(data: &[u8]) -> Result<OuterEnvelope, UnifiedStorageError> {
        let config = bincode::config::standard();
        let (envelope, _): (OuterEnvelope, _) = bincode::decode_from_slice(data, config)
            .map_err(|e| UnifiedStorageError::Serialization(e.to_string()))?;
        Ok(envelope)
    }

    // ============================================
    // Contact operations
    // ============================================

    /// Add a contact.
    pub fn add_contact(
        &self,
        public_id: &PublicID,
        name: Option<&str>,
    ) -> Result<i64, UnifiedStorageError> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        let public_id_bytes = public_id.to_bytes();
        let now = Self::now_secs() as i64;

        conn.execute(
            "INSERT INTO contacts (public_id, name, created_at) VALUES (?, ?, ?)",
            params![&public_id_bytes[..], name, now],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Get contact ID by public ID.
    pub fn get_contact_id(&self, public_id: &PublicID) -> Result<i64, UnifiedStorageError> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        let public_id_bytes = public_id.to_bytes();
        conn.query_row(
            "SELECT id FROM contacts WHERE public_id = ?",
            params![&public_id_bytes[..]],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(UnifiedStorageError::NotFound)
    }

    /// Get contact public ID by contact ID.
    pub fn get_contact_public_id(&self, contact_id: i64) -> Result<PublicID, UnifiedStorageError> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        let bytes: Vec<u8> = conn
            .query_row(
                "SELECT public_id FROM contacts WHERE id = ?",
                params![contact_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(UnifiedStorageError::NotFound)?;

        if bytes.len() != 32 {
            return Err(UnifiedStorageError::Serialization(
                "Invalid public_id length".to_string(),
            ));
        }

        let public_id_bytes: [u8; 32] = bytes.try_into().unwrap();
        Ok(PublicID::try_from_bytes(&public_id_bytes)?)
    }

    /// List all contacts.
    pub fn list_contacts(&self) -> Result<Vec<(i64, PublicID, Option<String>)>, UnifiedStorageError> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        let mut stmt = conn.prepare("SELECT id, public_id, name FROM contacts ORDER BY name, id")?;

        let rows = stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let public_id_bytes: Vec<u8> = row.get(1)?;
            let name: Option<String> = row.get(2)?;
            Ok((id, public_id_bytes, name))
        })?;

        let mut contacts = Vec::new();
        for row in rows {
            let (id, public_id_bytes, name) = row?;
            if public_id_bytes.len() != 32 {
                continue;
            }
            let public_id_arr: [u8; 32] = public_id_bytes.try_into().unwrap();
            if let Ok(public_id) = PublicID::try_from_bytes(&public_id_arr) {
                contacts.push((id, public_id, name));
            }
        }

        Ok(contacts)
    }

    // ============================================
    // Message operations
    // ============================================

    /// Store a sent message.
    pub fn store_sent_message(
        &self,
        contact_id: i64,
        message_id: MessageID,
        content: &Content,
    ) -> Result<(), UnifiedStorageError> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        let now = Self::now_secs() as i64;

        let (content_type, body) = match content {
            Content::Text(text) => ("text", Some(text.body.as_str())),
            Content::Receipt(_) => ("receipt", None),
            _ => ("unknown", None),
        };

        let message_id_bytes = message_id.as_bytes();

        conn.execute(
            "INSERT INTO messages (message_id, contact_id, direction, content_type, body, created_at)
             VALUES (?, ?, 'sent', ?, ?, ?)",
            params![&message_id_bytes[..], contact_id, content_type, body, now],
        )?;

        Ok(())
    }

    /// Store a received message.
    pub fn store_received_message(
        &self,
        contact_id: i64,
        message_id: MessageID,
        content: &Content,
    ) -> Result<(), UnifiedStorageError> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        let now = Self::now_secs() as i64;

        let (content_type, body) = match content {
            Content::Text(text) => ("text", Some(text.body.as_str())),
            Content::Receipt(_) => ("receipt", None),
            _ => ("unknown", None),
        };

        let message_id_bytes = message_id.as_bytes();

        conn.execute(
            "INSERT INTO messages (message_id, contact_id, direction, content_type, body, created_at)
             VALUES (?, ?, 'received', ?, ?, ?)",
            params![&message_id_bytes[..], contact_id, content_type, body, now],
        )?;

        Ok(())
    }

    /// Mark a message as delivered.
    pub fn mark_delivered(&self, message_id: MessageID) -> Result<(), UnifiedStorageError> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        let now = Self::now_secs() as i64;
        let message_id_bytes = message_id.as_bytes();

        conn.execute(
            "UPDATE messages SET delivered_at = ? WHERE message_id = ?",
            params![now, &message_id_bytes[..]],
        )?;

        Ok(())
    }

    /// Mark a message as read.
    pub fn mark_read(&self, message_id: MessageID) -> Result<(), UnifiedStorageError> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        let now = Self::now_secs() as i64;
        let message_id_bytes = message_id.as_bytes();

        conn.execute(
            "UPDATE messages SET read_at = ? WHERE message_id = ?",
            params![now, &message_id_bytes[..]],
        )?;

        Ok(())
    }
}

// ============================================
// MailboxStorage implementation
// ============================================

#[async_trait]
impl MailboxStorage for UnifiedStorage {
    async fn mailbox_enqueue(
        &self,
        routing_key: RoutingKey,
        envelope: OuterEnvelope,
    ) -> Result<(), NodeStorageError> {
        let now = Self::now_secs();
        let ttl_secs = envelope
            .ttl_hours
            .map(|h| h as u64 * 3600)
            .unwrap_or(Self::DEFAULT_TTL_SECS);
        let expires_at = now + ttl_secs;

        let envelope_data = Self::serialize_envelope(&envelope)
            .map_err(|e| NodeStorageError::Serialization(e.to_string()))?;
        let message_id_bytes = envelope.message_id.as_bytes();

        let conn = self
            .conn
            .lock()
            .map_err(|_| NodeStorageError::LockPoisoned)?;

        // Use transaction for atomicity
        conn.execute("BEGIN IMMEDIATE", [])
            .map_err(|e| NodeStorageError::Database(e.to_string()))?;

        let result = (|| -> Result<(), NodeStorageError> {
            // Clean up expired messages for this routing key
            conn.execute(
                "DELETE FROM mailbox_messages WHERE routing_key = ? AND expires_at <= ?",
                params![&routing_key[..], now as i64],
            )
            .map_err(|e| NodeStorageError::Database(e.to_string()))?;

            // Check capacity
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM mailbox_messages WHERE routing_key = ?",
                    params![&routing_key[..]],
                    |row| row.get(0),
                )
                .map_err(|e| NodeStorageError::Database(e.to_string()))?;

            if count as usize >= Self::MAX_MESSAGES_PER_MAILBOX {
                warn!(routing_key = ?&routing_key[..4], count = count, "mailbox full");
                return Err(NodeStorageError::MailboxFull);
            }

            // Insert message
            conn.execute(
                "INSERT OR IGNORE INTO mailbox_messages
                 (routing_key, message_id, envelope_data, expires_at, created_at)
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    &routing_key[..],
                    &message_id_bytes[..],
                    &envelope_data,
                    expires_at as i64,
                    now as i64
                ],
            )
            .map_err(|e| NodeStorageError::Database(e.to_string()))?;

            Ok(())
        })();

        match result {
            Ok(()) => {
                conn.execute("COMMIT", [])
                    .map_err(|e| NodeStorageError::Database(e.to_string()))?;
                trace!(
                    routing_key = ?&routing_key[..4],
                    message_id = ?envelope.message_id,
                    "message enqueued to mailbox"
                );
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    async fn mailbox_fetch(
        &self,
        routing_key: &RoutingKey,
    ) -> Result<Vec<OuterEnvelope>, NodeStorageError> {
        let now = Self::now_secs();

        let conn = self
            .conn
            .lock()
            .map_err(|_| NodeStorageError::LockPoisoned)?;

        let mut stmt = conn
            .prepare(
                "SELECT envelope_data FROM mailbox_messages
                 WHERE routing_key = ? AND expires_at > ?
                 ORDER BY created_at ASC",
            )
            .map_err(|e| NodeStorageError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![&routing_key[..], now as i64], |row| {
                let data: Vec<u8> = row.get(0)?;
                Ok(data)
            })
            .map_err(|e| NodeStorageError::Database(e.to_string()))?;

        let mut envelopes = Vec::new();
        for row in rows {
            let data = row.map_err(|e| NodeStorageError::Database(e.to_string()))?;
            match Self::deserialize_envelope(&data) {
                Ok(envelope) => envelopes.push(envelope),
                Err(e) => warn!(error = %e, "failed to deserialize envelope, skipping"),
            }
        }

        debug!(
            routing_key = ?&routing_key[..4],
            count = envelopes.len(),
            "fetched messages from mailbox"
        );

        Ok(envelopes)
    }

    async fn mailbox_has_message(
        &self,
        routing_key: &RoutingKey,
        message_id: &MessageID,
    ) -> Result<bool, NodeStorageError> {
        let now = Self::now_secs();
        let message_id_bytes = message_id.as_bytes();

        let conn = self
            .conn
            .lock()
            .map_err(|_| NodeStorageError::LockPoisoned)?;

        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM mailbox_messages
                 WHERE routing_key = ? AND message_id = ? AND expires_at > ?",
                params![&routing_key[..], &message_id_bytes[..], now as i64],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| NodeStorageError::Database(e.to_string()))?
            .unwrap_or(false);

        Ok(exists)
    }

    async fn mailbox_delete_message(
        &self,
        _routing_key: &RoutingKey,
        message_id: &MessageID,
    ) -> Result<bool, NodeStorageError> {
        let message_id_bytes = message_id.as_bytes();

        let conn = self
            .conn
            .lock()
            .map_err(|_| NodeStorageError::LockPoisoned)?;

        let deleted = conn
            .execute(
                "DELETE FROM mailbox_messages WHERE message_id = ?",
                params![&message_id_bytes[..]],
            )
            .map_err(|e| NodeStorageError::Database(e.to_string()))?;

        Ok(deleted > 0)
    }

    async fn mailbox_cleanup_expired(&self) -> Result<usize, NodeStorageError> {
        let now = Self::now_secs();

        let conn = self
            .conn
            .lock()
            .map_err(|_| NodeStorageError::LockPoisoned)?;

        let deleted = conn
            .execute(
                "DELETE FROM mailbox_messages WHERE expires_at <= ?",
                params![now as i64],
            )
            .map_err(|e| NodeStorageError::Database(e.to_string()))?;

        if deleted > 0 {
            debug!(deleted = deleted, "expired mailbox messages cleaned up");
        }

        Ok(deleted)
    }
}

// ============================================
// OutboxStore implementation
// ============================================

impl UnifiedStorage {
    /// Load attempts for an outbox entry.
    fn load_attempts_inner(
        conn: &Connection,
        outbox_id: i64,
    ) -> Result<Vec<TransportAttempt>, UnifiedStorageError> {
        let mut stmt = conn.prepare(
            "SELECT transport_id, attempted_at_ms, result_type, error_type, error_message, error_transient
             FROM outbox_attempts
             WHERE outbox_id = ?
             ORDER BY attempted_at_ms ASC",
        )?;

        let rows = stmt.query_map(params![outbox_id], |row| {
            let transport_id: String = row.get(0)?;
            let attempted_at_ms: u64 = row.get(1)?;
            let result_type: String = row.get(2)?;
            let error_type: Option<String> = row.get(3)?;
            let error_message: Option<String> = row.get(4)?;
            let error_transient: Option<i32> = row.get(5)?;
            Ok((transport_id, attempted_at_ms, result_type, error_type, error_message, error_transient))
        })?;

        let mut attempts = Vec::new();
        for row in rows {
            let (transport_id, attempted_at_ms, result_type, error_type, error_message, error_transient) = row?;

            let result = if result_type == "sent" {
                AttemptResult::Sent
            } else {
                let error = match error_type.as_deref() {
                    Some("network") => AttemptError::Network {
                        message: error_message.unwrap_or_default(),
                        is_transient: error_transient.map(|v| v != 0).unwrap_or(true),
                    },
                    Some("rejected") => AttemptError::Rejected {
                        message: error_message.unwrap_or_default(),
                        is_transient: error_transient.map(|v| v != 0).unwrap_or(false),
                    },
                    Some("unavailable") => AttemptError::Unavailable {
                        message: error_message.unwrap_or_default(),
                    },
                    Some("encoding") => AttemptError::Encoding {
                        message: error_message.unwrap_or_default(),
                    },
                    Some("timeout") => AttemptError::TimedOut {
                        timeout_ms: error_message.and_then(|s| s.parse().ok()).unwrap_or(60000),
                    },
                    _ => AttemptError::Network {
                        message: error_message.unwrap_or_else(|| "unknown error".to_string()),
                        is_transient: true,
                    },
                };
                AttemptResult::Failed(error)
            };

            attempts.push(TransportAttempt {
                transport_id,
                attempted_at_ms,
                result,
            });
        }

        Ok(attempts)
    }

    fn load_confirmation(
        confirmation_type: Option<String>,
        confirmation_data: Option<Vec<u8>>,
    ) -> Option<DeliveryConfirmation> {
        match confirmation_type.as_deref() {
            Some("dag") => {
                let data = confirmation_data?;
                if data.len() >= 8 {
                    let mut content_id = [0u8; 8];
                    content_id.copy_from_slice(&data[..8]);
                    Some(DeliveryConfirmation::Dag {
                        observed_in_message_id: content_id,
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn load_pending_message_inner(
        conn: &Connection,
        id: i64,
        recipient_id: Vec<u8>,
        content_id: Vec<u8>,
        message_id: Vec<u8>,
        envelope_bytes: Vec<u8>,
        inner_bytes: Vec<u8>,
        created_at_ms: u64,
        expires_at_ms: Option<u64>,
        expired_at_ms: Option<u64>,
        next_retry_at_ms: Option<u64>,
        confirmation_type: Option<String>,
        confirmation_data: Option<Vec<u8>>,
    ) -> Result<PendingMessage, UnifiedStorageError> {
        if recipient_id.len() != 32 {
            return Err(UnifiedStorageError::Serialization("Invalid recipient_id length".to_string()));
        }
        let recipient_bytes: [u8; 32] = recipient_id.try_into().unwrap();
        let recipient = PublicID::try_from_bytes(&recipient_bytes)?;

        if content_id.len() != 8 {
            return Err(UnifiedStorageError::Serialization("Invalid content_id length".to_string()));
        }
        let content_id_arr: ContentId = content_id.try_into().unwrap();

        if message_id.len() != 16 {
            return Err(UnifiedStorageError::Serialization("Invalid message_id length".to_string()));
        }
        let message_id_arr: [u8; 16] = message_id.try_into().unwrap();
        let message_id = MessageID::from_bytes(message_id_arr);

        let attempts = Self::load_attempts_inner(conn, id)?;
        let confirmation = Self::load_confirmation(confirmation_type, confirmation_data);

        Ok(PendingMessage {
            id,
            recipient,
            content_id: content_id_arr,
            message_id,
            envelope_bytes,
            inner_bytes,
            created_at_ms,
            expires_at_ms,
            expired_at_ms,
            attempts,
            next_retry_at_ms,
            confirmation,
        })
    }
}

impl OutboxStore for UnifiedStorage {
    type Error = UnifiedStorageError;

    fn outbox_enqueue(
        &self,
        recipient: &PublicID,
        content_id: ContentId,
        message_id: MessageID,
        envelope_bytes: &[u8],
        inner_bytes: &[u8],
        expires_at_ms: Option<u64>,
    ) -> Result<OutboxEntryId, Self::Error> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        let now_ms = Self::now_ms();
        let recipient_bytes = recipient.to_bytes();
        let message_id_bytes = message_id.as_bytes();

        conn.execute(
            "INSERT INTO outbox (recipient_id, content_id, message_id, envelope_bytes, inner_bytes, created_at_ms, expires_at_ms, next_retry_at_ms)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                &recipient_bytes[..],
                &content_id[..],
                &message_id_bytes[..],
                envelope_bytes,
                inner_bytes,
                now_ms as i64,
                expires_at_ms.map(|v| v as i64),
                now_ms as i64,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    fn outbox_get_pending(&self) -> Result<Vec<PendingMessage>, Self::Error> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;

        let mut stmt = conn.prepare(
            "SELECT id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                    created_at_ms, expires_at_ms, next_retry_at_ms, confirmation_type, confirmation_data
             FROM outbox
             WHERE confirmed_at_ms IS NULL AND expired_at_ms IS NULL
             ORDER BY created_at_ms ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, u64>(6)?,
                row.get::<_, Option<u64>>(7)?,
                row.get::<_, Option<u64>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<Vec<u8>>>(10)?,
            ))
        })?;

        let mut messages = Vec::new();
        for row in rows {
            let (id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                 created_at_ms, expires_at_ms, next_retry_at_ms, confirmation_type, confirmation_data) = row?;

            messages.push(Self::load_pending_message_inner(
                &conn, id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                created_at_ms, expires_at_ms, None, next_retry_at_ms, confirmation_type, confirmation_data,
            )?);
        }

        Ok(messages)
    }

    fn outbox_get_for_recipient(&self, recipient: &PublicID) -> Result<Vec<PendingMessage>, Self::Error> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        let recipient_bytes = recipient.to_bytes();

        let mut stmt = conn.prepare(
            "SELECT id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                    created_at_ms, expires_at_ms, next_retry_at_ms, confirmation_type, confirmation_data
             FROM outbox
             WHERE recipient_id = ? AND confirmed_at_ms IS NULL AND expired_at_ms IS NULL
             ORDER BY created_at_ms ASC",
        )?;

        let rows = stmt.query_map(params![&recipient_bytes[..]], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, u64>(6)?,
                row.get::<_, Option<u64>>(7)?,
                row.get::<_, Option<u64>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<Vec<u8>>>(10)?,
            ))
        })?;

        let mut messages = Vec::new();
        for row in rows {
            let (id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                 created_at_ms, expires_at_ms, next_retry_at_ms, confirmation_type, confirmation_data) = row?;

            messages.push(Self::load_pending_message_inner(
                &conn, id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                created_at_ms, expires_at_ms, None, next_retry_at_ms, confirmation_type, confirmation_data,
            )?);
        }

        Ok(messages)
    }

    fn outbox_get_due_for_retry(&self, now_ms: u64) -> Result<Vec<PendingMessage>, Self::Error> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;

        let mut stmt = conn.prepare(
            "SELECT id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                    created_at_ms, expires_at_ms, next_retry_at_ms, confirmation_type, confirmation_data
             FROM outbox
             WHERE confirmed_at_ms IS NULL
               AND expired_at_ms IS NULL
               AND (expires_at_ms IS NULL OR expires_at_ms > ?)
               AND (next_retry_at_ms IS NULL OR next_retry_at_ms <= ?)
             ORDER BY next_retry_at_ms ASC",
        )?;

        let rows = stmt.query_map(params![now_ms as i64, now_ms as i64], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, u64>(6)?,
                row.get::<_, Option<u64>>(7)?,
                row.get::<_, Option<u64>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<Vec<u8>>>(10)?,
            ))
        })?;

        let mut messages = Vec::new();
        for row in rows {
            let (id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                 created_at_ms, expires_at_ms, next_retry_at_ms, confirmation_type, confirmation_data) = row?;

            messages.push(Self::load_pending_message_inner(
                &conn, id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                created_at_ms, expires_at_ms, None, next_retry_at_ms, confirmation_type, confirmation_data,
            )?);
        }

        Ok(messages)
    }

    fn outbox_get_by_id(&self, entry_id: OutboxEntryId) -> Result<Option<PendingMessage>, Self::Error> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;

        let result = conn
            .query_row(
                "SELECT id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                        created_at_ms, expires_at_ms, expired_at_ms, next_retry_at_ms, confirmation_type, confirmation_data
                 FROM outbox WHERE id = ?",
                params![entry_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, u64>(6)?,
                        row.get::<_, Option<u64>>(7)?,
                        row.get::<_, Option<u64>>(8)?,
                        row.get::<_, Option<u64>>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, Option<Vec<u8>>>(11)?,
                    ))
                },
            )
            .optional()?;

        match result {
            Some((id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                  created_at_ms, expires_at_ms, expired_at_ms, next_retry_at_ms, confirmation_type, confirmation_data)) => {
                Ok(Some(Self::load_pending_message_inner(
                    &conn, id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                    created_at_ms, expires_at_ms, expired_at_ms, next_retry_at_ms, confirmation_type, confirmation_data,
                )?))
            }
            None => Ok(None),
        }
    }

    fn outbox_get_by_content_id(&self, content_id: ContentId) -> Result<Option<PendingMessage>, Self::Error> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;

        let result = conn
            .query_row(
                "SELECT id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                        created_at_ms, expires_at_ms, next_retry_at_ms, confirmation_type, confirmation_data
                 FROM outbox
                 WHERE content_id = ? AND confirmed_at_ms IS NULL AND expired_at_ms IS NULL",
                params![&content_id[..]],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, u64>(6)?,
                        row.get::<_, Option<u64>>(7)?,
                        row.get::<_, Option<u64>>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Option<Vec<u8>>>(10)?,
                    ))
                },
            )
            .optional()?;

        match result {
            Some((id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                  created_at_ms, expires_at_ms, next_retry_at_ms, confirmation_type, confirmation_data)) => {
                Ok(Some(Self::load_pending_message_inner(
                    &conn, id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                    created_at_ms, expires_at_ms, None, next_retry_at_ms, confirmation_type, confirmation_data,
                )?))
            }
            None => Ok(None),
        }
    }

    fn outbox_record_attempt(
        &self,
        entry_id: OutboxEntryId,
        attempt: &TransportAttempt,
        next_retry_at_ms: Option<u64>,
    ) -> Result<(), Self::Error> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;

        let (result_type, error_type, error_message, error_transient) = match &attempt.result {
            AttemptResult::Sent => ("sent", None, None, None),
            AttemptResult::Failed(err) => {
                let (err_type, err_msg) = match err {
                    AttemptError::Network { message, .. } => ("network", message.clone()),
                    AttemptError::Rejected { message, .. } => ("rejected", message.clone()),
                    AttemptError::Unavailable { message } => ("unavailable", message.clone()),
                    AttemptError::Encoding { message } => ("encoding", message.clone()),
                    AttemptError::TimedOut { timeout_ms } => ("timeout", timeout_ms.to_string()),
                };
                ("failed", Some(err_type), Some(err_msg), Some(if err.is_transient() { 1 } else { 0 }))
            }
        };

        conn.execute("BEGIN IMMEDIATE", [])?;

        let result = (|| {
            conn.execute(
                "INSERT INTO outbox_attempts (outbox_id, transport_id, attempted_at_ms, result_type, error_type, error_message, error_transient)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![entry_id, &attempt.transport_id, attempt.attempted_at_ms as i64, result_type, error_type, error_message, error_transient],
            )?;

            conn.execute(
                "UPDATE outbox SET next_retry_at_ms = ? WHERE id = ?",
                params![next_retry_at_ms.map(|v| v as i64), entry_id],
            )?;

            Ok::<(), UnifiedStorageError>(())
        })();

        match result {
            Ok(()) => {
                conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    fn outbox_mark_confirmed(&self, entry_id: OutboxEntryId, confirmation: &DeliveryConfirmation) -> Result<(), Self::Error> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        let now_ms = Self::now_ms();

        let (confirmation_type, confirmation_data) = match confirmation {
            DeliveryConfirmation::Dag { observed_in_message_id } => ("dag", observed_in_message_id.to_vec()),
        };

        conn.execute(
            "UPDATE outbox SET confirmed_at_ms = ?, confirmation_type = ?, confirmation_data = ?, next_retry_at_ms = NULL WHERE id = ?",
            params![now_ms as i64, confirmation_type, confirmation_data, entry_id],
        )?;

        Ok(())
    }

    fn outbox_mark_expired(&self, entry_id: OutboxEntryId) -> Result<(), Self::Error> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        let now_ms = Self::now_ms();

        conn.execute(
            "UPDATE outbox SET expired_at_ms = ?, next_retry_at_ms = NULL WHERE id = ?",
            params![now_ms as i64, entry_id],
        )?;

        Ok(())
    }

    fn outbox_schedule_retry(&self, entry_ids: &[OutboxEntryId], now_ms: u64) -> Result<(), Self::Error> {
        if entry_ids.is_empty() {
            return Ok(());
        }

        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        conn.execute("BEGIN IMMEDIATE", [])?;

        let result = (|| {
            for id in entry_ids {
                conn.execute(
                    "UPDATE outbox SET next_retry_at_ms = ? WHERE id = ? AND confirmed_at_ms IS NULL AND expired_at_ms IS NULL",
                    params![now_ms as i64, id],
                )?;
            }
            Ok::<(), UnifiedStorageError>(())
        })();

        match result {
            Ok(()) => {
                conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    fn outbox_cleanup(&self, confirmed_before_ms: u64) -> Result<u64, Self::Error> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        let count = conn.execute(
            "DELETE FROM outbox WHERE (confirmed_at_ms IS NOT NULL AND confirmed_at_ms <= ?) OR (expired_at_ms IS NOT NULL AND expired_at_ms <= ?)",
            params![confirmed_before_ms as i64, confirmed_before_ms as i64],
        )?;
        Ok(count as u64)
    }

    fn outbox_expire_due(&self, now_ms: u64) -> Result<u64, Self::Error> {
        let conn = self.conn.lock().map_err(|_| UnifiedStorageError::LockPoisoned)?;
        let count = conn.execute(
            "UPDATE outbox SET expired_at_ms = ?, next_retry_at_ms = NULL
             WHERE confirmed_at_ms IS NULL AND expired_at_ms IS NULL AND expires_at_ms IS NOT NULL AND expires_at_ms < ?",
            params![now_ms as i64, now_ms as i64],
        )?;
        Ok(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_identity::Identity;
    use reme_message::CURRENT_VERSION;

    fn create_test_envelope(routing_key: RoutingKey, ttl_hours: Option<u16>) -> OuterEnvelope {
        OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: 482253,
            ttl_hours,
            message_id: MessageID::new(),
            ephemeral_key: [0u8; 32],
            inner_ciphertext: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn test_contact_operations() {
        let storage = UnifiedStorage::in_memory().unwrap();
        let contact_id = Identity::generate();

        let id = storage.add_contact(contact_id.public_id(), Some("Alice")).unwrap();
        assert!(id > 0);

        let retrieved_id = storage.get_contact_id(contact_id.public_id()).unwrap();
        assert_eq!(id, retrieved_id);

        let retrieved_public_id = storage.get_contact_public_id(id).unwrap();
        assert_eq!(contact_id.public_id(), &retrieved_public_id);
    }

    #[tokio::test]
    async fn test_mailbox_enqueue_and_fetch() {
        let storage = UnifiedStorage::in_memory().unwrap();
        let routing_key = RoutingKey::from_bytes([1u8; 16]);

        let envelope = create_test_envelope(routing_key, Some(1));
        let message_id = envelope.message_id;

        storage.mailbox_enqueue(routing_key, envelope).await.unwrap();

        assert!(storage.mailbox_has_message(&routing_key, &message_id).await.unwrap());

        let fetched = storage.mailbox_fetch(&routing_key).await.unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].message_id, message_id);
    }

    #[tokio::test]
    async fn test_mailbox_delete() {
        let storage = UnifiedStorage::in_memory().unwrap();
        let routing_key = RoutingKey::from_bytes([2u8; 16]);

        let envelope = create_test_envelope(routing_key, Some(1));
        let message_id = envelope.message_id;

        storage.mailbox_enqueue(routing_key, envelope).await.unwrap();
        assert!(storage.mailbox_has_message(&routing_key, &message_id).await.unwrap());

        let deleted = storage.mailbox_delete_message(&routing_key, &message_id).await.unwrap();
        assert!(deleted);

        assert!(!storage.mailbox_has_message(&routing_key, &message_id).await.unwrap());
    }
}
