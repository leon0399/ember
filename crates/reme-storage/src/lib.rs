use reme_identity::{InvalidPublicKey, PublicID};
use reme_message::{Content, ContentId, MessageID};
use reme_outbox::{
    AttemptError, AttemptResult, DeliveryConfirmation, OutboxEntryId, OutboxStore, PendingMessage,
    TransportAttempt,
};
use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;
use tracing::{debug, trace};

#[derive(Debug, Error)]
pub enum StorageError {
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
}

/// Simple SQLite storage for desktop v0.1
pub struct Storage {
    conn: Connection,
}

impl Storage {
    /// Open or create a storage database at the given path
    pub fn open(path: &str) -> Result<Self, StorageError> {
        debug!(path = %path, "opening storage database");
        let conn = Connection::open(path)?;
        let storage = Self { conn };
        storage.init_schema()?;
        debug!("storage database initialized");
        Ok(storage)
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> Result<Self, StorageError> {
        trace!("creating in-memory storage database");
        let conn = Connection::open_in_memory()?;
        let storage = Self { conn };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Initialize database schema
    ///
    /// MIK-only storage: no sessions table, no prekeys table.
    /// Each message is encrypted with a fresh ephemeral key directly to the recipient's MIK.
    fn init_schema(&self) -> Result<(), StorageError> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id BLOB NOT NULL UNIQUE,
                name TEXT,
                created_at INTEGER NOT NULL
            );

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
                recipient_id BLOB NOT NULL,          -- PublicID (32 bytes)
                content_id BLOB NOT NULL,            -- ContentId (8 bytes)
                message_id BLOB NOT NULL,            -- MessageID (16 bytes)
                envelope_bytes BLOB NOT NULL,        -- Serialized OuterEnvelope
                inner_bytes BLOB NOT NULL,           -- Serialized InnerEnvelope
                created_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER,               -- NULL = no expiry
                next_retry_at_ms INTEGER,            -- NULL = immediate, used for scheduling
                confirmed_at_ms INTEGER,             -- NULL = not confirmed
                expired_at_ms INTEGER,               -- NULL = not expired
                confirmation_type TEXT,              -- 'dag', future: 'zk_receipt', 'p2p_ack'
                confirmation_data BLOB               -- Type-specific confirmation data
            );

            CREATE INDEX IF NOT EXISTS idx_outbox_content_id ON outbox(content_id);
            CREATE INDEX IF NOT EXISTS idx_outbox_recipient ON outbox(recipient_id);
            CREATE INDEX IF NOT EXISTS idx_outbox_retry
                ON outbox(next_retry_at_ms)
                WHERE confirmed_at_ms IS NULL AND expired_at_ms IS NULL;

            -- Delivery attempts (separate table for history)
            CREATE TABLE IF NOT EXISTS outbox_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                outbox_id INTEGER NOT NULL REFERENCES outbox(id) ON DELETE CASCADE,
                transport_id TEXT NOT NULL,          -- e.g., "http:node1.example.com"
                attempted_at_ms INTEGER NOT NULL,
                result_type TEXT NOT NULL,           -- 'sent', 'failed'
                error_type TEXT,                     -- 'network', 'rejected', etc.
                error_message TEXT,
                error_transient INTEGER              -- 1 = transient, 0 = permanent
            );

            CREATE INDEX IF NOT EXISTS idx_attempts_outbox ON outbox_attempts(outbox_id);
            "#,
        )?;
        Ok(())
    }

    // ============================================
    // Contact operations
    // ============================================

    /// Add a contact
    pub fn add_contact(&self, public_id: &PublicID, name: Option<&str>) -> Result<i64, StorageError> {
        debug!(name = ?name, "adding contact");
        let public_id_bytes = public_id.to_bytes();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        self.conn.execute(
            "INSERT INTO contacts (public_id, name, created_at) VALUES (?, ?, ?)",
            params![&public_id_bytes[..], name, now],
        )?;

        let id = self.conn.last_insert_rowid();
        trace!(contact_id = id, "contact added");
        Ok(id)
    }

    /// Get contact ID by public ID
    pub fn get_contact_id(&self, public_id: &PublicID) -> Result<i64, StorageError> {
        let public_id_bytes = public_id.to_bytes();
        self.conn
            .query_row(
                "SELECT id FROM contacts WHERE public_id = ?",
                params![&public_id_bytes[..]],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StorageError::NotFound)
    }

    /// Get contact public ID by contact ID
    pub fn get_contact_public_id(&self, contact_id: i64) -> Result<PublicID, StorageError> {
        let bytes: Vec<u8> = self
            .conn
            .query_row(
                "SELECT public_id FROM contacts WHERE id = ?",
                params![contact_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StorageError::NotFound)?;

        if bytes.len() != 32 {
            return Err(StorageError::Serialization(
                "Invalid public_id length".to_string(),
            ));
        }

        let public_id_bytes: [u8; 32] = bytes.try_into().unwrap();
        Ok(PublicID::try_from_bytes(&public_id_bytes)?)
    }

    /// Get contact name by contact ID
    pub fn get_contact_name(&self, contact_id: i64) -> Result<Option<String>, StorageError> {
        self.conn
            .query_row(
                "SELECT name FROM contacts WHERE id = ?",
                params![contact_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StorageError::NotFound)
    }

    /// List all contacts
    pub fn list_contacts(&self) -> Result<Vec<(i64, PublicID, Option<String>)>, StorageError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, public_id, name FROM contacts ORDER BY name, id")?;

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
                continue; // Skip invalid entries
            }
            let public_id_arr: [u8; 32] = public_id_bytes.try_into().unwrap();
            // Skip contacts with invalid (low-order) public keys
            if let Ok(public_id) = PublicID::try_from_bytes(&public_id_arr) {
                contacts.push((id, public_id, name));
            }
        }

        Ok(contacts)
    }

    // ============================================
    // Message operations
    // ============================================

    /// Store a sent message
    pub fn store_sent_message(
        &self,
        contact_id: i64,
        message_id: MessageID,
        content: &Content,
    ) -> Result<(), StorageError> {
        trace!(contact_id = contact_id, ?message_id, "storing sent message");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let (content_type, body) = match content {
            Content::Text(text) => ("text", Some(text.body.as_str())),
            Content::Receipt(_) => ("receipt", None),
            _ => ("unknown", None),
        };

        let message_id_bytes = message_id.as_bytes();

        self.conn.execute(
            "INSERT INTO messages (message_id, contact_id, direction, content_type, body, created_at)
             VALUES (?, ?, 'sent', ?, ?, ?)",
            params![&message_id_bytes[..], contact_id, content_type, body, now],
        )?;

        Ok(())
    }

    /// Store a received message
    pub fn store_received_message(
        &self,
        contact_id: i64,
        message_id: MessageID,
        content: &Content,
    ) -> Result<(), StorageError> {
        trace!(contact_id = contact_id, ?message_id, "storing received message");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let (content_type, body) = match content {
            Content::Text(text) => ("text", Some(text.body.as_str())),
            Content::Receipt(_) => ("receipt", None),
            _ => ("unknown", None),
        };

        let message_id_bytes = message_id.as_bytes();

        self.conn.execute(
            "INSERT INTO messages (message_id, contact_id, direction, content_type, body, created_at)
             VALUES (?, ?, 'received', ?, ?, ?)",
            params![&message_id_bytes[..], contact_id, content_type, body, now],
        )?;

        Ok(())
    }

    /// Mark a message as delivered
    pub fn mark_delivered(&self, message_id: MessageID) -> Result<(), StorageError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let message_id_bytes = message_id.as_bytes();

        self.conn.execute(
            "UPDATE messages SET delivered_at = ? WHERE message_id = ?",
            params![now, &message_id_bytes[..]],
        )?;

        Ok(())
    }

    /// Mark a message as read
    pub fn mark_read(&self, message_id: MessageID) -> Result<(), StorageError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let message_id_bytes = message_id.as_bytes();

        self.conn.execute(
            "UPDATE messages SET read_at = ? WHERE message_id = ?",
            params![now, &message_id_bytes[..]],
        )?;

        Ok(())
    }

    // ============================================
    // Outbox helper methods
    // ============================================

    /// Load attempts for an outbox entry
    fn load_attempts(&self, outbox_id: i64) -> Result<Vec<TransportAttempt>, StorageError> {
        let mut stmt = self.conn.prepare(
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

            Ok((
                transport_id,
                attempted_at_ms,
                result_type,
                error_type,
                error_message,
                error_transient,
            ))
        })?;

        let mut attempts = Vec::new();
        for row in rows {
            let (transport_id, attempted_at_ms, result_type, error_type, error_message, error_transient) =
                row?;

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
                        timeout_ms: error_message
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(60000),
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

    /// Load confirmation from a row
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
            // Future: handle other confirmation types
            _ => None,
        }
    }

    /// Load a PendingMessage from row data
    fn load_pending_message(
        &self,
        id: i64,
        recipient_id: Vec<u8>,
        content_id: Vec<u8>,
        message_id: Vec<u8>,
        envelope_bytes: Vec<u8>,
        inner_bytes: Vec<u8>,
        created_at_ms: u64,
        expires_at_ms: Option<u64>,
        next_retry_at_ms: Option<u64>,
        confirmation_type: Option<String>,
        confirmation_data: Option<Vec<u8>>,
    ) -> Result<PendingMessage, StorageError> {
        // Parse recipient
        if recipient_id.len() != 32 {
            return Err(StorageError::Serialization(
                "Invalid recipient_id length".to_string(),
            ));
        }
        let recipient_bytes: [u8; 32] = recipient_id.try_into().unwrap();
        let recipient = PublicID::try_from_bytes(&recipient_bytes)?;

        // Parse content_id
        if content_id.len() != 8 {
            return Err(StorageError::Serialization(
                "Invalid content_id length".to_string(),
            ));
        }
        let content_id_arr: ContentId = content_id.try_into().unwrap();

        // Parse message_id
        if message_id.len() != 16 {
            return Err(StorageError::Serialization(
                "Invalid message_id length".to_string(),
            ));
        }
        let message_id_arr: [u8; 16] = message_id.try_into().unwrap();
        let message_id = MessageID::from_bytes(message_id_arr);

        // Load attempts
        let attempts = self.load_attempts(id)?;

        // Load confirmation
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
            attempts,
            next_retry_at_ms,
            confirmation,
        })
    }
}

// ============================================
// OutboxStore implementation
// ============================================

impl OutboxStore for Storage {
    type Error = StorageError;

    fn outbox_enqueue(
        &self,
        recipient: &PublicID,
        content_id: ContentId,
        message_id: MessageID,
        envelope_bytes: &[u8],
        inner_bytes: &[u8],
        expires_at_ms: Option<u64>,
    ) -> Result<OutboxEntryId, Self::Error> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let recipient_bytes = recipient.to_bytes();
        let message_id_bytes = message_id.as_bytes();

        self.conn.execute(
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
                now_ms as i64, // Ready for immediate retry
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    fn outbox_get_pending(&self) -> Result<Vec<PendingMessage>, Self::Error> {
        let mut stmt = self.conn.prepare(
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
            let (
                id,
                recipient_id,
                content_id,
                message_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            ) = row?;

            messages.push(self.load_pending_message(
                id,
                recipient_id,
                content_id,
                message_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )?);
        }

        Ok(messages)
    }

    fn outbox_get_for_recipient(&self, recipient: &PublicID) -> Result<Vec<PendingMessage>, Self::Error> {
        let recipient_bytes = recipient.to_bytes();

        let mut stmt = self.conn.prepare(
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
            let (
                id,
                recipient_id,
                content_id,
                message_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            ) = row?;

            messages.push(self.load_pending_message(
                id,
                recipient_id,
                content_id,
                message_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )?);
        }

        Ok(messages)
    }

    fn outbox_get_due_for_retry(&self, now_ms: u64) -> Result<Vec<PendingMessage>, Self::Error> {
        let mut stmt = self.conn.prepare(
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
            let (
                id,
                recipient_id,
                content_id,
                message_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            ) = row?;

            messages.push(self.load_pending_message(
                id,
                recipient_id,
                content_id,
                message_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )?);
        }

        Ok(messages)
    }

    fn outbox_get_by_id(&self, entry_id: OutboxEntryId) -> Result<Option<PendingMessage>, Self::Error> {
        let result: Option<(
            i64,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            u64,
            Option<u64>,
            Option<u64>,
            Option<u64>,
            Option<String>,
            Option<Vec<u8>>,
        )> = self
            .conn
            .query_row(
                "SELECT id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                        created_at_ms, expires_at_ms, expired_at_ms, next_retry_at_ms, confirmation_type, confirmation_data
                 FROM outbox
                 WHERE id = ?",
                params![entry_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                    ))
                },
            )
            .optional()?;

        match result {
            Some((
                id,
                recipient_id,
                content_id,
                message_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                expired_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )) => Ok(Some(self.load_pending_message(
                id,
                recipient_id,
                content_id,
                message_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                expired_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )?)),
            None => Ok(None),
        }
    }

    fn outbox_get_by_content_id(&self, content_id: ContentId) -> Result<Option<PendingMessage>, Self::Error> {
        let result: Option<(
            i64,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            u64,
            Option<u64>,
            Option<u64>,
            Option<String>,
            Option<Vec<u8>>,
        )> = self
            .conn
            .query_row(
                "SELECT id, recipient_id, content_id, message_id, envelope_bytes, inner_bytes,
                        created_at_ms, expires_at_ms, next_retry_at_ms, confirmation_type, confirmation_data
                 FROM outbox
                 WHERE content_id = ? AND confirmed_at_ms IS NULL AND expired_at_ms IS NULL",
                params![&content_id[..]],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                    ))
                },
            )
            .optional()?;

        match result {
            Some((
                id,
                recipient_id,
                content_id,
                message_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )) => Ok(Some(self.load_pending_message(
                id,
                recipient_id,
                content_id,
                message_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )?)),
            None => Ok(None),
        }
    }

    fn outbox_record_attempt(
        &self,
        entry_id: OutboxEntryId,
        attempt: &TransportAttempt,
        next_retry_at_ms: Option<u64>,
    ) -> Result<(), Self::Error> {
        // Determine error fields
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
                (
                    "failed",
                    Some(err_type),
                    Some(err_msg),
                    Some(if err.is_transient() { 1 } else { 0 }),
                )
            }
        };

        // Use transaction to ensure atomicity of attempt + retry scheduling
        self.conn.execute("BEGIN IMMEDIATE", [])?;

        let result = (|| {
            // Insert attempt record
            self.conn.execute(
                "INSERT INTO outbox_attempts (outbox_id, transport_id, attempted_at_ms, result_type, error_type, error_message, error_transient)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    entry_id,
                    &attempt.transport_id,
                    attempt.attempted_at_ms as i64,
                    result_type,
                    error_type,
                    error_message,
                    error_transient,
                ],
            )?;

            // Update next_retry_at
            self.conn.execute(
                "UPDATE outbox SET next_retry_at_ms = ? WHERE id = ?",
                params![next_retry_at_ms.map(|v| v as i64), entry_id],
            )?;

            Ok::<(), StorageError>(())
        })();

        match result {
            Ok(()) => {
                self.conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    fn outbox_mark_confirmed(
        &self,
        entry_id: OutboxEntryId,
        confirmation: &DeliveryConfirmation,
    ) -> Result<(), Self::Error> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let (confirmation_type, confirmation_data) = match confirmation {
            DeliveryConfirmation::Dag { observed_in_message_id } => {
                ("dag", observed_in_message_id.to_vec())
            }
        };

        self.conn.execute(
            "UPDATE outbox SET confirmed_at_ms = ?, confirmation_type = ?, confirmation_data = ?, next_retry_at_ms = NULL
             WHERE id = ?",
            params![now_ms as i64, confirmation_type, confirmation_data, entry_id],
        )?;

        Ok(())
    }

    fn outbox_mark_expired(&self, entry_id: OutboxEntryId) -> Result<(), Self::Error> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        self.conn.execute(
            "UPDATE outbox SET expired_at_ms = ?, next_retry_at_ms = NULL WHERE id = ?",
            params![now_ms as i64, entry_id],
        )?;

        Ok(())
    }

    fn outbox_schedule_retry(&self, entry_ids: &[OutboxEntryId], now_ms: u64) -> Result<(), Self::Error> {
        if entry_ids.is_empty() {
            return Ok(());
        }

        // Use transaction for atomic batch update
        self.conn.execute("BEGIN IMMEDIATE", [])?;

        let result = (|| {
            for id in entry_ids {
                self.conn.execute(
                    "UPDATE outbox SET next_retry_at_ms = ? WHERE id = ? AND confirmed_at_ms IS NULL AND expired_at_ms IS NULL",
                    params![now_ms as i64, id],
                )?;
            }
            Ok::<(), StorageError>(())
        })();

        match result {
            Ok(()) => {
                self.conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    fn outbox_cleanup(&self, confirmed_before_ms: u64) -> Result<u64, Self::Error> {
        let count = self.conn.execute(
            "DELETE FROM outbox WHERE (confirmed_at_ms IS NOT NULL AND confirmed_at_ms <= ?) OR (expired_at_ms IS NOT NULL AND expired_at_ms <= ?)",
            params![confirmed_before_ms as i64, confirmed_before_ms as i64],
        )?;

        Ok(count as u64)
    }

    fn outbox_expire_due(&self, now_ms: u64) -> Result<u64, Self::Error> {
        let count = self.conn.execute(
            "UPDATE outbox SET expired_at_ms = ?, next_retry_at_ms = NULL
             WHERE confirmed_at_ms IS NULL
               AND expired_at_ms IS NULL
               AND expires_at_ms IS NOT NULL
               AND expires_at_ms < ?",
            params![now_ms as i64, now_ms as i64],
        )?;

        Ok(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_identity::Identity;

    #[test]
    fn test_contact_operations() {
        let storage = Storage::in_memory().unwrap();
        let contact_id = Identity::generate();

        let id = storage.add_contact(contact_id.public_id(), Some("Alice")).unwrap();
        assert!(id > 0);

        let retrieved_id = storage.get_contact_id(contact_id.public_id()).unwrap();
        assert_eq!(id, retrieved_id);

        let retrieved_public_id = storage.get_contact_public_id(id).unwrap();
        assert_eq!(contact_id.public_id(), &retrieved_public_id);
    }

    #[test]
    fn test_message_storage() {
        let storage = Storage::in_memory().unwrap();
        let contact = Identity::generate();
        let contact_id = storage.add_contact(contact.public_id(), Some("Bob")).unwrap();

        let msg_id = MessageID::new();
        let content = Content::Text(reme_message::TextContent {
            body: "Hello!".to_string(),
        });

        storage.store_sent_message(contact_id, msg_id, &content).unwrap();
        storage.mark_delivered(msg_id).unwrap();
        storage.mark_read(msg_id).unwrap();
    }
}
