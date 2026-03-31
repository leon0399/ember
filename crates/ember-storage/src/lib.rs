#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub use ember_contact::{AddContactOutcome, Contact, TrustLevel};
use ember_identity::{InvalidPublicKey, PublicID};
use ember_message::{Content, ContentId, MessageID, ReceiptContent, ReceiptKind};
use ember_node_core::{
    now_ms, now_secs_i64, timestamp_opt_to_i64, timestamp_to_i64, NodeError,
    PersistentMailboxStore, PersistentStoreConfig,
};
use ember_outbox::{
    AttemptError, AttemptResult, DeliveryConfidence, DeliveryConfirmation, EnqueueParams,
    OutboxEntryId, OutboxStore, PendingMessage, TargetId, TieredDeliveryPhase, TransportAttempt,
};
use rusqlite::{params, Connection, ErrorCode, OptionalExtension};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use thiserror::Error;
use tracing::{debug, trace};

// Re-export mailbox types for embedded node functionality
pub use ember_node_core::{MailboxStore, PersistentStoreStats};

const CLIENT_SCHEMA_VERSION: i64 = 2;

/// Direction of a stored message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageDirection {
    Sent,
    Received,
}

/// A message retrieved from storage
#[derive(Debug, Clone)]
pub struct StoredMessage {
    /// Database row ID (used as cursor for pagination)
    pub id: i64,
    /// Wire message ID
    pub message_id: MessageID,
    /// Contact database ID
    pub contact_id: i64,
    /// Whether this message was sent or received
    pub direction: MessageDirection,
    /// Content type (e.g. "text", "receipt")
    pub content_type: String,
    /// Message body (None for some content types)
    pub body: Option<String>,
    /// Creation timestamp (unix seconds)
    pub created_at: i64,
    /// Delivery timestamp (unix seconds, None if not delivered)
    pub delivered_at: Option<i64>,
    /// Read timestamp (unix seconds, None if not read)
    pub read_at: Option<i64>,
}

/// Preview data for the most recent message in a conversation.
/// Used by the TUI conversation list to show message snippets and timestamps.
#[derive(Debug, Clone)]
pub struct LastMessagePreview {
    pub body: String,
    pub created_at: i64,
}

#[derive(Debug, Error)]
#[non_exhaustive]
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

    #[error("Node error: {0}")]
    Node(#[from] NodeError),

    #[error("Lock poisoned")]
    LockPoisoned,

    #[error("Unsupported client schema: {0}")]
    UnsupportedSchema(String),
}

/// Simple `SQLite` storage for desktop v0.1
///
/// Supports unified storage for both client data (contacts, messages, outbox)
/// and embedded node mailbox data.
///
/// Thread-safe via internal `Mutex`. Can be wrapped in `Arc` for shared access.
pub struct Storage {
    conn: Mutex<Connection>,
    /// Path to the database file (None for in-memory)
    path: Option<PathBuf>,
}

struct RawContactRow {
    id: i64,
    public_id_bytes: Vec<u8>,
    routing_key_bytes: Vec<u8>,
    name: Option<String>,
    trust_level_raw: i64,
    verified_at: Option<i64>,
    created_at: i64,
}

impl Storage {
    /// Open or create a storage database at the given path
    pub fn open(path: &str) -> Result<Self, StorageError> {
        debug!(path = %path, "opening storage database");
        let conn = Connection::open(path)?;
        let storage = Self {
            conn: Mutex::new(conn),
            path: Some(PathBuf::from(path)),
        };
        storage.init_schema()?;
        debug!("storage database initialized");
        Ok(storage)
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> Result<Self, StorageError> {
        trace!("creating in-memory storage database");
        let conn = Connection::open_in_memory()?;
        let storage = Self {
            conn: Mutex::new(conn),
            path: None,
        };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Get the database path (None for in-memory databases)
    pub const fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }

    /// Initialize database schema
    ///
    /// MIK-only storage: no sessions table, no prekeys table.
    /// Each message is encrypted with a fresh ephemeral key directly to the recipient's MIK.
    fn init_schema(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        Self::validate_contacts_schema(&conn)?;
        Self::create_contact_and_message_tables(&conn)?;
        Self::create_client_schema_version_table(&conn)?;
        Self::create_outbox_tables(&conn)?;
        Self::create_ack_and_dag_tables(&conn)?;
        Ok(())
    }

    /// Create contacts and messages tables with indexes.
    fn create_contact_and_message_tables(conn: &Connection) -> Result<(), StorageError> {
        conn.execute_batch(
            r"
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id BLOB NOT NULL UNIQUE,
                routing_key BLOB NOT NULL,
                name TEXT,
                trust_level INTEGER NOT NULL,
                verified_at INTEGER,
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_contacts_routing_key ON contacts(routing_key);

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
            CREATE INDEX IF NOT EXISTS idx_messages_contact_id_desc ON messages(contact_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
            ",
        )?;
        Ok(())
    }

    fn create_client_schema_version_table(conn: &Connection) -> Result<(), StorageError> {
        conn.execute_batch(
            r"
            CREATE TABLE IF NOT EXISTS client_schema_version (
                version INTEGER PRIMARY KEY
            );
            ",
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO client_schema_version (version) VALUES (?)",
            params![CLIENT_SCHEMA_VERSION],
        )?;
        Ok(())
    }

    fn validate_contacts_schema(conn: &Connection) -> Result<(), StorageError> {
        if !Self::table_exists(conn, "contacts")? {
            return Ok(());
        }

        let mut stmt = conn.prepare("PRAGMA table_info(contacts)")?;
        let rows = stmt.query_map([], |row| {
            let name: String = row.get(1)?;
            let data_type: String = row.get(2)?;
            Ok((name, data_type))
        })?;

        let mut columns = Vec::new();
        for row in rows {
            columns.push(row?);
        }

        let expected = vec![
            ("id".to_string(), "INTEGER".to_string()),
            ("public_id".to_string(), "BLOB".to_string()),
            ("routing_key".to_string(), "BLOB".to_string()),
            ("name".to_string(), "TEXT".to_string()),
            ("trust_level".to_string(), "INTEGER".to_string()),
            ("verified_at".to_string(), "INTEGER".to_string()),
            ("created_at".to_string(), "INTEGER".to_string()),
        ];

        if columns == expected {
            return Self::validate_client_schema_version(conn);
        }

        Err(StorageError::UnsupportedSchema(format!(
            "contacts table columns {columns:?} do not match schema v2"
        )))
    }

    fn table_exists(conn: &Connection, table_name: &str) -> Result<bool, StorageError> {
        let exists = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)",
            params![table_name],
            |row| row.get::<_, i64>(0),
        )? == 1;
        Ok(exists)
    }

    fn validate_client_schema_version(conn: &Connection) -> Result<(), StorageError> {
        if !Self::table_exists(conn, "client_schema_version")? {
            return Err(StorageError::UnsupportedSchema(
                "missing client_schema_version table".to_string(),
            ));
        }

        let mut stmt =
            conn.prepare("SELECT version FROM client_schema_version ORDER BY version ASC")?;
        let versions = stmt
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;

        if versions == [CLIENT_SCHEMA_VERSION] {
            return Ok(());
        }

        Err(StorageError::UnsupportedSchema(format!(
            "unsupported client schema versions: {versions:?}"
        )))
    }

    /// Create outbox, successes, and attempts tables with indexes.
    fn create_outbox_tables(conn: &Connection) -> Result<(), StorageError> {
        conn.execute_batch(
            r"
            CREATE TABLE IF NOT EXISTS outbox (
                message_id BLOB PRIMARY KEY NOT NULL,
                recipient_id BLOB NOT NULL,
                content_id BLOB NOT NULL,
                envelope_bytes BLOB NOT NULL,
                inner_bytes BLOB NOT NULL,
                created_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER,
                next_retry_at_ms INTEGER,
                confirmed_at_ms INTEGER,
                expired_at_ms INTEGER,
                confirmation_type TEXT,
                confirmation_data BLOB,
                delivery_phase TEXT DEFAULT 'urgent',
                quorum_reached_at_ms INTEGER,
                last_maintenance_ms INTEGER,
                quorum_count INTEGER,
                quorum_required INTEGER,
                direct_target_id TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_outbox_content_id ON outbox(content_id);
            CREATE INDEX IF NOT EXISTS idx_outbox_recipient ON outbox(recipient_id);
            CREATE INDEX IF NOT EXISTS idx_outbox_retry
                ON outbox(next_retry_at_ms)
                WHERE confirmed_at_ms IS NULL AND expired_at_ms IS NULL;
            CREATE INDEX IF NOT EXISTS idx_outbox_urgent_retry
                ON outbox(next_retry_at_ms)
                WHERE delivery_phase = 'urgent' AND confirmed_at_ms IS NULL AND expired_at_ms IS NULL;
            CREATE INDEX IF NOT EXISTS idx_outbox_maintenance
                ON outbox(last_maintenance_ms)
                WHERE delivery_phase = 'distributed' AND confirmed_at_ms IS NULL AND expired_at_ms IS NULL;

            CREATE TABLE IF NOT EXISTS outbox_successes (
                message_id BLOB NOT NULL REFERENCES outbox(message_id) ON DELETE CASCADE,
                target_id TEXT NOT NULL,
                succeeded_at_ms INTEGER NOT NULL,
                PRIMARY KEY (message_id, target_id)
            );

            CREATE INDEX IF NOT EXISTS idx_successes_message ON outbox_successes(message_id);

            CREATE TABLE IF NOT EXISTS outbox_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id BLOB NOT NULL REFERENCES outbox(message_id) ON DELETE CASCADE,
                transport_id TEXT NOT NULL,
                attempted_at_ms INTEGER NOT NULL,
                result_type TEXT NOT NULL,
                error_type TEXT,
                error_message TEXT,
                error_transient INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_attempts_message ON outbox_attempts(message_id);
            ",
        )?;
        Ok(())
    }

    /// Create pending acks and DAG state tables with indexes.
    fn create_ack_and_dag_tables(conn: &Connection) -> Result<(), StorageError> {
        conn.execute_batch(
            r"
            CREATE TABLE IF NOT EXISTS pending_acks (
                message_id BLOB PRIMARY KEY NOT NULL,
                ack_secret BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_pending_acks_created ON pending_acks(created_at);

            CREATE TABLE IF NOT EXISTS dag_state (
                contact_pubkey BLOB PRIMARY KEY NOT NULL,
                epoch INTEGER NOT NULL DEFAULT 0,
                sender_head BLOB,
                peer_heads BLOB
            );
            ",
        )?;
        Ok(())
    }

    // ============================================
    // Mailbox schema (for embedded node)
    // ============================================

    /// Initialize mailbox schema for embedded node functionality.
    ///
    /// This creates the tables needed for the embedded mailbox node to store
    /// incoming messages from LAN peers. Call this after opening the storage
    /// if you want to use embedded node features.
    ///
    /// The mailbox tables are separate from client tables (contacts, messages, outbox)
    /// but share the same database file for unified storage.
    pub fn init_mailbox_schema(&self) -> Result<(), StorageError> {
        debug!("initializing mailbox schema for embedded node");
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.execute_batch(
            r"
            -- Mailbox messages table for embedded node
            -- Stores incoming messages from LAN peers until fetched
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

            -- Mailbox schema version for future migrations
            CREATE TABLE IF NOT EXISTS mailbox_schema_version (
                version INTEGER PRIMARY KEY
            );

            INSERT OR IGNORE INTO mailbox_schema_version (version) VALUES (1);
            ",
        )?;
        debug!("mailbox schema initialized");
        Ok(())
    }

    /// Create a mailbox store for embedded node functionality.
    ///
    /// This creates a new `PersistentMailboxStore` that connects to the same
    /// database file with its own connection. Both connections can safely
    /// coexist using `SQLite`'s WAL mode.
    ///
    /// # Note
    /// For in-memory databases (testing mode), this creates a separate in-memory
    /// mailbox store that does not share data with the main Storage connection.
    ///
    /// # Errors
    /// Returns an error if opening the database connection fails.
    ///
    /// # Example
    /// ```ignore
    /// let storage = Storage::open("client.db")?;
    /// storage.init_mailbox_schema()?;
    /// let mailbox_store = storage.mailbox_store(PersistentStoreConfig::default())?;
    /// ```
    pub fn mailbox_store(
        &self,
        config: PersistentStoreConfig,
    ) -> Result<PersistentMailboxStore, StorageError> {
        Self::open_mailbox_store(self.path.as_ref(), config)
    }

    /// Open a mailbox store backed by the same database (or in-memory for tests).
    fn open_mailbox_store(
        path: Option<&PathBuf>,
        config: PersistentStoreConfig,
    ) -> Result<PersistentMailboxStore, StorageError> {
        if let Some(path) = path {
            debug!(path = %path.display(), "creating mailbox store for embedded node");
            return Ok(PersistentMailboxStore::open(path, config)?);
        }

        // For in-memory databases, create an in-memory mailbox store
        // Note: This won't share data with the main connection
        debug!("creating in-memory mailbox store (testing mode)");
        Ok(PersistentMailboxStore::in_memory(config)?)
    }

    // ============================================
    // DAG state persistence
    // ============================================

    /// Persist DAG state for a single contact.
    ///
    /// Stores the essential fields needed to resume message ordering
    /// after a client restart: epoch, sender head, and peer heads.
    pub fn save_dag_state(
        &self,
        contact_key: &[u8; 32],
        epoch: u16,
        sender_head: Option<ContentId>,
        peer_heads: &[ContentId],
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let sender_head_blob: Option<Vec<u8>> = sender_head.map(|h| h.to_vec());
        let peer_heads_blob: Vec<u8> = peer_heads.concat();

        conn.execute(
            "INSERT OR REPLACE INTO dag_state (contact_pubkey, epoch, sender_head, peer_heads)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                contact_key.as_slice(),
                i64::from(epoch),
                sender_head_blob,
                if peer_heads_blob.is_empty() {
                    None
                } else {
                    Some(peer_heads_blob)
                },
            ],
        )?;
        Ok(())
    }

    /// Load all persisted DAG states.
    ///
    /// Returns a map from contact public key bytes to (epoch, `sender_head`, `peer_heads`).
    /// The caller is responsible for reconstructing `ConversationDag` from these fields.
    #[allow(clippy::type_complexity)]
    pub fn load_all_dag_states(
        &self,
    ) -> Result<HashMap<[u8; 32], (u16, Option<ContentId>, Vec<ContentId>)>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let mut stmt =
            conn.prepare("SELECT contact_pubkey, epoch, sender_head, peer_heads FROM dag_state")?;

        let rows = stmt.query_map([], |row| {
            let pubkey_blob: Vec<u8> = row.get(0)?;
            let epoch: i64 = row.get(1)?;
            let sender_head_blob: Option<Vec<u8>> = row.get(2)?;
            let peer_heads_blob: Option<Vec<u8>> = row.get(3)?;
            Ok((pubkey_blob, epoch, sender_head_blob, peer_heads_blob))
        })?;

        let mut result = HashMap::new();
        for row in rows {
            let (pubkey_blob, epoch_i64, sender_head_blob, peer_heads_blob) = row?;

            // Parse contact key (32 bytes)
            let contact_key: [u8; 32] = pubkey_blob.as_slice().try_into().map_err(|_| {
                StorageError::Serialization(format!(
                    "invalid contact key length: {}",
                    pubkey_blob.len()
                ))
            })?;

            // Parse epoch (u16)
            let epoch = u16::try_from(epoch_i64).map_err(|_| {
                StorageError::Serialization(format!("invalid epoch value: {epoch_i64}"))
            })?;

            // Parse sender head (Option<ContentId> = Option<[u8; 8]>)
            let sender_head: Option<ContentId> = sender_head_blob
                .map(|blob| {
                    blob.as_slice().try_into().map_err(|_| {
                        StorageError::Serialization(format!(
                            "invalid sender_head length: {}",
                            blob.len()
                        ))
                    })
                })
                .transpose()?;

            // Parse peer heads (Vec<ContentId>)
            let peer_heads: Vec<ContentId> = match peer_heads_blob {
                Some(blob) if !blob.is_empty() => {
                    if blob.len() % 8 != 0 {
                        return Err(StorageError::Serialization(format!(
                            "invalid peer_heads length: {} (not multiple of 8)",
                            blob.len()
                        )));
                    }
                    blob.chunks_exact(8)
                        .map(|chunk| {
                            let mut arr: ContentId = [0u8; 8];
                            arr.copy_from_slice(chunk);
                            arr
                        })
                        .collect()
                }
                _ => Vec::new(),
            };

            result.insert(contact_key, (epoch, sender_head, peer_heads));
        }

        Ok(result)
    }

    // ============================================
    // Contact operations
    // ============================================

    /// Add a manual contact as `Known`.
    pub fn add_contact(
        &self,
        public_id: &PublicID,
        name: Option<&str>,
    ) -> Result<i64, StorageError> {
        self.create_contact(public_id, name, TrustLevel::Known)
            .map(|contact| contact.id)
    }

    pub fn create_contact(
        &self,
        public_id: &PublicID,
        name: Option<&str>,
        trust_level: TrustLevel,
    ) -> Result<Contact, StorageError> {
        debug!(name = ?name, ?trust_level, "creating contact");
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        Self::insert_contact(&conn, public_id, name, trust_level, None)
    }

    pub fn get_contact(&self, public_id: &PublicID) -> Result<Contact, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        Self::query_contact_by_public_id(&conn, public_id)
    }

    pub fn find_contact_by_routing_key(
        &self,
        routing_key: &ember_identity::RoutingKey,
    ) -> Result<Contact, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        Self::query_contact_by_routing_key(&conn, routing_key)
    }

    pub fn promote_manual_contact(
        &self,
        public_id: &PublicID,
        name: Option<&str>,
    ) -> Result<AddContactOutcome, StorageError> {
        let mut conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let tx = conn.transaction()?;

        match Self::query_contact_by_public_id(&tx, public_id) {
            Ok(existing) => {
                if existing.trust_level >= TrustLevel::Known {
                    tx.commit()?;
                    return Ok(AddContactOutcome::AlreadyPresent(existing));
                }

                let updated_name = name
                    .map(ToOwned::to_owned)
                    .or_else(|| existing.name.clone());
                let public_id_bytes = public_id.to_bytes();
                tx.execute(
                    "UPDATE contacts
                     SET name = ?, trust_level = ?
                     WHERE public_id = ?",
                    params![
                        updated_name.as_deref(),
                        TrustLevel::Known as u8,
                        &public_id_bytes[..]
                    ],
                )?;
                let promoted = Self::query_contact_by_public_id(&tx, public_id)?;
                tx.commit()?;
                Ok(AddContactOutcome::Promoted(promoted))
            }
            Err(StorageError::NotFound) => {
                let created = Self::insert_contact(&tx, public_id, name, TrustLevel::Known, None)?;
                tx.commit()?;
                Ok(AddContactOutcome::Created(created))
            }
            Err(error) => Err(error),
        }
    }

    pub fn mark_contact_verified(
        &self,
        public_id: &PublicID,
        verified_at: i64,
    ) -> Result<Contact, StorageError> {
        let mut conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let tx = conn.transaction()?;
        let existing = Self::query_contact_by_public_id(&tx, public_id)?;
        let updated_trust = existing.trust_level.max(TrustLevel::Verified);
        let public_id_bytes = public_id.to_bytes();

        tx.execute(
            "UPDATE contacts
             SET trust_level = ?, verified_at = ?
             WHERE public_id = ?",
            params![updated_trust as u8, verified_at, &public_id_bytes[..]],
        )?;
        let contact = Self::query_contact_by_public_id(&tx, public_id)?;
        tx.commit()?;
        Ok(contact)
    }

    /// Get contact ID by public ID
    pub fn get_contact_id(&self, public_id: &PublicID) -> Result<i64, StorageError> {
        let public_id_bytes = public_id.to_bytes();
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.query_row(
            "SELECT id FROM contacts WHERE public_id = ?",
            params![&public_id_bytes[..]],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(StorageError::NotFound)
    }

    /// Get contact public ID by contact ID
    pub fn get_contact_public_id(&self, contact_id: i64) -> Result<PublicID, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let bytes: Vec<u8> = conn
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

        let public_id_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| StorageError::Serialization("Invalid public_id length".to_string()))?;
        Ok(PublicID::try_from_bytes(&public_id_bytes)?)
    }

    /// Get contact name by contact ID
    pub fn get_contact_name(&self, contact_id: i64) -> Result<Option<String>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.query_row(
            "SELECT name FROM contacts WHERE id = ?",
            params![contact_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(StorageError::NotFound)
    }

    /// List all contacts
    pub fn list_contacts(&self) -> Result<Vec<Contact>, StorageError> {
        self.list_contacts_query(
            "SELECT id, public_id, routing_key, name, trust_level, verified_at, created_at
             FROM contacts
             ORDER BY name, id",
            None,
        )
    }

    pub fn list_contacts_with_min_trust(
        &self,
        min_trust: TrustLevel,
    ) -> Result<Vec<Contact>, StorageError> {
        self.list_contacts_query(
            "SELECT id, public_id, routing_key, name, trust_level, verified_at, created_at
             FROM contacts
             WHERE trust_level >= ?
             ORDER BY name, id",
            Some(min_trust),
        )
    }

    fn list_contacts_query(
        &self,
        sql: &str,
        min_trust: Option<TrustLevel>,
    ) -> Result<Vec<Contact>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let mut stmt = conn.prepare(sql)?;
        let mut rows = if let Some(level) = min_trust {
            stmt.query(params![level as u8])?
        } else {
            stmt.query([])?
        };

        let mut contacts = Vec::new();
        while let Some(row) = rows.next()? {
            contacts.push(Self::decode_contact_row(Self::read_contact_row(row)?)?);
        }

        Ok(contacts)
    }

    fn decode_contact_row(raw: RawContactRow) -> Result<Contact, StorageError> {
        let RawContactRow {
            id,
            public_id_bytes,
            routing_key_bytes,
            name,
            trust_level_raw,
            verified_at,
            created_at,
        } = raw;
        let public_id_len = public_id_bytes.len();
        let public_id_array: [u8; 32] = public_id_bytes.try_into().map_err(|_| {
            StorageError::Serialization(format!("invalid public_id length: {public_id_len}"))
        })?;
        let public_id = PublicID::try_from_bytes(&public_id_array)?;

        let routing_key_len = routing_key_bytes.len();
        let routing_key_array: [u8; 16] = routing_key_bytes.try_into().map_err(|_| {
            StorageError::Serialization(format!("invalid routing_key length: {routing_key_len}"))
        })?;
        let routing_key = ember_identity::RoutingKey::from_bytes(routing_key_array);

        let trust_level = match trust_level_raw {
            0 => TrustLevel::Stranger,
            1 => TrustLevel::Known,
            2 => TrustLevel::Verified,
            3 => TrustLevel::Trusted,
            value => {
                return Err(StorageError::Serialization(format!(
                    "invalid trust_level value: {value}"
                )))
            }
        };

        Ok(Contact {
            id,
            public_id,
            routing_key,
            name,
            trust_level,
            verified_at,
            created_at,
        })
    }

    fn insert_contact(
        conn: &Connection,
        public_id: &PublicID,
        name: Option<&str>,
        trust_level: TrustLevel,
        verified_at: Option<i64>,
    ) -> Result<Contact, StorageError> {
        let public_id_bytes = public_id.to_bytes();
        let routing_key = public_id.routing_key();
        let now = now_secs_i64();

        conn.execute(
            "INSERT INTO contacts (public_id, routing_key, name, trust_level, verified_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![
                &public_id_bytes[..],
                &routing_key.as_bytes()[..],
                name,
                trust_level as u8,
                verified_at,
                now
            ],
        )?;

        let id = conn.last_insert_rowid();
        trace!(contact_id = id, "contact created");
        Ok(Contact {
            id,
            public_id: *public_id,
            routing_key,
            name: name.map(ToOwned::to_owned),
            trust_level,
            verified_at,
            created_at: now,
        })
    }

    fn query_contact_by_public_id(
        conn: &Connection,
        public_id: &PublicID,
    ) -> Result<Contact, StorageError> {
        let public_id_bytes = public_id.to_bytes();
        let row = conn
            .query_row(
                "SELECT id, public_id, routing_key, name, trust_level, verified_at, created_at
                 FROM contacts
                 WHERE public_id = ?",
                params![&public_id_bytes[..]],
                Self::read_contact_row,
            )
            .optional()?
            .ok_or(StorageError::NotFound)?;

        Self::decode_contact_row(row)
    }

    fn query_contact_by_routing_key(
        conn: &Connection,
        routing_key: &ember_identity::RoutingKey,
    ) -> Result<Contact, StorageError> {
        let row = conn
            .query_row(
                "SELECT id, public_id, routing_key, name, trust_level, verified_at, created_at
                 FROM contacts
                 WHERE routing_key = ?",
                params![&routing_key.as_bytes()[..]],
                Self::read_contact_row,
            )
            .optional()?
            .ok_or(StorageError::NotFound)?;

        Self::decode_contact_row(row)
    }

    fn read_contact_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawContactRow> {
        Ok(RawContactRow {
            id: row.get::<_, i64>(0)?,
            public_id_bytes: row.get::<_, Vec<u8>>(1)?,
            routing_key_bytes: row.get::<_, Vec<u8>>(2)?,
            name: row.get::<_, Option<String>>(3)?,
            trust_level_raw: row.get::<_, i64>(4)?,
            verified_at: row.get::<_, Option<i64>>(5)?,
            created_at: row.get::<_, i64>(6)?,
        })
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
        let now = now_secs_i64();

        let (content_type, body) = encode_content(content);

        let message_id_bytes = message_id.as_bytes();

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.execute(
            "INSERT INTO messages (message_id, contact_id, direction, content_type, body, created_at)
             VALUES (?, ?, 'sent', ?, ?, ?)",
            params![
                &message_id_bytes[..],
                contact_id,
                content_type,
                body.as_deref(),
                now
            ],
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
        trace!(
            contact_id = contact_id,
            ?message_id,
            "storing received message"
        );
        let now = now_secs_i64();

        let (content_type, body) = encode_content(content);

        let message_id_bytes = message_id.as_bytes();

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.execute(
            "INSERT INTO messages (message_id, contact_id, direction, content_type, body, created_at)
             VALUES (?, ?, 'received', ?, ?, ?)",
            params![
                &message_id_bytes[..],
                contact_id,
                content_type,
                body.as_deref(),
                now
            ],
        )
        .map_err(|e| {
            if is_duplicate_message_id_error(&e) {
                StorageError::AlreadyExists
            } else {
                StorageError::Database(e)
            }
        })?;

        Ok(())
    }

    /// Check whether an existing message row matches an incoming received message.
    ///
    /// This is used to distinguish benign duplicate delivery from a conflicting
    /// reuse of an existing `message_id`.
    pub fn received_message_matches(
        &self,
        contact_id: i64,
        message_id: MessageID,
        content: &Content,
    ) -> Result<bool, StorageError> {
        let expected_content_type = content_type_name(content);
        let expected_body = encoded_body(content);
        let message_id_bytes = message_id.as_bytes();

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let row: Option<(i64, String, String, Option<String>)> = conn
            .query_row(
                "SELECT contact_id, direction, content_type, body
                 FROM messages
                 WHERE message_id = ?",
                params![&message_id_bytes[..]],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;

        let Some((stored_contact_id, direction, stored_content_type, stored_body)) = row else {
            return Ok(false);
        };

        if direction != "received" || stored_contact_id != contact_id {
            return Ok(false);
        }

        if stored_content_type != expected_content_type {
            return Ok(false);
        }

        if matches!(content, Content::Receipt(_)) && stored_body.is_none() {
            // Legacy receipt rows were stored without a serialized body. Treat
            // type/contact match as equivalent for backward compatibility.
            return Ok(true);
        }

        Ok(stored_body == expected_body)
    }

    /// Mark a message as delivered
    pub fn mark_delivered(&self, message_id: MessageID) -> Result<(), StorageError> {
        let now = now_secs_i64();

        let message_id_bytes = message_id.as_bytes();

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.execute(
            "UPDATE messages SET delivered_at = ? WHERE message_id = ?",
            params![now, &message_id_bytes[..]],
        )?;

        Ok(())
    }

    /// Mark a message as read
    pub fn mark_read(&self, message_id: MessageID) -> Result<(), StorageError> {
        let now = now_secs_i64();

        let message_id_bytes = message_id.as_bytes();

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.execute(
            "UPDATE messages SET read_at = ? WHERE message_id = ?",
            params![now, &message_id_bytes[..]],
        )?;

        Ok(())
    }

    /// Retrieve messages for a contact in chronological order (oldest first).
    ///
    /// Uses cursor-based pagination: when `before_id` is `Some(id)`, only
    /// messages with `id < before_id` are returned. When `None`, returns
    /// the most recent messages.
    ///
    /// Internally queries `ORDER BY id DESC` for efficient cursor pagination,
    /// then reverses to return chronological order. At most `limit` rows.
    pub fn get_messages(
        &self,
        contact_id: i64,
        limit: u32,
        before_id: Option<i64>,
    ) -> Result<Vec<StoredMessage>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let mut messages = if let Some(cursor) = before_id {
            let mut stmt = conn.prepare(
                "SELECT id, message_id, contact_id, direction, content_type, body,
                        created_at, delivered_at, read_at
                 FROM messages
                 WHERE contact_id = ? AND id < ?
                 ORDER BY id DESC
                 LIMIT ?",
            )?;
            let rows = stmt.query_map(params![contact_id, cursor, limit], map_stored_message)?;
            rows.collect::<Result<Vec<_>, _>>()?
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, message_id, contact_id, direction, content_type, body,
                        created_at, delivered_at, read_at
                 FROM messages
                 WHERE contact_id = ?
                 ORDER BY id DESC
                 LIMIT ?",
            )?;
            let rows = stmt.query_map(params![contact_id, limit], map_stored_message)?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        // Reverse so the caller gets chronological order (oldest first)
        messages.reverse();
        Ok(messages)
    }

    /// Get the most recent message preview for each of the given contact IDs.
    ///
    /// Returns a map from `contact_id` to a [`LastMessagePreview`] containing
    /// the message body and creation timestamp (unix seconds).
    /// Receipts and messages without a body are skipped.
    /// `SQLite` bound variable limit (matches `ember-node-core`).
    const SQLITE_MAX_BOUND_VARIABLES: usize = 999;

    pub fn get_last_message_per_contact(
        &self,
        contact_ids: &[i64],
    ) -> Result<HashMap<i64, LastMessagePreview>, StorageError> {
        if contact_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let mut result = HashMap::new();

        // Chunk to stay within SQLite's bound-parameter limit
        for chunk in contact_ids.chunks(Self::SQLITE_MAX_BOUND_VARIABLES) {
            let placeholders: Vec<&str> = chunk.iter().map(|_| "?").collect();
            let sql = format!(
                "SELECT m.contact_id, m.body, m.created_at
                 FROM messages m
                 INNER JOIN (
                     SELECT contact_id, MAX(id) AS max_id
                     FROM messages
                     WHERE contact_id IN ({})
                       AND content_type = 'text'
                       AND body IS NOT NULL
                     GROUP BY contact_id
                 ) latest ON m.id = latest.max_id",
                placeholders.join(", ")
            );

            let mut stmt = conn.prepare(&sql)?;
            let params_iter = rusqlite::params_from_iter(chunk.iter());
            let rows = stmt.query_map(params_iter, |row| {
                let cid: i64 = row.get(0)?;
                let body: String = row.get(1)?;
                let created_at: i64 = row.get(2)?;
                Ok((cid, LastMessagePreview { body, created_at }))
            })?;

            for row in rows {
                let (cid, preview) = row?;
                result.insert(cid, preview);
            }
        }
        Ok(result)
    }

    // ============================================
    // Pending Ack operations (Tombstone V2)
    // ============================================

    /// Store a pending ack secret for a sent message.
    ///
    /// This is used by senders to retain the `ack_secret` so they can create
    /// tombstones for their own messages (e.g., to retract before delivery).
    pub fn store_pending_ack(
        &self,
        message_id: MessageID,
        ack_secret: [u8; 16],
    ) -> Result<(), StorageError> {
        let now = now_secs_i64();

        let message_id_bytes = message_id.as_bytes();

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.execute(
            "INSERT OR REPLACE INTO pending_acks (message_id, ack_secret, created_at)
             VALUES (?, ?, ?)",
            params![&message_id_bytes[..], &ack_secret[..], now],
        )?;

        trace!(?message_id, "stored pending ack secret");
        Ok(())
    }

    /// Get the ack secret for a pending message.
    ///
    /// Returns None if no ack secret is stored for this message.
    pub fn get_pending_ack(
        &self,
        message_id: &MessageID,
    ) -> Result<Option<[u8; 16]>, StorageError> {
        let message_id_bytes = message_id.as_bytes();

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT ack_secret FROM pending_acks WHERE message_id = ?",
                params![&message_id_bytes[..]],
                |row| row.get(0),
            )
            .optional()?;

        match result {
            Some(bytes) if bytes.len() == 16 => {
                let mut ack_secret = [0u8; 16];
                ack_secret.copy_from_slice(&bytes);
                Ok(Some(ack_secret))
            }
            Some(_) => Err(StorageError::Serialization(
                "Invalid ack_secret length in database".to_string(),
            )),
            None => Ok(None),
        }
    }

    /// Remove a pending ack secret after it has been used (tombstone sent).
    pub fn remove_pending_ack(&self, message_id: &MessageID) -> Result<(), StorageError> {
        let message_id_bytes = message_id.as_bytes();

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.execute(
            "DELETE FROM pending_acks WHERE message_id = ?",
            params![&message_id_bytes[..]],
        )?;

        trace!(?message_id, "removed pending ack secret");
        Ok(())
    }

    /// Clean up old pending ack secrets that are older than `max_age_secs`.
    ///
    /// Returns the number of deleted entries.
    pub fn cleanup_old_pending_acks(&self, max_age_secs: u64) -> Result<usize, StorageError> {
        let now = now_secs_i64();

        let cutoff = now - timestamp_to_i64(max_age_secs);

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let count = conn.execute(
            "DELETE FROM pending_acks WHERE created_at < ?",
            params![cutoff],
        )?;

        if count > 0 {
            debug!(count, "cleaned up old pending ack secrets");
        }

        Ok(count)
    }

    // ============================================
    // Outbox helper methods
    // ============================================

    /// Load attempts for an outbox entry
    fn load_attempts(
        conn: &Connection,
        message_id: &MessageID,
    ) -> Result<Vec<TransportAttempt>, StorageError> {
        let message_id_bytes = message_id.as_bytes();
        let mut stmt = conn.prepare(
            "SELECT transport_id, attempted_at_ms, result_type, error_type, error_message, error_transient
             FROM outbox_attempts
             WHERE message_id = ?
             ORDER BY attempted_at_ms ASC",
        )?;

        let rows = stmt.query_map(params![&message_id_bytes[..]], |row| {
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
            let (
                transport_id,
                attempted_at_ms,
                result_type,
                error_type,
                error_message,
                error_transient,
            ) = row?;

            let result = if result_type == "sent" {
                AttemptResult::Sent
            } else {
                let error = match error_type.as_deref() {
                    Some("network") => AttemptError::Network {
                        message: error_message.unwrap_or_default(),
                        is_transient: error_transient != Some(0),
                    },
                    Some("rejected") => AttemptError::Rejected {
                        message: error_message.unwrap_or_default(),
                        is_transient: error_transient.is_some_and(|v| v != 0),
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

    /// Load confirmation from a row
    #[allow(clippy::needless_pass_by_value)] // Private helper, value semantics simpler for Option<String>
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

    /// Load successful targets for an outbox entry
    fn load_successful_targets(
        conn: &Connection,
        message_id: &MessageID,
    ) -> Result<std::collections::HashSet<TargetId>, StorageError> {
        let message_id_bytes = message_id.as_bytes();
        let mut stmt =
            conn.prepare("SELECT target_id FROM outbox_successes WHERE message_id = ?")?;

        let rows = stmt.query_map(params![&message_id_bytes[..]], |row| {
            let target_id: String = row.get(0)?;
            Ok(target_id)
        })?;

        let mut targets = std::collections::HashSet::new();
        for row in rows {
            let target_str = row?;
            // Parse target_id string back to TargetId
            // Format is "type:url" - we reconstruct using the appropriate constructor
            if let Some(url) = target_str.strip_prefix("http:") {
                targets.insert(TargetId::http(url));
            } else if let Some(url) = target_str.strip_prefix("mqtt:") {
                targets.insert(TargetId::mqtt(url));
            } else {
                return Err(StorageError::Serialization(format!(
                    "Unknown target_id prefix in '{target_str}'"
                )));
            }
        }

        Ok(targets)
    }

    /// Load tiered delivery phase for an outbox entry
    #[allow(clippy::type_complexity)] // SQL row unpacking requires tuple type
    fn load_tiered_phase(
        conn: &Connection,
        message_id: &MessageID,
    ) -> Result<TieredDeliveryPhase, StorageError> {
        let message_id_bytes = message_id.as_bytes();
        let result: Option<(
            String,         // delivery_phase
            Option<u64>,    // quorum_reached_at_ms
            Option<u64>,    // last_maintenance_ms
            Option<u32>,    // quorum_count
            Option<u32>,    // quorum_required
            Option<String>, // direct_target_id
        )> = conn
            .query_row(
                "SELECT delivery_phase, quorum_reached_at_ms, last_maintenance_ms,
                        quorum_count, quorum_required, direct_target_id
                 FROM outbox
                 WHERE message_id = ?",
                params![&message_id_bytes[..]],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?
                            .unwrap_or_else(|| "urgent".to_string()),
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;

        match result {
            Some((
                phase,
                reached_at_ms,
                last_maintenance_ms,
                quorum_count,
                quorum_required,
                direct_target_id,
            )) => {
                match phase.as_str() {
                    "distributed" => {
                        let confidence = if let Some(target_str) = direct_target_id {
                            // Direct delivery - parse target
                            let target = if let Some(url) = target_str.strip_prefix("http:") {
                                TargetId::http(url)
                            } else if let Some(url) = target_str.strip_prefix("mqtt:") {
                                TargetId::mqtt(url)
                            } else {
                                return Err(StorageError::Serialization(format!(
                                    "Unknown target_id prefix in '{target_str}'"
                                )));
                            };
                            DeliveryConfidence::DirectDelivery { target }
                        } else {
                            DeliveryConfidence::QuorumReached {
                                count: quorum_count.unwrap_or(0),
                                required: quorum_required.unwrap_or(1),
                            }
                        };
                        Ok(TieredDeliveryPhase::Distributed {
                            confidence,
                            reached_at_ms: reached_at_ms.unwrap_or(0),
                            last_maintenance_ms,
                        })
                    }
                    "confirmed" => Ok(TieredDeliveryPhase::Confirmed {
                        confirmed_at_ms: reached_at_ms.unwrap_or(0),
                    }),
                    "urgent" => Ok(TieredDeliveryPhase::Urgent),
                    unknown => {
                        tracing::warn!(
                            phase = %unknown,
                            "Unknown delivery phase in database, falling back to Urgent"
                        );
                        Ok(TieredDeliveryPhase::Urgent)
                    }
                }
            }
            None => Ok(TieredDeliveryPhase::Urgent),
        }
    }

    /// Load a `PendingMessage` from row data
    ///
    /// Note: `message_id` serves as both the primary key and the entry ID.
    #[allow(clippy::too_many_arguments)]
    fn load_pending_message(
        conn: &Connection,
        message_id: Vec<u8>,
        recipient_id: Vec<u8>,
        content_id: Vec<u8>,
        envelope_bytes: Vec<u8>,
        inner_bytes: Vec<u8>,
        created_at_ms: u64,
        expires_at_ms: Option<u64>,
        expired_at_ms: Option<u64>,
        next_retry_at_ms: Option<u64>,
        confirmation_type: Option<String>,
        confirmation_data: Option<Vec<u8>>,
    ) -> Result<PendingMessage, StorageError> {
        // Parse message_id (this is also the entry ID)
        if message_id.len() != 16 {
            return Err(StorageError::Serialization(
                "Invalid message_id length".to_string(),
            ));
        }
        let message_id_arr: [u8; 16] = message_id
            .try_into()
            .map_err(|_| StorageError::Serialization("Invalid message_id length".to_string()))?;
        let message_id = MessageID::from_bytes(message_id_arr);

        // Parse recipient
        let recipient_bytes: [u8; 32] = recipient_id
            .try_into()
            .map_err(|_| StorageError::Serialization("Invalid recipient_id length".to_string()))?;
        let recipient = PublicID::try_from_bytes(&recipient_bytes)?;

        // Parse content_id
        let content_id_arr: ContentId = content_id
            .try_into()
            .map_err(|_| StorageError::Serialization("Invalid content_id length".to_string()))?;

        // Load attempts
        let attempts = Self::load_attempts(conn, &message_id)?;

        // Load confirmation
        let confirmation = Self::load_confirmation(confirmation_type, confirmation_data);

        // Load successful targets
        let successful_targets = Self::load_successful_targets(conn, &message_id)?;

        // Load tiered phase (defaults to Urgent for existing entries)
        let tiered_phase = Self::load_tiered_phase(conn, &message_id)?;

        Ok(PendingMessage {
            id: message_id,
            recipient,
            content_id: content_id_arr,
            envelope_bytes,
            inner_bytes,
            created_at_ms,
            expires_at_ms,
            expired_at_ms,
            attempts,
            next_retry_at_ms,
            confirmation,
            successful_targets,
            tiered_phase,
        })
    }

    /// Query outbox rows with the full 11-column projection (including `expired_at_ms`).
    ///
    /// Shared implementation for `outbox_get_all` and `outbox_get_all_for_recipient`.
    fn query_outbox_full(
        &self,
        sql: &str,
        query_params: &[&dyn rusqlite::types::ToSql],
    ) -> Result<Vec<PendingMessage>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let mut stmt = conn.prepare(sql)?;

        let rows = stmt.query_map(query_params, |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,          // message_id
                row.get::<_, Vec<u8>>(1)?,          // recipient_id
                row.get::<_, Vec<u8>>(2)?,          // content_id
                row.get::<_, Vec<u8>>(3)?,          // envelope_bytes
                row.get::<_, Vec<u8>>(4)?,          // inner_bytes
                row.get::<_, u64>(5)?,              // created_at_ms
                row.get::<_, Option<u64>>(6)?,      // expires_at_ms
                row.get::<_, Option<u64>>(7)?,      // expired_at_ms
                row.get::<_, Option<u64>>(8)?,      // next_retry_at_ms
                row.get::<_, Option<String>>(9)?,   // confirmation_type
                row.get::<_, Option<Vec<u8>>>(10)?, // confirmation_data
            ))
        })?;

        let mut messages = Vec::new();
        for row in rows {
            let (
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                expired_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            ) = row?;

            messages.push(Self::load_pending_message(
                &conn,
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                expired_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )?);
        }

        Ok(messages)
    }
}

/// Map a database row to a [`StoredMessage`].
fn map_stored_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMessage> {
    let id: i64 = row.get(0)?;
    let message_id_bytes: Vec<u8> = row.get(1)?;
    let contact_id: i64 = row.get(2)?;
    let direction_str: String = row.get(3)?;
    let content_type: String = row.get(4)?;
    let body: Option<String> = row.get(5)?;
    let created_at: i64 = row.get(6)?;
    let delivered_at: Option<i64> = row.get(7)?;
    let read_at: Option<i64> = row.get(8)?;

    let message_id_arr: [u8; 16] = message_id_bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidColumnType(1, "message_id".to_string(), rusqlite::types::Type::Blob)
    })?;
    let message_id = MessageID::from_bytes(message_id_arr);

    let direction = match direction_str.as_str() {
        "sent" => MessageDirection::Sent,
        "received" => MessageDirection::Received,
        _ => {
            return Err(rusqlite::Error::InvalidColumnType(
                3,
                "direction".to_string(),
                rusqlite::types::Type::Text,
            ));
        }
    };

    Ok(StoredMessage {
        id,
        message_id,
        contact_id,
        direction,
        content_type,
        body,
        created_at,
        delivered_at,
        read_at,
    })
}

const fn content_type_name(content: &Content) -> &'static str {
    match content {
        Content::Text(_) => "text",
        Content::Receipt(_) => "receipt",
        _ => "unknown",
    }
}

fn encoded_body(content: &Content) -> Option<String> {
    match content {
        Content::Text(text) => Some(text.body.clone()),
        Content::Receipt(receipt) => Some(encode_receipt_body(receipt)),
        _ => None,
    }
}

fn encode_content(content: &Content) -> (&'static str, Option<String>) {
    (content_type_name(content), encoded_body(content))
}

fn encode_receipt_body(receipt: &ReceiptContent) -> String {
    format!(
        "{}:{}",
        match receipt.kind {
            ReceiptKind::Delivered => "delivered",
            ReceiptKind::Read => "read",
            _ => "unknown",
        },
        hex::encode(receipt.target_message_id.as_bytes())
    )
}

fn is_duplicate_message_id_error(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, Some(message))
            if inner.code == ErrorCode::ConstraintViolation
                && message.contains("messages.message_id")
    )
}

// ============================================
// OutboxStore implementation
// ============================================

impl OutboxStore for Storage {
    type Error = StorageError;

    fn outbox_enqueue(&self, params: EnqueueParams<'_>) -> Result<OutboxEntryId, Self::Error> {
        let now_ms = now_ms();

        let recipient_bytes = params.recipient.to_bytes();
        let message_id_bytes = params.message_id.as_bytes();

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.execute(
            "INSERT INTO outbox (message_id, recipient_id, content_id, envelope_bytes, inner_bytes, created_at_ms, expires_at_ms, next_retry_at_ms)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                &message_id_bytes[..],
                &recipient_bytes[..],
                &params.content_id[..],
                params.envelope_bytes,
                params.inner_bytes,
                timestamp_to_i64(now_ms),
                timestamp_opt_to_i64(params.expires_at_ms),
                timestamp_to_i64(now_ms), // Ready for immediate retry
            ],
        )?;

        // Return the message_id as the entry ID (it's the primary key now)
        Ok(params.message_id)
    }

    fn outbox_get_pending(&self) -> Result<Vec<PendingMessage>, Self::Error> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let mut stmt = conn.prepare(
            "SELECT message_id, recipient_id, content_id, envelope_bytes, inner_bytes,
                    created_at_ms, expires_at_ms, next_retry_at_ms, confirmation_type, confirmation_data
             FROM outbox
             WHERE confirmed_at_ms IS NULL AND expired_at_ms IS NULL
             ORDER BY created_at_ms ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,         // message_id
                row.get::<_, Vec<u8>>(1)?,         // recipient_id
                row.get::<_, Vec<u8>>(2)?,         // content_id
                row.get::<_, Vec<u8>>(3)?,         // envelope_bytes
                row.get::<_, Vec<u8>>(4)?,         // inner_bytes
                row.get::<_, u64>(5)?,             // created_at_ms
                row.get::<_, Option<u64>>(6)?,     // expires_at_ms
                row.get::<_, Option<u64>>(7)?,     // next_retry_at_ms
                row.get::<_, Option<String>>(8)?,  // confirmation_type
                row.get::<_, Option<Vec<u8>>>(9)?, // confirmation_data
            ))
        })?;

        let mut messages = Vec::new();
        for row in rows {
            let (
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            ) = row?;

            messages.push(Self::load_pending_message(
                &conn,
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                None, // expired_at_ms - always None since query filters expired
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )?);
        }

        Ok(messages)
    }

    fn outbox_get_for_recipient(
        &self,
        recipient: &PublicID,
    ) -> Result<Vec<PendingMessage>, Self::Error> {
        let recipient_bytes = recipient.to_bytes();

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let mut stmt = conn.prepare(
            "SELECT message_id, recipient_id, content_id, envelope_bytes, inner_bytes,
                    created_at_ms, expires_at_ms, next_retry_at_ms, confirmation_type, confirmation_data
             FROM outbox
             WHERE recipient_id = ? AND confirmed_at_ms IS NULL AND expired_at_ms IS NULL
             ORDER BY created_at_ms ASC",
        )?;

        let rows = stmt.query_map(params![&recipient_bytes[..]], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,         // message_id
                row.get::<_, Vec<u8>>(1)?,         // recipient_id
                row.get::<_, Vec<u8>>(2)?,         // content_id
                row.get::<_, Vec<u8>>(3)?,         // envelope_bytes
                row.get::<_, Vec<u8>>(4)?,         // inner_bytes
                row.get::<_, u64>(5)?,             // created_at_ms
                row.get::<_, Option<u64>>(6)?,     // expires_at_ms
                row.get::<_, Option<u64>>(7)?,     // next_retry_at_ms
                row.get::<_, Option<String>>(8)?,  // confirmation_type
                row.get::<_, Option<Vec<u8>>>(9)?, // confirmation_data
            ))
        })?;

        let mut messages = Vec::new();
        for row in rows {
            let (
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            ) = row?;

            messages.push(Self::load_pending_message(
                &conn,
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                None, // expired_at_ms - always None since query filters expired
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )?);
        }

        Ok(messages)
    }

    fn outbox_get_all(&self) -> Result<Vec<PendingMessage>, Self::Error> {
        self.query_outbox_full(
            "SELECT message_id, recipient_id, content_id, envelope_bytes, inner_bytes,
                    created_at_ms, expires_at_ms, expired_at_ms, next_retry_at_ms,
                    confirmation_type, confirmation_data
             FROM outbox
             ORDER BY created_at_ms ASC",
            &[],
        )
    }

    fn outbox_get_all_for_recipient(
        &self,
        recipient: &PublicID,
    ) -> Result<Vec<PendingMessage>, Self::Error> {
        let recipient_bytes = recipient.to_bytes();
        self.query_outbox_full(
            "SELECT message_id, recipient_id, content_id, envelope_bytes, inner_bytes,
                    created_at_ms, expires_at_ms, expired_at_ms, next_retry_at_ms,
                    confirmation_type, confirmation_data
             FROM outbox
             WHERE recipient_id = ?
             ORDER BY created_at_ms ASC",
            &[&recipient_bytes.as_ref() as &dyn rusqlite::types::ToSql],
        )
    }

    fn outbox_get_due_for_retry(&self, now_ms: u64) -> Result<Vec<PendingMessage>, Self::Error> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let mut stmt = conn.prepare(
            "SELECT message_id, recipient_id, content_id, envelope_bytes, inner_bytes,
                    created_at_ms, expires_at_ms, next_retry_at_ms, confirmation_type, confirmation_data
             FROM outbox
             WHERE confirmed_at_ms IS NULL
               AND expired_at_ms IS NULL
               AND (expires_at_ms IS NULL OR expires_at_ms > ?)
               AND (next_retry_at_ms IS NULL OR next_retry_at_ms <= ?)
             ORDER BY next_retry_at_ms ASC",
        )?;

        let rows = stmt.query_map(
            params![timestamp_to_i64(now_ms), timestamp_to_i64(now_ms)],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,         // message_id
                    row.get::<_, Vec<u8>>(1)?,         // recipient_id
                    row.get::<_, Vec<u8>>(2)?,         // content_id
                    row.get::<_, Vec<u8>>(3)?,         // envelope_bytes
                    row.get::<_, Vec<u8>>(4)?,         // inner_bytes
                    row.get::<_, u64>(5)?,             // created_at_ms
                    row.get::<_, Option<u64>>(6)?,     // expires_at_ms
                    row.get::<_, Option<u64>>(7)?,     // next_retry_at_ms
                    row.get::<_, Option<String>>(8)?,  // confirmation_type
                    row.get::<_, Option<Vec<u8>>>(9)?, // confirmation_data
                ))
            },
        )?;

        let mut messages = Vec::new();
        for row in rows {
            let (
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            ) = row?;

            messages.push(Self::load_pending_message(
                &conn,
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                None, // expired_at_ms - always None since query filters expired
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )?);
        }

        Ok(messages)
    }

    #[allow(clippy::type_complexity)] // SQL row unpacking requires tuple type
    fn outbox_get_by_id(
        &self,
        entry_id: OutboxEntryId,
    ) -> Result<Option<PendingMessage>, Self::Error> {
        let entry_id_bytes = entry_id.as_bytes();
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let result: Option<(
            Vec<u8>,  // message_id
            Vec<u8>,  // recipient_id
            Vec<u8>,  // content_id
            Vec<u8>,  // envelope_bytes
            Vec<u8>,  // inner_bytes
            u64,      // created_at_ms
            Option<u64>,  // expires_at_ms
            Option<u64>,  // expired_at_ms
            Option<u64>,  // next_retry_at_ms
            Option<String>,  // confirmation_type
            Option<Vec<u8>>,  // confirmation_data
        )> = conn
            .query_row(
                "SELECT message_id, recipient_id, content_id, envelope_bytes, inner_bytes,
                        created_at_ms, expires_at_ms, expired_at_ms, next_retry_at_ms, confirmation_type, confirmation_data
                 FROM outbox
                 WHERE message_id = ?",
                params![&entry_id_bytes[..]],
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
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                expired_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )) => Ok(Some(Self::load_pending_message(
                &conn,
                message_id,
                recipient_id,
                content_id,
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

    #[allow(clippy::type_complexity)] // SQL row unpacking requires tuple type
    fn outbox_get_by_content_id(
        &self,
        content_id: ContentId,
    ) -> Result<Option<PendingMessage>, Self::Error> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let result: Option<(
            Vec<u8>,  // message_id
            Vec<u8>,  // recipient_id
            Vec<u8>,  // content_id
            Vec<u8>,  // envelope_bytes
            Vec<u8>,  // inner_bytes
            u64,      // created_at_ms
            Option<u64>,  // expires_at_ms
            Option<u64>,  // next_retry_at_ms
            Option<String>,  // confirmation_type
            Option<Vec<u8>>,  // confirmation_data
        )> = conn
            .query_row(
                "SELECT message_id, recipient_id, content_id, envelope_bytes, inner_bytes,
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
                    ))
                },
            )
            .optional()?;

        match result {
            Some((
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )) => Ok(Some(Self::load_pending_message(
                &conn,
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                None, // expired_at_ms - always None since query filters expired
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
        let entry_id_bytes = entry_id.as_bytes();

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
                    Some(i32::from(err.is_transient())),
                )
            }
        };

        // Use transaction to ensure atomicity of attempt + retry scheduling
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.execute("BEGIN IMMEDIATE", [])?;

        let result = (|| {
            // Insert attempt record
            conn.execute(
                "INSERT INTO outbox_attempts (message_id, transport_id, attempted_at_ms, result_type, error_type, error_message, error_transient)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    &entry_id_bytes[..],
                    &attempt.transport_id,
                    timestamp_to_i64(attempt.attempted_at_ms),
                    result_type,
                    error_type,
                    error_message,
                    error_transient,
                ],
            )?;

            // Update next_retry_at
            conn.execute(
                "UPDATE outbox SET next_retry_at_ms = ? WHERE message_id = ?",
                params![timestamp_opt_to_i64(next_retry_at_ms), &entry_id_bytes[..]],
            )?;

            Ok::<(), StorageError>(())
        })();

        match result {
            Ok(()) => {
                conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                if let Err(rollback_err) = conn.execute("ROLLBACK", []) {
                    tracing::error!(
                        "Transaction rollback failed after error: {} (rollback error: {})",
                        e,
                        rollback_err
                    );
                }
                Err(e)
            }
        }
    }

    fn outbox_mark_confirmed(
        &self,
        entry_id: OutboxEntryId,
        confirmation: &DeliveryConfirmation,
    ) -> Result<(), Self::Error> {
        let entry_id_bytes = entry_id.as_bytes();
        let now_ms = now_ms();

        let (confirmation_type, confirmation_data) = match confirmation {
            DeliveryConfirmation::Dag {
                observed_in_message_id,
            } => ("dag", observed_in_message_id.to_vec()),
        };

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.execute(
            "UPDATE outbox SET confirmed_at_ms = ?, confirmation_type = ?, confirmation_data = ?, next_retry_at_ms = NULL
             WHERE message_id = ?",
            params![timestamp_to_i64(now_ms), confirmation_type, confirmation_data, &entry_id_bytes[..]],
        )?;

        Ok(())
    }

    fn outbox_mark_expired(&self, entry_id: OutboxEntryId) -> Result<(), Self::Error> {
        let entry_id_bytes = entry_id.as_bytes();
        let now_ms = now_ms();

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.execute(
            "UPDATE outbox SET expired_at_ms = ?, next_retry_at_ms = NULL WHERE message_id = ?",
            params![timestamp_to_i64(now_ms), &entry_id_bytes[..]],
        )?;

        Ok(())
    }

    fn outbox_schedule_retry(
        &self,
        entry_ids: &[OutboxEntryId],
        now_ms: u64,
    ) -> Result<(), Self::Error> {
        if entry_ids.is_empty() {
            return Ok(());
        }

        // Use transaction for atomic batch update
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.execute("BEGIN IMMEDIATE", [])?;

        let result = (|| {
            for id in entry_ids {
                let id_bytes = id.as_bytes();
                conn.execute(
                    "UPDATE outbox SET next_retry_at_ms = ? WHERE message_id = ? AND confirmed_at_ms IS NULL AND expired_at_ms IS NULL",
                    params![timestamp_to_i64(now_ms), &id_bytes[..]],
                )?;
            }
            Ok::<(), StorageError>(())
        })();

        match result {
            Ok(()) => {
                conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                if let Err(rollback_err) = conn.execute("ROLLBACK", []) {
                    tracing::error!(
                        "Transaction rollback failed after error: {} (rollback error: {})",
                        e,
                        rollback_err
                    );
                }
                Err(e)
            }
        }
    }

    fn outbox_cleanup(&self, confirmed_before_ms: u64) -> Result<u64, Self::Error> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let count = conn.execute(
            "DELETE FROM outbox WHERE (confirmed_at_ms IS NOT NULL AND confirmed_at_ms <= ?) OR (expired_at_ms IS NOT NULL AND expired_at_ms <= ?)",
            params![timestamp_to_i64(confirmed_before_ms), timestamp_to_i64(confirmed_before_ms)],
        )?;

        Ok(count as u64)
    }

    fn outbox_expire_due(&self, now_ms: u64) -> Result<u64, Self::Error> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let count = conn.execute(
            "UPDATE outbox SET expired_at_ms = ?, next_retry_at_ms = NULL
             WHERE confirmed_at_ms IS NULL
               AND expired_at_ms IS NULL
               AND expires_at_ms IS NOT NULL
               AND expires_at_ms < ?",
            params![timestamp_to_i64(now_ms), timestamp_to_i64(now_ms)],
        )?;

        Ok(count as u64)
    }

    // ========== Tiered Delivery Methods ==========

    fn outbox_update_tiered_phase(
        &self,
        entry_id: OutboxEntryId,
        phase: &TieredDeliveryPhase,
    ) -> Result<(), Self::Error> {
        let entry_id_bytes = entry_id.as_bytes();
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        match phase {
            TieredDeliveryPhase::Urgent => {
                conn.execute(
                    "UPDATE outbox SET delivery_phase = 'urgent', quorum_reached_at_ms = NULL,
                     last_maintenance_ms = NULL, quorum_count = NULL, quorum_required = NULL,
                     direct_target_id = NULL
                     WHERE message_id = ?",
                    params![&entry_id_bytes[..]],
                )?;
            }
            TieredDeliveryPhase::Distributed {
                confidence,
                reached_at_ms,
                last_maintenance_ms,
            } => {
                let (quorum_count, quorum_required, direct_target_id) = match confidence {
                    DeliveryConfidence::QuorumReached { count, required } => {
                        (Some(*count), Some(*required), None)
                    }
                    DeliveryConfidence::DirectDelivery { target } => {
                        (None, None, Some(target.as_str().to_string()))
                    }
                };
                conn.execute(
                    "UPDATE outbox SET delivery_phase = 'distributed', quorum_reached_at_ms = ?,
                     last_maintenance_ms = ?, quorum_count = ?, quorum_required = ?,
                     direct_target_id = ?
                     WHERE message_id = ?",
                    params![
                        timestamp_to_i64(*reached_at_ms),
                        timestamp_opt_to_i64(*last_maintenance_ms),
                        quorum_count,
                        quorum_required,
                        direct_target_id,
                        &entry_id_bytes[..],
                    ],
                )?;
            }
            TieredDeliveryPhase::Confirmed { confirmed_at_ms } => {
                conn.execute(
                    "UPDATE outbox SET delivery_phase = 'confirmed', quorum_reached_at_ms = ?
                     WHERE message_id = ?",
                    params![timestamp_to_i64(*confirmed_at_ms), &entry_id_bytes[..]],
                )?;
            }
        }
        Ok(())
    }

    fn outbox_add_successful_target(
        &self,
        entry_id: OutboxEntryId,
        target_id: &TargetId,
    ) -> Result<(), Self::Error> {
        let entry_id_bytes = entry_id.as_bytes();
        let now_ms = now_ms();

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.execute(
            "INSERT OR REPLACE INTO outbox_successes (message_id, target_id, succeeded_at_ms)
             VALUES (?, ?, ?)",
            params![
                &entry_id_bytes[..],
                target_id.as_str(),
                timestamp_to_i64(now_ms)
            ],
        )?;
        Ok(())
    }

    fn outbox_get_urgent_retry_due(&self, now_ms: u64) -> Result<Vec<PendingMessage>, Self::Error> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let mut stmt = conn.prepare(
            "SELECT message_id, recipient_id, content_id, envelope_bytes, inner_bytes,
                    created_at_ms, expires_at_ms, next_retry_at_ms, confirmation_type, confirmation_data
             FROM outbox
             WHERE confirmed_at_ms IS NULL
               AND expired_at_ms IS NULL
               AND (delivery_phase IS NULL OR delivery_phase = 'urgent')
               AND (next_retry_at_ms IS NULL OR next_retry_at_ms <= ?)
             ORDER BY created_at_ms ASC",
        )?;

        let rows = stmt.query_map(params![timestamp_to_i64(now_ms)], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, u64>(5)?,
                row.get::<_, Option<u64>>(6)?,
                row.get::<_, Option<u64>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<Vec<u8>>>(9)?,
            ))
        })?;

        let mut messages = Vec::new();
        for row in rows {
            let (
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            ) = row?;
            messages.push(Self::load_pending_message(
                &conn,
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                None,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )?);
        }

        Ok(messages)
    }

    fn outbox_get_maintenance_due(
        &self,
        now_ms: u64,
        maintenance_interval_ms: u64,
    ) -> Result<Vec<PendingMessage>, Self::Error> {
        let cutoff = now_ms.saturating_sub(maintenance_interval_ms);

        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let mut stmt = conn.prepare(
            "SELECT message_id, recipient_id, content_id, envelope_bytes, inner_bytes,
                    created_at_ms, expires_at_ms, next_retry_at_ms, confirmation_type, confirmation_data
             FROM outbox
             WHERE confirmed_at_ms IS NULL
               AND expired_at_ms IS NULL
               AND delivery_phase = 'distributed'
               AND (next_retry_at_ms IS NULL OR next_retry_at_ms <= ?)
               AND (last_maintenance_ms IS NULL OR last_maintenance_ms <= ?)
             ORDER BY last_maintenance_ms ASC NULLS FIRST",
        )?;

        let rows = stmt.query_map(
            params![timestamp_to_i64(now_ms), timestamp_to_i64(cutoff)],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, Option<u64>>(6)?,
                    row.get::<_, Option<u64>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                ))
            },
        )?;

        let mut messages = Vec::new();
        for row in rows {
            let (
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            ) = row?;
            messages.push(Self::load_pending_message(
                &conn,
                message_id,
                recipient_id,
                content_id,
                envelope_bytes,
                inner_bytes,
                created_at_ms,
                expires_at_ms,
                None,
                next_retry_at_ms,
                confirmation_type,
                confirmation_data,
            )?);
        }

        Ok(messages)
    }

    fn outbox_update_last_maintenance(
        &self,
        entry_id: OutboxEntryId,
        last_maintenance_ms: u64,
    ) -> Result<(), Self::Error> {
        let entry_id_bytes = entry_id.as_bytes();
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        conn.execute(
            "UPDATE outbox SET last_maintenance_ms = ? WHERE message_id = ?",
            params![timestamp_to_i64(last_maintenance_ms), &entry_id_bytes[..]],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ember_contact::{AddContactOutcome, TrustLevel};
    use ember_identity::Identity;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn test_create_contact_persists_routing_key_and_known_trust() {
        let storage = Storage::in_memory().unwrap();
        let identity = Identity::generate();

        let contact = storage
            .create_contact(identity.public_id(), Some("Alice"), TrustLevel::Known)
            .unwrap();

        assert!(contact.id > 0);
        assert_eq!(contact.public_id, *identity.public_id());
        assert_eq!(contact.routing_key, identity.public_id().routing_key());
        assert_eq!(contact.name.as_deref(), Some("Alice"));
        assert_eq!(contact.trust_level, TrustLevel::Known);
        assert_eq!(contact.verified_at, None);
        assert!(contact.created_at > 0);

        let stored = storage.get_contact(identity.public_id()).unwrap();
        assert_eq!(stored, contact);
    }

    #[test]
    fn test_promote_manual_contact_upgrades_existing_stranger() {
        let storage = Storage::in_memory().unwrap();
        let identity = Identity::generate();

        let stranger = storage
            .create_contact(identity.public_id(), None, TrustLevel::Stranger)
            .unwrap();

        let outcome = storage
            .promote_manual_contact(identity.public_id(), Some("Alice"))
            .unwrap();

        let AddContactOutcome::Promoted(contact) = outcome else {
            panic!("expected stranger contact to be promoted");
        };

        assert_eq!(contact.id, stranger.id);
        assert_eq!(contact.trust_level, TrustLevel::Known);
        assert_eq!(contact.name.as_deref(), Some("Alice"));
    }

    #[test]
    fn test_promote_manual_contact_returns_already_present_for_known_plus() {
        let storage = Storage::in_memory().unwrap();
        let identity = Identity::generate();

        let known = storage
            .create_contact(identity.public_id(), Some("Alice"), TrustLevel::Known)
            .unwrap();

        let outcome = storage
            .promote_manual_contact(identity.public_id(), Some("Renamed"))
            .unwrap();

        let AddContactOutcome::AlreadyPresent(contact) = outcome else {
            panic!("expected known contact to be returned without error");
        };

        assert_eq!(contact.id, known.id);
        assert_eq!(contact.trust_level, TrustLevel::Known);
    }

    #[test]
    fn test_mark_contact_verified_sets_timestamp_without_downgrading_trusted() {
        let storage = Storage::in_memory().unwrap();
        let identity = Identity::generate();
        let verified_at = 1_700_000_000;

        let trusted = storage
            .create_contact(identity.public_id(), Some("Alice"), TrustLevel::Trusted)
            .unwrap();

        let updated = storage
            .mark_contact_verified(identity.public_id(), verified_at)
            .unwrap();

        assert_eq!(updated.id, trusted.id);
        assert_eq!(updated.trust_level, TrustLevel::Trusted);
        assert_eq!(updated.verified_at, Some(verified_at));
    }

    #[test]
    fn test_legacy_contacts_schema_is_rejected() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("legacy-client.db");
        let conn = Connection::open(&db_path).unwrap();

        conn.execute_batch(
            r"
            CREATE TABLE contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id BLOB NOT NULL UNIQUE,
                name TEXT,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE messages (
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
            ",
        )
        .unwrap();
        drop(conn);

        let path = db_path.to_str().unwrap();
        let Err(error) = Storage::open(path) else {
            panic!("legacy contacts schema should be rejected");
        };
        assert!(matches!(error, StorageError::UnsupportedSchema(_)));
    }

    #[test]
    fn test_wrong_client_schema_version_is_rejected() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("wrong-version.db");
        let conn = Connection::open(&db_path).unwrap();

        conn.execute_batch(
            r"
            CREATE TABLE contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id BLOB NOT NULL UNIQUE,
                routing_key BLOB NOT NULL,
                name TEXT,
                trust_level INTEGER NOT NULL,
                verified_at INTEGER,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE client_schema_version (
                version INTEGER PRIMARY KEY
            );
            ",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO client_schema_version (version) VALUES (?)",
            params![1_i64],
        )
        .unwrap();
        drop(conn);

        let path = db_path.to_str().unwrap();
        let Err(error) = Storage::open(path) else {
            panic!("wrong schema version should be rejected");
        };
        assert!(matches!(error, StorageError::UnsupportedSchema(_)));
    }

    #[test]
    fn test_contact_operations() {
        let storage = Storage::in_memory().unwrap();
        let contact_id = Identity::generate();

        let id = storage
            .add_contact(contact_id.public_id(), Some("Alice"))
            .unwrap();
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
        let contact_id = storage
            .add_contact(contact.public_id(), Some("Bob"))
            .unwrap();

        let msg_id = MessageID::new();
        let content = Content::Text(ember_message::TextContent {
            body: "Hello!".to_string(),
        });

        storage
            .store_sent_message(contact_id, msg_id, &content)
            .unwrap();
        storage.mark_delivered(msg_id).unwrap();
        storage.mark_read(msg_id).unwrap();
    }

    #[test]
    fn test_received_message_duplicate_returns_already_exists() {
        let storage = Storage::in_memory().unwrap();
        let contact = Identity::generate();
        let contact_id = storage
            .add_contact(contact.public_id(), Some("Bob"))
            .unwrap();
        let msg_id = MessageID::new();
        let content = Content::Text(ember_message::TextContent {
            body: "Hello again".to_string(),
        });

        storage
            .store_received_message(contact_id, msg_id, &content)
            .unwrap();

        let duplicate = storage.store_received_message(contact_id, msg_id, &content);
        assert!(matches!(duplicate, Err(StorageError::AlreadyExists)));
        assert!(storage
            .received_message_matches(contact_id, msg_id, &content)
            .unwrap());
    }

    #[test]
    fn test_unified_mailbox_storage() {
        use ember_message::{OuterEnvelope, RoutingKey, CURRENT_VERSION};

        // Create storage and initialize mailbox schema
        let storage = Storage::in_memory().unwrap();
        storage.init_mailbox_schema().unwrap();

        // Verify path() returns None for in-memory
        assert!(storage.path().is_none());

        // Create mailbox store (in-memory mode for testing)
        let config = PersistentStoreConfig::default();
        let mailbox = storage.mailbox_store(config).unwrap();

        // Create a test envelope
        let routing_key = RoutingKey::from_bytes([42u8; 16]);
        let envelope = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: 482_253,
            ttl_hours: Some(24),
            message_id: MessageID::new(),
            ephemeral_key: [0u8; 32],
            ack_hash: [0u8; 16],
            inner_ciphertext: vec![1, 2, 3, 4],
        };
        let msg_id = envelope.message_id;

        // Enqueue message
        mailbox.enqueue(routing_key, envelope).unwrap();

        // Verify message exists
        assert!(mailbox.has_message(&routing_key, &msg_id).unwrap());

        // Fetch and verify
        let fetched = mailbox.fetch(&routing_key).unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].message_id, msg_id);
    }

    #[test]
    fn test_file_based_unified_storage() {
        use ember_message::{OuterEnvelope, RoutingKey, CURRENT_VERSION};
        use tempfile::tempdir;

        // Create a temp directory for the test database
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("unified.db");
        let db_path_str = db_path.to_str().unwrap();

        // Create storage and initialize mailbox schema
        let storage = Storage::open(db_path_str).unwrap();
        storage.init_mailbox_schema().unwrap();

        // Verify path() returns the correct path
        assert_eq!(storage.path().unwrap().as_os_str(), db_path.as_os_str());

        // Add a contact to the client storage
        let contact = Identity::generate();
        let contact_id = storage
            .add_contact(contact.public_id(), Some("Test"))
            .unwrap();
        assert!(contact_id > 0);

        // Create mailbox store using the same database
        let config = PersistentStoreConfig::default();
        let mailbox = storage.mailbox_store(config).unwrap();

        // Enqueue a message via the mailbox store
        let routing_key = RoutingKey::from_bytes([99u8; 16]);
        let envelope = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: 482_253,
            ttl_hours: Some(1),
            message_id: MessageID::new(),
            ephemeral_key: [0u8; 32],
            ack_hash: [0u8; 16],
            inner_ciphertext: vec![5, 6, 7, 8],
        };

        mailbox.enqueue(routing_key, envelope).unwrap();

        // Verify both client and mailbox data coexist
        let contacts = storage.list_contacts().unwrap();
        assert_eq!(contacts.len(), 1);

        let fetched = mailbox.fetch(&routing_key).unwrap();
        assert_eq!(fetched.len(), 1);
    }

    #[test]
    fn test_pending_acks() {
        let storage = Storage::in_memory().unwrap();
        let message_id = MessageID::new();
        let ack_secret = [42u8; 16];

        // Store a pending ack
        storage.store_pending_ack(message_id, ack_secret).unwrap();

        // Retrieve it
        let retrieved = storage.get_pending_ack(&message_id).unwrap();
        assert_eq!(retrieved, Some(ack_secret));

        // Remove it
        storage.remove_pending_ack(&message_id).unwrap();

        // Should be gone now
        let retrieved = storage.get_pending_ack(&message_id).unwrap();
        assert_eq!(retrieved, None);
    }

    #[test]
    fn test_pending_acks_cleanup() {
        let storage = Storage::in_memory().unwrap();

        // Store a pending ack
        let message_id = MessageID::new();
        let ack_secret = [99u8; 16];
        storage.store_pending_ack(message_id, ack_secret).unwrap();

        // Cleanup with very small max_age shouldn't delete (entry is new)
        // We'd need to mock time to properly test expiry, but we can test
        // the query runs without error
        let cleaned = storage.cleanup_old_pending_acks(3600).unwrap();
        assert_eq!(cleaned, 0); // Entry is fresh, shouldn't be deleted

        // Entry should still exist
        let retrieved = storage.get_pending_ack(&message_id).unwrap();
        assert_eq!(retrieved, Some(ack_secret));
    }

    #[test]
    fn test_pending_ack_overwrite() {
        let storage = Storage::in_memory().unwrap();
        let message_id = MessageID::new();
        let ack_secret1 = [1u8; 16];
        let ack_secret2 = [2u8; 16];

        // Store first ack secret
        storage.store_pending_ack(message_id, ack_secret1).unwrap();

        // Overwrite with second (should succeed due to INSERT OR REPLACE)
        storage.store_pending_ack(message_id, ack_secret2).unwrap();

        // Should get the second one
        let retrieved = storage.get_pending_ack(&message_id).unwrap();
        assert_eq!(retrieved, Some(ack_secret2));
    }

    /// Helper: store N text messages for a contact and return their `MessageID`s.
    fn store_n_messages(storage: &Storage, contact_id: i64, n: usize) -> Vec<MessageID> {
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let msg_id = MessageID::new();
            let content = Content::Text(ember_message::TextContent {
                body: format!("msg-{i}"),
            });
            if i % 2 == 0 {
                storage
                    .store_sent_message(contact_id, msg_id, &content)
                    .unwrap();
            } else {
                storage
                    .store_received_message(contact_id, msg_id, &content)
                    .unwrap();
            }
            ids.push(msg_id);
        }
        ids
    }

    #[test]
    fn test_get_messages_returns_chronological_order() {
        let storage = Storage::in_memory().unwrap();
        let contact = Identity::generate();
        let contact_id = storage
            .add_contact(contact.public_id(), Some("Alice"))
            .unwrap();

        store_n_messages(&storage, contact_id, 5);

        let messages = storage.get_messages(contact_id, 50, None).unwrap();
        assert_eq!(messages.len(), 5);

        // Verify chronological order (ascending id)
        for w in messages.windows(2) {
            assert!(
                w[0].id < w[1].id,
                "messages should be in ascending id order"
            );
        }

        // Verify content
        assert_eq!(messages[0].body.as_deref(), Some("msg-0"));
        assert_eq!(messages[4].body.as_deref(), Some("msg-4"));
    }

    #[test]
    fn test_get_messages_limit() {
        let storage = Storage::in_memory().unwrap();
        let contact = Identity::generate();
        let contact_id = storage
            .add_contact(contact.public_id(), Some("Alice"))
            .unwrap();

        store_n_messages(&storage, contact_id, 10);

        let messages = storage.get_messages(contact_id, 3, None).unwrap();
        assert_eq!(messages.len(), 3);

        // Should be the 3 most recent messages
        assert_eq!(messages[0].body.as_deref(), Some("msg-7"));
        assert_eq!(messages[2].body.as_deref(), Some("msg-9"));
    }

    #[test]
    fn test_get_messages_cursor_pagination() {
        let storage = Storage::in_memory().unwrap();
        let contact = Identity::generate();
        let contact_id = storage
            .add_contact(contact.public_id(), Some("Alice"))
            .unwrap();

        store_n_messages(&storage, contact_id, 10);

        // First page: most recent 3
        let page1 = storage.get_messages(contact_id, 3, None).unwrap();
        assert_eq!(page1.len(), 3);
        assert_eq!(page1[2].body.as_deref(), Some("msg-9"));

        // Second page: 3 before the oldest of page1
        let cursor = page1[0].id;
        let page2 = storage.get_messages(contact_id, 3, Some(cursor)).unwrap();
        assert_eq!(page2.len(), 3);

        // page2 should be older than page1
        assert!(page2.last().unwrap().id < page1[0].id);

        // Third page
        let cursor2 = page2[0].id;
        let page3 = storage.get_messages(contact_id, 3, Some(cursor2)).unwrap();
        assert_eq!(page3.len(), 3);

        // Fourth page: only 1 remaining
        let cursor3 = page3[0].id;
        let page4 = storage.get_messages(contact_id, 3, Some(cursor3)).unwrap();
        assert_eq!(page4.len(), 1);
        assert_eq!(page4[0].body.as_deref(), Some("msg-0"));
    }

    #[test]
    fn test_get_messages_direction() {
        let storage = Storage::in_memory().unwrap();
        let contact = Identity::generate();
        let contact_id = storage
            .add_contact(contact.public_id(), Some("Alice"))
            .unwrap();

        store_n_messages(&storage, contact_id, 4);

        let messages = storage.get_messages(contact_id, 50, None).unwrap();
        // Even indices are sent, odd are received
        assert_eq!(messages[0].direction, MessageDirection::Sent);
        assert_eq!(messages[1].direction, MessageDirection::Received);
        assert_eq!(messages[2].direction, MessageDirection::Sent);
        assert_eq!(messages[3].direction, MessageDirection::Received);
    }

    #[test]
    fn test_get_messages_empty_conversation() {
        let storage = Storage::in_memory().unwrap();
        let contact = Identity::generate();
        let contact_id = storage
            .add_contact(contact.public_id(), Some("Alice"))
            .unwrap();

        let messages = storage.get_messages(contact_id, 50, None).unwrap();
        assert!(messages.is_empty());
    }

    #[test]
    fn test_get_messages_isolates_contacts() {
        let storage = Storage::in_memory().unwrap();
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_id = storage
            .add_contact(alice.public_id(), Some("Alice"))
            .unwrap();
        let bob_id = storage.add_contact(bob.public_id(), Some("Bob")).unwrap();

        store_n_messages(&storage, alice_id, 5);
        store_n_messages(&storage, bob_id, 3);

        let alice_msgs = storage.get_messages(alice_id, 50, None).unwrap();
        let bob_msgs = storage.get_messages(bob_id, 50, None).unwrap();
        assert_eq!(alice_msgs.len(), 5);
        assert_eq!(bob_msgs.len(), 3);
    }

    #[test]
    fn test_get_last_message_per_contact() {
        let storage = Storage::in_memory().unwrap();
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_id = storage
            .add_contact(alice.public_id(), Some("Alice"))
            .unwrap();
        let bob_id = storage.add_contact(bob.public_id(), Some("Bob")).unwrap();

        store_n_messages(&storage, alice_id, 3);
        store_n_messages(&storage, bob_id, 5);

        let last = storage
            .get_last_message_per_contact(&[alice_id, bob_id])
            .unwrap();
        assert_eq!(last.get(&alice_id).map(|p| p.body.as_str()), Some("msg-2"));
        assert_eq!(last.get(&bob_id).map(|p| p.body.as_str()), Some("msg-4"));
        assert!(last.get(&alice_id).unwrap().created_at > 0);
        assert!(last.get(&bob_id).unwrap().created_at > 0);
    }

    #[test]
    fn test_get_last_message_per_contact_empty() {
        let storage = Storage::in_memory().unwrap();
        let result = storage.get_last_message_per_contact(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_last_message_skips_receipts() {
        let storage = Storage::in_memory().unwrap();
        let contact = Identity::generate();
        let contact_id = storage
            .add_contact(contact.public_id(), Some("Alice"))
            .unwrap();

        // Store a text message
        let msg_id1 = MessageID::new();
        let text = Content::Text(ember_message::TextContent {
            body: "Hello".to_string(),
        });
        storage
            .store_sent_message(contact_id, msg_id1, &text)
            .unwrap();

        // Store a receipt (should be skipped)
        let msg_id2 = MessageID::new();
        let receipt = Content::Receipt(ember_message::ReceiptContent {
            kind: ReceiptKind::Delivered,
            target_message_id: msg_id1,
        });
        storage
            .store_received_message(contact_id, msg_id2, &receipt)
            .unwrap();

        let last = storage.get_last_message_per_contact(&[contact_id]).unwrap();
        // Should return the text message, not the receipt
        assert_eq!(
            last.get(&contact_id).map(|p| p.body.as_str()),
            Some("Hello")
        );
        assert!(last.get(&contact_id).unwrap().created_at > 0);
    }

    #[test]
    fn test_dag_state_save_and_load() {
        let storage = Storage::in_memory().unwrap();

        let contact_key: [u8; 32] = [1u8; 32];
        let sender_head: ContentId = [10, 20, 30, 40, 50, 60, 70, 80];
        let peer_head1: ContentId = [11, 21, 31, 41, 51, 61, 71, 81];
        let peer_head2: ContentId = [12, 22, 32, 42, 52, 62, 72, 82];

        // Save DAG state
        storage
            .save_dag_state(
                &contact_key,
                5,
                Some(sender_head),
                &[peer_head1, peer_head2],
            )
            .unwrap();

        // Load and verify
        let states = storage.load_all_dag_states().unwrap();
        assert_eq!(states.len(), 1);

        let (epoch, loaded_sender_head, loaded_peer_heads) = &states[&contact_key];
        assert_eq!(*epoch, 5);
        assert_eq!(*loaded_sender_head, Some(sender_head));
        assert_eq!(loaded_peer_heads.len(), 2);
        assert!(loaded_peer_heads.contains(&peer_head1));
        assert!(loaded_peer_heads.contains(&peer_head2));
    }

    #[test]
    fn test_dag_state_save_no_sender_head() {
        let storage = Storage::in_memory().unwrap();

        let contact_key: [u8; 32] = [2u8; 32];

        // Save with no sender head and no peer heads
        storage.save_dag_state(&contact_key, 0, None, &[]).unwrap();

        let states = storage.load_all_dag_states().unwrap();
        let (epoch, sender_head, peer_heads) = &states[&contact_key];
        assert_eq!(*epoch, 0);
        assert!(sender_head.is_none());
        assert!(peer_heads.is_empty());
    }

    #[test]
    fn test_dag_state_upsert() {
        let storage = Storage::in_memory().unwrap();

        let contact_key: [u8; 32] = [3u8; 32];
        let head1: ContentId = [1, 2, 3, 4, 5, 6, 7, 8];
        let head2: ContentId = [9, 10, 11, 12, 13, 14, 15, 16];

        // Initial save
        storage
            .save_dag_state(&contact_key, 0, Some(head1), &[])
            .unwrap();

        // Upsert with new values
        storage
            .save_dag_state(&contact_key, 1, Some(head2), &[head1])
            .unwrap();

        let states = storage.load_all_dag_states().unwrap();
        assert_eq!(states.len(), 1);

        let (epoch, sender_head, peer_heads) = &states[&contact_key];
        assert_eq!(*epoch, 1);
        assert_eq!(*sender_head, Some(head2));
        assert_eq!(peer_heads, &[head1]);
    }

    #[test]
    fn test_dag_state_multiple_contacts() {
        let storage = Storage::in_memory().unwrap();

        let key1: [u8; 32] = [1u8; 32];
        let key2: [u8; 32] = [2u8; 32];
        let head_a: ContentId = [1, 2, 3, 4, 5, 6, 7, 8];
        let head_b: ContentId = [9, 10, 11, 12, 13, 14, 15, 16];

        storage.save_dag_state(&key1, 3, Some(head_a), &[]).unwrap();
        storage
            .save_dag_state(&key2, 7, Some(head_b), &[head_a])
            .unwrap();

        let states = storage.load_all_dag_states().unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(states[&key1].0, 3);
        assert_eq!(states[&key2].0, 7);
    }
}
