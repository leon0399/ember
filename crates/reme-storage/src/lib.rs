use reme_identity::PublicID;
use reme_message::{Content, MessageID};
use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;
use tracing::{debug, trace};

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

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
        Ok(PublicID::from_bytes(&public_id_bytes))
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
            contacts.push((id, PublicID::from_bytes(&public_id_arr), name));
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
