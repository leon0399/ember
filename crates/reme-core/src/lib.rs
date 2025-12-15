//! reme-core: Client business logic for Resilient Messenger
//!
//! This crate provides the high-level client API for:
//! - Identity management
//! - MIK-only stateless encryption (Session V1-style)
//! - Sending and receiving encrypted messages
//! - Contact management

use reme_encryption::{decrypt_with_mik, encrypt_to_mik, EncryptionError};
use reme_identity::{Identity, PublicID};
use reme_message::{
    Content, DeviceID, InnerEnvelope, MessageID, OuterEnvelope, ReceiptContent, ReceiptKind,
    RoutingKey, TextContent, TombstoneEnvelope, TombstoneStatus, CURRENT_VERSION,
};
use reme_storage::{Storage, StorageError};
use reme_transport::{Transport, TransportError};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptionError),

    #[error("Contact not found")]
    ContactNotFound,

    #[error("Message decryption failed (wrong recipient, tampered, or corrupted)")]
    DecryptionFailed,

    #[error("Invalid sender signature: message may be forged or tampered")]
    InvalidSenderSignature,
}

/// Represents a contact in the messenger
#[derive(Debug, Clone)]
pub struct Contact {
    pub id: i64,
    pub public_id: PublicID,
    pub name: Option<String>,
}

/// Represents a decrypted received message
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub message_id: MessageID,
    pub from: PublicID,
    pub content: Content,
    pub created_at_ms: u64,
}

/// The main client for Resilient Messenger (MIK-only stateless encryption)
///
/// Provides high-level API for:
/// - Sending messages to contacts (stateless, no session establishment needed)
/// - Receiving and decrypting messages
/// - Managing contacts
/// - Sending tombstones for message acknowledgment
///
/// With MIK-only encryption, each message includes an ephemeral key for
/// stateless ECDH. No session state is maintained between messages.
pub struct Client<T: Transport> {
    identity: Identity,
    transport: Arc<T>,
    storage: Storage,
    /// Device ID for tombstone sequence management (unique per device)
    device_id: DeviceID,
    /// Monotonically increasing tombstone sequence counter
    tombstone_sequence: AtomicU64,
}

impl<T: Transport> Client<T> {
    /// Create a new client with the given identity, transport, and storage
    ///
    /// Generates a random device ID for tombstone sequence management.
    pub fn new(identity: Identity, transport: Arc<T>, storage: Storage) -> Self {
        // Generate random device ID
        let mut device_id = [0u8; 16];
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(&mut device_id);

        Self {
            identity,
            transport,
            storage,
            device_id,
            tombstone_sequence: AtomicU64::new(1), // Start at 1
        }
    }

    /// Create a new client with a specific device ID
    ///
    /// Use this when you need deterministic device IDs (e.g., for testing or
    /// when restoring from storage).
    pub fn with_device_id(
        identity: Identity,
        transport: Arc<T>,
        storage: Storage,
        device_id: DeviceID,
        initial_sequence: u64,
    ) -> Self {
        Self {
            identity,
            transport,
            storage,
            device_id,
            tombstone_sequence: AtomicU64::new(initial_sequence),
        }
    }

    /// Get the device ID
    pub fn device_id(&self) -> &DeviceID {
        &self.device_id
    }

    /// Get the current tombstone sequence number (for persistence)
    pub fn tombstone_sequence(&self) -> u64 {
        self.tombstone_sequence.load(Ordering::SeqCst)
    }

    /// Get the client's public identity (MIK)
    pub fn public_id(&self) -> &PublicID {
        self.identity.public_id()
    }

    /// Get the routing key for this client's mailbox
    pub fn routing_key(&self) -> RoutingKey {
        self.identity.public_id().routing_key()
    }

    /// Get the identity's private key bytes (for decryption)
    fn private_key(&self) -> [u8; 32] {
        self.identity.to_bytes()
    }

    // ========================================
    // Contact Management
    // ========================================

    /// Add a new contact
    pub fn add_contact(
        &self,
        public_id: &PublicID,
        name: Option<&str>,
    ) -> Result<Contact, ClientError> {
        let id = self.storage.add_contact(public_id, name)?;
        Ok(Contact {
            id,
            public_id: *public_id,
            name: name.map(String::from),
        })
    }

    /// Get contact by public ID
    pub fn get_contact(&self, public_id: &PublicID) -> Result<Contact, ClientError> {
        let id = self.storage.get_contact_id(public_id)?;
        let name = self.storage.get_contact_name(id).ok().flatten();
        Ok(Contact {
            id,
            public_id: *public_id,
            name,
        })
    }

    /// List all contacts
    pub fn list_contacts(&self) -> Result<Vec<Contact>, ClientError> {
        let contacts = self.storage.list_contacts()?;
        Ok(contacts
            .into_iter()
            .map(|(id, public_id, name)| Contact { id, public_id, name })
            .collect())
    }

    // ========================================
    // Sending Messages (MIK-only, stateless)
    // ========================================

    /// Send a text message to a contact
    ///
    /// With MIK-only encryption, no session establishment is needed.
    /// Each message is encrypted directly to the recipient's public MIK.
    pub async fn send_text(&self, to: &PublicID, text: &str) -> Result<MessageID, ClientError> {
        let content = Content::Text(TextContent {
            body: text.to_string(),
        });
        self.send_message(to, content).await
    }

    /// Send a delivery receipt for a received message
    pub async fn send_delivery_receipt(
        &self,
        to: &PublicID,
        for_message_id: MessageID,
    ) -> Result<MessageID, ClientError> {
        let content = Content::Receipt(ReceiptContent {
            target_message_id: for_message_id,
            kind: ReceiptKind::Delivered,
        });
        self.send_message(to, content).await
    }

    /// Send a read receipt for a received message
    pub async fn send_read_receipt(
        &self,
        to: &PublicID,
        for_message_id: MessageID,
    ) -> Result<MessageID, ClientError> {
        let content = Content::Receipt(ReceiptContent {
            target_message_id: for_message_id,
            kind: ReceiptKind::Read,
        });
        self.send_message(to, content).await
    }

    /// Send a message with arbitrary content (MIK-only encryption)
    async fn send_message(&self, to: &PublicID, content: Content) -> Result<MessageID, ClientError> {
        // Generate message ID
        let outer_message_id = MessageID::new();
        let routing_key = to.routing_key();

        // Get precise timestamp for inner envelope
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Create inner envelope without signature first
        let mut inner = InnerEnvelope {
            from: *self.identity.public_id(),
            created_at_ms: now_ms,
            content: content.clone(),
            signature: None,
        };

        // Sign the envelope with sender's private key (message_id included in signable bytes)
        let signable = inner.signable_bytes(&outer_message_id);
        inner.signature = Some(InnerEnvelope::sign(&signable, &self.private_key()));

        // Encrypt to recipient's MIK (stateless, returns ephemeral_key + ciphertext)
        let (ephemeral_key, ciphertext) = encrypt_to_mik(&inner, to, &outer_message_id)?;

        // Create outer envelope (must use same message_id as encryption!)
        let outer = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: reme_message::now_hours(),
            ttl_hours: Some(7 * 24), // 7 days default TTL in hours
            message_id: outer_message_id, // Must match the ID used for encryption
            ephemeral_key,
            inner_ciphertext: ciphertext,
        };

        // Store locally first - we require local message history before transmitting.
        // This prepares for possible future support of DAG-based message history.
        let contact_id = self.storage.get_contact_id(to)?;
        self.storage
            .store_sent_message(contact_id, outer_message_id, &content)?;

        // Only submit to transport after successful local storage
        self.transport.submit_message(outer).await?;

        debug!("Message sent to contact (MIK-only encryption)");
        Ok(outer_message_id)
    }

    // ========================================
    // Receiving Messages (MIK-only, stateless)
    // ========================================

    /// Process a raw envelope into a decrypted message
    ///
    /// With MIK-only encryption, each message is decrypted using:
    /// 1. The ephemeral public key from the envelope
    /// 2. Our MIK private key
    ///
    /// After decryption, the sender signature is verified to prevent impersonation.
    /// No session state is needed - each message is independently decryptable.
    ///
    /// The recipient binding is implicit: if decryption succeeds, the message was
    /// intended for us (sealed box ECDH cryptographically binds to recipient).
    pub async fn process_message(
        &self,
        outer: &OuterEnvelope,
    ) -> Result<ReceivedMessage, ClientError> {
        // Decrypt using MIK (stateless decryption)
        // This also verifies AAD binding (message_id must match)
        let inner = decrypt_with_mik(
            &outer.ephemeral_key,
            &outer.inner_ciphertext,
            &self.private_key(),
            &outer.message_id,
        )?;

        // Verify sender signature to prevent impersonation attacks
        // This ensures the `from` field matches who actually signed the message
        // The signature also binds to message_id (triple binding)
        if !inner.verify_signature(&outer.message_id) {
            return Err(ClientError::InvalidSenderSignature);
        }

        // Note: Recipient binding is implicit via sealed box ECDH.
        // If decryption succeeded, the message was intended for our MIK.
        // The removed `to` field is cryptographically redundant.

        let sender_id = inner.from;

        // Ensure contact exists (add if not)
        let contact_id = match self.storage.get_contact_id(&sender_id) {
            Ok(id) => id,
            Err(StorageError::NotFound) => {
                info!("Adding new contact from incoming message");
                self.storage.add_contact(&sender_id, None)?
            }
            Err(e) => return Err(e.into()),
        };

        // Store received message - fail if storage fails to prevent data loss
        self.storage.store_received_message(
            contact_id,
            outer.message_id,
            &inner.content,
        )?;

        Ok(ReceivedMessage {
            message_id: outer.message_id,
            from: inner.from,
            content: inner.content,
            created_at_ms: inner.created_at_ms,
        })
    }

    /// Process a delivery receipt
    pub fn process_delivery_receipt(&self, message_id: MessageID) -> Result<(), ClientError> {
        self.storage.mark_delivered(message_id)?;
        Ok(())
    }

    /// Process a read receipt
    pub fn process_read_receipt(&self, message_id: MessageID) -> Result<(), ClientError> {
        self.storage.mark_read(message_id)?;
        Ok(())
    }

    // ========================================
    // Tombstone Management
    // ========================================

    /// Send a tombstone to acknowledge message receipt
    ///
    /// Tombstones are cryptographically signed acknowledgments that enable:
    /// - Cache clearing on relay nodes (network layer)
    /// - Optional delivery/read receipts for the sender (application layer, future)
    ///
    /// # Arguments
    ///
    /// * `message` - The received message to acknowledge
    /// * `status` - How the message was processed (Delivered/Read/Deleted)
    pub async fn send_tombstone(
        &self,
        message: &ReceivedMessage,
        status: TombstoneStatus,
    ) -> Result<(), ClientError> {
        // Get the routing key for this message (our mailbox where it was stored)
        let routing_key = self.routing_key();

        // Get next sequence number
        let sequence = self.tombstone_sequence.fetch_add(1, Ordering::SeqCst);

        // Get recipient's X25519 secret key for signing (XEdDSA)
        let recipient_secret = self.identity.to_bytes();
        let recipient_id_pub = self.identity.public_id().to_bytes();

        // Create tombstone
        let tombstone = TombstoneEnvelope::new(
            message.message_id,
            routing_key,
            recipient_id_pub,
            &recipient_secret,
            self.device_id,
            sequence,
            status,
            None, // sender_pub - not used in MIK-only v0.2
            None, // session_recv_key - not used in MIK-only v0.2
            None::<&[u8]>, // inner_ciphertext - not used in MIK-only v0.2
        );

        // Submit to transport
        self.transport.submit_tombstone(tombstone).await?;

        debug!(
            "Tombstone sent for message {:?} (status: {:?}, seq: {})",
            message.message_id, status, sequence
        );

        Ok(())
    }

    /// Send a delivery tombstone
    ///
    /// This is the recommended method for acknowledging message delivery.
    pub async fn send_delivery_tombstone(
        &self,
        message: &ReceivedMessage,
    ) -> Result<(), ClientError> {
        self.send_tombstone(message, TombstoneStatus::Delivered)
            .await
    }

    /// Send a read tombstone
    ///
    /// Use this when the user has opened/read the message.
    pub async fn send_read_tombstone(&self, message: &ReceivedMessage) -> Result<(), ClientError> {
        self.send_tombstone(message, TombstoneStatus::Read).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Mock transport for testing (MIK-only, no prekeys)
    struct MockTransport {
        messages: Mutex<Vec<OuterEnvelope>>,
        tombstones: Mutex<Vec<TombstoneEnvelope>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                messages: Mutex::new(Vec::new()),
                tombstones: Mutex::new(Vec::new()),
            }
        }

        /// Helper to get pending messages (simulates push-based delivery)
        fn take_messages(&self) -> Vec<OuterEnvelope> {
            self.messages.lock().unwrap().drain(..).collect()
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
            self.messages.lock().unwrap().push(envelope);
            Ok(())
        }

        async fn submit_tombstone(
            &self,
            tombstone: TombstoneEnvelope,
        ) -> Result<(), TransportError> {
            self.tombstones.lock().unwrap().push(tombstone);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_add_contact() {
        let identity = Identity::generate();
        let transport = Arc::new(MockTransport::new());
        let storage = Storage::in_memory().unwrap();

        let client = Client::new(identity, transport, storage);

        let contact_identity = Identity::generate();
        let contact = client
            .add_contact(contact_identity.public_id(), Some("Alice"))
            .unwrap();

        assert_eq!(contact.public_id, *contact_identity.public_id());
        assert_eq!(contact.name, Some("Alice".to_string()));
    }

    #[tokio::test]
    async fn test_send_message_mik_only() {
        // Create Alice
        let alice_identity = Identity::generate();
        let alice_transport = Arc::new(MockTransport::new());
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, alice_transport.clone(), alice_storage);

        // Create Bob identity (no need to initialize prekeys!)
        let bob_identity = Identity::generate();

        // Alice adds Bob as contact
        alice
            .add_contact(bob_identity.public_id(), Some("Bob"))
            .unwrap();

        // Alice sends a message (no session establishment needed!)
        let msg_id = alice.send_text(bob_identity.public_id(), "Hello Bob!").await.unwrap();
        assert!(msg_id.as_bytes().len() > 0);

        // Verify message was submitted
        let messages = alice_transport.messages.lock().unwrap();
        assert_eq!(messages.len(), 1);

        // Verify ephemeral key is present
        assert_ne!(messages[0].ephemeral_key, [0u8; 32]);
    }

    #[tokio::test]
    async fn test_send_receive_roundtrip() {
        // Create Alice and Bob with shared transport
        let shared_transport = Arc::new(MockTransport::new());

        let alice_identity = Identity::generate();
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, shared_transport.clone(), alice_storage);

        let bob_identity = Identity::generate();
        let bob_storage = Storage::in_memory().unwrap();
        let bob = Client::new(bob_identity, shared_transport.clone(), bob_storage);

        // Alice adds Bob as contact and sends a message
        alice.add_contact(bob.public_id(), Some("Bob")).unwrap();
        let _msg_id = alice.send_text(bob.public_id(), "Hello Bob!").await.unwrap();

        // Bob receives and decrypts the message
        let messages = shared_transport.take_messages();
        assert_eq!(messages.len(), 1);

        let received = bob.process_message(&messages[0]).await.unwrap();
        assert_eq!(received.from, *alice.public_id());

        match received.content {
            Content::Text(text) => assert_eq!(text.body, "Hello Bob!"),
            _ => panic!("Expected text content"),
        }
    }

    #[tokio::test]
    async fn test_wrong_recipient_fails() {
        let shared_transport = Arc::new(MockTransport::new());

        let alice_identity = Identity::generate();
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, shared_transport.clone(), alice_storage);

        let bob_identity = Identity::generate();
        let bob_storage = Storage::in_memory().unwrap();
        let bob = Client::new(bob_identity, shared_transport.clone(), bob_storage);

        // Create Eve (wrong recipient)
        let eve_identity = Identity::generate();
        let eve_storage = Storage::in_memory().unwrap();
        let eve = Client::new(eve_identity, shared_transport.clone(), eve_storage);

        // Alice sends to Bob
        alice.add_contact(bob.public_id(), Some("Bob")).unwrap();
        alice.send_text(bob.public_id(), "Secret message").await.unwrap();

        // Eve tries to decrypt (should fail)
        let messages = shared_transport.take_messages();
        let result = eve.process_message(&messages[0]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tombstone_sent() {
        let shared_transport = Arc::new(MockTransport::new());

        let alice_identity = Identity::generate();
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, shared_transport.clone(), alice_storage);

        let bob_identity = Identity::generate();
        let bob_storage = Storage::in_memory().unwrap();
        let bob = Client::new(bob_identity, shared_transport.clone(), bob_storage);

        // Alice sends to Bob
        alice.add_contact(bob.public_id(), Some("Bob")).unwrap();
        alice.send_text(bob.public_id(), "Hello!").await.unwrap();

        // Bob receives
        let messages = shared_transport.take_messages();
        let received = bob.process_message(&messages[0]).await.unwrap();

        // Bob sends tombstone
        bob.send_delivery_tombstone(&received).await.unwrap();

        // Verify tombstone was submitted
        let tombstones = shared_transport.tombstones.lock().unwrap();
        assert_eq!(tombstones.len(), 1);
        assert_eq!(tombstones[0].target_message_id, received.message_id);
    }
}
