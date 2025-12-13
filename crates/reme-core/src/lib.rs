//! reme-core: Client business logic for Branch Messenger
//!
//! This crate provides the high-level client API for:
//! - Identity management
//! - Session establishment (X3DH)
//! - Sending and receiving encrypted messages
//! - Contact management
//! - Prekey management

use reme_encryption::{decrypt_inner_envelope, encrypt_inner_envelope, EncryptionError};
use reme_identity::{Identity, PublicID};
use reme_message::{
    Content, DeviceID, InnerEnvelope, MessageID, OuterEnvelope, ReceiptContent, ReceiptKind,
    RoutingKey, SessionEstablishment, TextContent, TombstoneEnvelope, TombstoneStatus,
    CURRENT_VERSION,
};
use reme_prekeys::{generate_prekey_bundle, LocalPrekeySecrets, SignedPrekeyID};
use reme_session::{
    derive_session_as_initiator, derive_session_as_responder, Session, SessionError,
};
use reme_storage::{Storage, StorageError};
use reme_transport::{Transport, TransportError};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use x25519_dalek::PublicKey as X25519PublicKey;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Session error: {0}")]
    Session(#[from] SessionError),

    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptionError),

    #[error("Contact not found")]
    ContactNotFound,

    #[error("Session not established with contact")]
    NoSession,

    #[error("Prekeys not initialized")]
    NoPrekeys,

    #[error("Message decryption failed: unknown sender")]
    UnknownSender,
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

/// The main client for Branch Messenger
///
/// Provides high-level API for:
/// - Sending messages to contacts
/// - Receiving and decrypting messages
/// - Managing contacts
/// - Managing prekeys
/// - Sending tombstones for message acknowledgment
pub struct Client<T: Transport> {
    identity: Identity,
    transport: Arc<T>,
    storage: Storage,
    /// In-memory session cache (sessions keyed by contact's PublicID)
    sessions: RwLock<HashMap<PublicID, Session>>,
    /// Local prekey secrets (loaded from storage or generated)
    prekey_secrets: RwLock<Option<LocalPrekeySecrets>>,
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
        use rand::RngCore;
        rand::rng().fill_bytes(&mut device_id);

        Self {
            identity,
            transport,
            storage,
            sessions: RwLock::new(HashMap::new()),
            prekey_secrets: RwLock::new(None),
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
            sessions: RwLock::new(HashMap::new()),
            prekey_secrets: RwLock::new(None),
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

    /// Get the client's public identity
    pub fn public_id(&self) -> &PublicID {
        self.identity.public_id()
    }

    /// Get the routing key for this client's mailbox
    pub fn routing_key(&self) -> RoutingKey {
        self.identity.public_id().routing_key()
    }

    // ========================================
    // Prekey Management
    // ========================================

    /// Initialize prekeys: load from storage or generate new ones
    pub async fn init_prekeys(&self, num_one_time_prekeys: usize) -> Result<(), ClientError> {
        // Try loading from storage first
        match self.storage.load_prekey_secrets() {
            Ok(secrets) => {
                info!("Loaded prekey secrets from storage");
                let mut prekey_secrets = self.prekey_secrets.write().await;
                *prekey_secrets = Some(secrets);
                Ok(())
            }
            Err(StorageError::NotFound) => {
                // Generate new prekeys
                info!("Generating new prekey bundle");
                let (secrets, bundle) = generate_prekey_bundle(&self.identity, num_one_time_prekeys);

                // Store locally
                self.storage.store_prekeys(&bundle, &secrets)?;

                // Upload to server
                self.transport
                    .upload_prekeys(self.routing_key(), bundle)
                    .await?;

                let mut prekey_secrets = self.prekey_secrets.write().await;
                *prekey_secrets = Some(secrets);

                info!("Prekeys generated and uploaded");
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Force regenerate and upload new prekeys
    pub async fn regenerate_prekeys(&self, num_one_time_prekeys: usize) -> Result<(), ClientError> {
        info!("Regenerating prekey bundle");
        let (secrets, bundle) = generate_prekey_bundle(&self.identity, num_one_time_prekeys);

        // Store locally
        self.storage.store_prekeys(&bundle, &secrets)?;

        // Upload to server
        self.transport
            .upload_prekeys(self.routing_key(), bundle)
            .await?;

        let mut prekey_secrets = self.prekey_secrets.write().await;
        *prekey_secrets = Some(secrets);

        info!("Prekeys regenerated and uploaded");
        Ok(())
    }

    /// Upload existing prekeys to server (useful for multi-node sync)
    pub async fn upload_prekeys(&self) -> Result<(), ClientError> {
        // Load prekeys from storage
        let (bundle, secrets) = self.storage.load_prekeys()?;

        // Upload to server
        self.transport
            .upload_prekeys(self.routing_key(), bundle)
            .await?;

        // Update in-memory cache
        let mut prekey_secrets = self.prekey_secrets.write().await;
        *prekey_secrets = Some(secrets);

        info!("Prekeys uploaded to server");
        Ok(())
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
        Ok(Contact {
            id,
            public_id: *public_id,
            name: None, // TODO: Add name retrieval to storage
        })
    }

    // ========================================
    // Session Management
    // ========================================

    /// Establish a session with a contact by fetching their prekeys
    pub async fn establish_session(&self, contact: &PublicID) -> Result<(), ClientError> {
        // Check if we already have a session
        {
            let sessions = self.sessions.read().await;
            if sessions.contains_key(contact) {
                debug!("Session already exists with contact");
                return Ok(());
            }
        }

        // Fetch contact's prekey bundle from server
        let contact_routing_key = contact.routing_key();
        let bundle = self.transport.fetch_prekeys(contact_routing_key).await?;

        // Derive session as initiator
        let session = derive_session_as_initiator(&self.identity, &bundle, true)?;

        // Store session in memory
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(*contact, session);
        }

        // Store session in database
        let contact_id = self.storage.get_contact_id(contact)?;
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(contact) {
            self.storage.store_session(contact_id, session)?;
        }

        info!("Session established with contact");
        Ok(())
    }

    /// Check if a session exists with a contact
    pub async fn has_session(&self, contact: &PublicID) -> bool {
        let sessions = self.sessions.read().await;
        sessions.contains_key(contact)
    }

    // ========================================
    // Sending Messages
    // ========================================

    /// Send a text message to a contact
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

    /// Send a message with arbitrary content
    async fn send_message(&self, to: &PublicID, content: Content) -> Result<MessageID, ClientError> {
        // Ensure session exists
        if !self.has_session(to).await {
            self.establish_session(to).await?;
        }

        // Get session and check if we need to include session init data
        let needs_session_init = {
            let sessions = self.sessions.read().await;
            let session = sessions.get(to).ok_or(ClientError::NoSession)?;
            !session.is_confirmed()
        };

        // Create outer envelope first to get message ID
        let routing_key = to.routing_key();
        let outer_message_id = MessageID::new();

        // Create inner envelope
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let inner = InnerEnvelope {
            version: CURRENT_VERSION,
            from: *self.identity.public_id(),
            to: *to,
            created_at_ms: now_ms,
            outer_message_id,
            content: content.clone(),
        };

        // Get session for encryption
        let sessions = self.sessions.read().await;
        let session = sessions.get(to).ok_or(ClientError::NoSession)?;

        // Encrypt inner envelope
        let ciphertext = encrypt_inner_envelope(&inner, session.send_key(), &outer_message_id)?;

        // Create outer envelope (with or without session init)
        let outer = if needs_session_init {
            let session_init = SessionEstablishment {
                sender_identity: self.identity.public_id().to_bytes(),
                ephemeral_public: session.ephemeral_public().to_bytes(),
                used_one_time_prekey_id: session.used_one_time_prekey_id().map(|id| id.to_bytes()),
            };
            OuterEnvelope {
                version: CURRENT_VERSION,
                flags: reme_message::flags::SESSION_INIT,
                routing_key,
                created_at_ms: Some(now_ms),
                ttl: Some(7 * 24 * 60 * 60), // 7 days default TTL
                message_id: outer_message_id,
                session_init: Some(session_init),
                inner_ciphertext: ciphertext,
            }
        } else {
            OuterEnvelope {
                version: CURRENT_VERSION,
                flags: 0,
                routing_key,
                created_at_ms: Some(now_ms),
                ttl: Some(7 * 24 * 60 * 60), // 7 days default TTL
                message_id: outer_message_id,
                session_init: None,
                inner_ciphertext: ciphertext,
            }
        };
        drop(sessions);

        // Submit to transport
        self.transport.submit_message(outer).await?;

        // Mark session as confirmed after first message sent
        if needs_session_init {
            let mut sessions = self.sessions.write().await;
            if let Some(session) = sessions.get_mut(to) {
                session.set_confirmed();
            }
        }

        // Store sent message
        let contact_id = self.storage.get_contact_id(to)?;
        self.storage
            .store_sent_message(contact_id, outer_message_id, &content)?;

        debug!("Message sent to contact (session_init: {})", needs_session_init);
        Ok(outer_message_id)
    }

    // ========================================
    // Receiving Messages
    // ========================================

    /// Fetch and decrypt pending messages from the mailbox
    pub async fn fetch_messages(&self) -> Result<Vec<ReceivedMessage>, ClientError> {
        let routing_key = self.routing_key();
        let envelopes = self.transport.fetch_messages(routing_key).await?;

        let mut messages = Vec::new();

        for outer in envelopes {
            match self.decrypt_message(&outer).await {
                Ok(msg) => messages.push(msg),
                Err(e) => {
                    warn!("Failed to decrypt message: {}", e);
                    // Continue processing other messages
                }
            }
        }

        Ok(messages)
    }

    /// Decrypt a single message
    async fn decrypt_message(
        &self,
        outer: &OuterEnvelope,
    ) -> Result<ReceivedMessage, ClientError> {
        // First, check if this is a session establishment message
        if outer.has_session_init() {
            if let Some(ref session_init) = outer.session_init {
                return self.handle_session_init_message(outer, session_init).await;
            }
        }

        // Try to decrypt with known sessions
        let sessions = self.sessions.read().await;
        for (sender_id, session) in sessions.iter() {
            match decrypt_inner_envelope(
                &outer.inner_ciphertext,
                session.recv_key(),
                &outer.message_id,
            ) {
                Ok(inner) => {
                    // Verify sender matches
                    if &inner.from != sender_id {
                        continue;
                    }

                    // Store received message
                    if let Ok(contact_id) = self.storage.get_contact_id(sender_id) {
                        let _ = self.storage.store_received_message(
                            contact_id,
                            outer.message_id,
                            &inner.content,
                        );
                    }

                    return Ok(ReceivedMessage {
                        message_id: outer.message_id,
                        from: inner.from,
                        content: inner.content,
                        created_at_ms: inner.created_at_ms,
                    });
                }
                Err(_) => continue,
            }
        }

        Err(ClientError::UnknownSender)
    }

    /// Handle an incoming message with session establishment data
    async fn handle_session_init_message(
        &self,
        outer: &OuterEnvelope,
        session_init: &SessionEstablishment,
    ) -> Result<ReceivedMessage, ClientError> {
        // Get our prekey secrets
        let prekey_secrets = self.prekey_secrets.read().await;
        let secrets = prekey_secrets.as_ref().ok_or(ClientError::NoPrekeys)?;

        // Parse sender's identity and ephemeral key
        let sender_id = PublicID::from_bytes(&session_init.sender_identity);
        let ephemeral_public = X25519PublicKey::from(session_init.ephemeral_public);
        let used_otp_id = session_init
            .used_one_time_prekey_id
            .map(SignedPrekeyID::from_bytes);

        // Derive the session as responder
        let session = derive_session_as_responder(
            &self.identity,
            secrets,
            &sender_id,
            &ephemeral_public,
            used_otp_id,
        )?;

        // Try to decrypt the message
        let inner = decrypt_inner_envelope(
            &outer.inner_ciphertext,
            session.recv_key(),
            &outer.message_id,
        )?;

        // Verify the sender matches
        if inner.from != sender_id {
            return Err(ClientError::UnknownSender);
        }

        // Ensure contact exists (add if not)
        let contact_id = match self.storage.get_contact_id(&sender_id) {
            Ok(id) => id,
            Err(StorageError::NotFound) => {
                info!("Adding new contact from incoming message");
                self.storage.add_contact(&sender_id, None)?
            }
            Err(e) => return Err(e.into()),
        };

        // Store the session
        self.storage.store_session(contact_id, &session)?;

        // Add session to memory cache
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(sender_id, session);
        }

        // Store received message
        let _ = self.storage.store_received_message(
            contact_id,
            outer.message_id,
            &inner.content,
        );

        info!("Session established from incoming message");

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
    /// - Optional delivery/read receipts for the sender (application layer)
    ///
    /// # Arguments
    ///
    /// * `message` - The received message to acknowledge
    /// * `status` - How the message was processed (Delivered/Read/Deleted)
    /// * `include_receipt` - Whether to include an encrypted receipt for the sender
    pub async fn send_tombstone(
        &self,
        message: &ReceivedMessage,
        status: TombstoneStatus,
        include_receipt: bool,
    ) -> Result<(), ClientError> {
        // Get the routing key for this message (our mailbox where it was stored)
        let routing_key = self.routing_key();

        // Get next sequence number
        let sequence = self.tombstone_sequence.fetch_add(1, Ordering::SeqCst);

        // Get recipient's X25519 secret key for signing (XEdDSA)
        let recipient_secret = self.identity.to_bytes();
        let recipient_id_pub = self.identity.public_id().to_bytes();

        // Optionally get sender's public key and session for encrypted receipt
        let (sender_pub, session_recv_key, inner_ciphertext) = if include_receipt {
            // Try to get session with sender
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(&message.from) {
                // Get sender's X25519 public key (from session)
                // For the receipt, we need the sender's public key
                // The sender_id is an Ed25519 key, we need to use the session's ephemeral
                // For simplicity in PoC, we skip the encrypted receipt if we can't get the key
                // In a full implementation, we'd store the sender's X25519 public during session init
                let recv_key = *session.recv_key();
                (None, Some(recv_key), None::<&[u8]>)
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };

        // Create tombstone
        let tombstone = TombstoneEnvelope::new(
            message.message_id,
            routing_key,
            recipient_id_pub,
            &recipient_secret,
            self.device_id,
            sequence,
            status,
            sender_pub.as_ref(),
            session_recv_key.as_ref(),
            inner_ciphertext,
        );

        // Submit to transport
        self.transport.submit_tombstone(tombstone).await?;

        debug!(
            "Tombstone sent for message {:?} (status: {:?}, seq: {})",
            message.message_id, status, sequence
        );

        Ok(())
    }

    /// Send a simple delivery tombstone (no encrypted receipt)
    ///
    /// This is the recommended method for acknowledging message delivery
    /// when you don't need to send detailed receipt info to the sender.
    pub async fn send_delivery_tombstone(
        &self,
        message: &ReceivedMessage,
    ) -> Result<(), ClientError> {
        self.send_tombstone(message, TombstoneStatus::Delivered, false)
            .await
    }

    /// Send a read tombstone (no encrypted receipt)
    ///
    /// Use this when the user has opened/read the message.
    pub async fn send_read_tombstone(&self, message: &ReceivedMessage) -> Result<(), ClientError> {
        self.send_tombstone(message, TombstoneStatus::Read, false)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use reme_prekeys::SignedPrekeyBundle;
    use std::sync::Mutex;

    /// Mock transport for testing
    struct MockTransport {
        messages: Mutex<Vec<OuterEnvelope>>,
        tombstones: Mutex<Vec<TombstoneEnvelope>>,
        prekeys: Mutex<HashMap<RoutingKey, SignedPrekeyBundle>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                messages: Mutex::new(Vec::new()),
                tombstones: Mutex::new(Vec::new()),
                prekeys: Mutex::new(HashMap::new()),
            }
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

        async fn fetch_messages(
            &self,
            _routing_key: RoutingKey,
        ) -> Result<Vec<OuterEnvelope>, TransportError> {
            Ok(self.messages.lock().unwrap().drain(..).collect())
        }

        async fn upload_prekeys(
            &self,
            routing_key: RoutingKey,
            bundle: SignedPrekeyBundle,
        ) -> Result<(), TransportError> {
            self.prekeys.lock().unwrap().insert(routing_key, bundle);
            Ok(())
        }

        async fn fetch_prekeys(
            &self,
            routing_key: RoutingKey,
        ) -> Result<SignedPrekeyBundle, TransportError> {
            self.prekeys
                .lock()
                .unwrap()
                .get(&routing_key)
                .cloned()
                .ok_or(TransportError::NotFound)
        }
    }

    #[tokio::test]
    async fn test_client_init_prekeys() {
        let identity = Identity::generate();
        let transport = Arc::new(MockTransport::new());
        let storage = Storage::in_memory().unwrap();

        let client = Client::new(identity, transport.clone(), storage);

        // Initialize prekeys
        client.init_prekeys(5).await.unwrap();

        // Verify prekeys were uploaded
        let routing_key = client.routing_key();
        let prekeys = transport.prekeys.lock().unwrap();
        assert!(prekeys.contains_key(&routing_key));
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
    async fn test_session_establishment_and_messaging() {
        // Create Alice
        let alice_identity = Identity::generate();
        let alice_transport = Arc::new(MockTransport::new());
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, alice_transport.clone(), alice_storage);

        // Create Bob
        let bob_identity = Identity::generate();
        let bob_transport = alice_transport.clone(); // Share transport for testing
        let bob_storage = Storage::in_memory().unwrap();
        let bob = Client::new(bob_identity, bob_transport, bob_storage);

        // Bob initializes prekeys (so Alice can establish session)
        bob.init_prekeys(5).await.unwrap();

        // Alice adds Bob as contact and establishes session
        alice
            .add_contact(bob.public_id(), Some("Bob"))
            .unwrap();
        alice.establish_session(bob.public_id()).await.unwrap();

        // Verify session exists
        assert!(alice.has_session(bob.public_id()).await);

        // Alice sends a message
        let msg_id = alice.send_text(bob.public_id(), "Hello Bob!").await.unwrap();
        assert!(msg_id.as_bytes().len() > 0);

        // Verify message was submitted
        let messages = alice_transport.messages.lock().unwrap();
        assert_eq!(messages.len(), 1);
    }
}
