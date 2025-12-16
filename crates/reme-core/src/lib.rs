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
    Content, ContentId, ConversationDag, DeviceID, InnerEnvelope, MessageID, OuterEnvelope,
    ReceiptContent, ReceiptKind, RoutingKey, TextContent, TombstoneEnvelope, TombstoneStatus,
    CURRENT_VERSION, FLAG_DETACHED,
};
use reme_storage::{Storage, StorageError};
use reme_transport::{Transport, TransportError};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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

    #[error("Message not intended for this recipient (routing key mismatch)")]
    WrongRecipient,

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
    /// Wire message ID (for network operations, tombstones)
    pub message_id: MessageID,
    /// Sender's public ID
    pub from: PublicID,
    /// Message content
    pub content: Content,
    /// When the message was created (milliseconds since epoch)
    pub created_at_ms: u64,
    /// Content-addressed ID (for DAG references)
    pub content_id: ContentId,
    /// Whether this message has gaps in the DAG (missing parents)
    pub has_gaps: bool,
    /// Sender likely lost state: we have history from them but they sent prev_self=None
    /// (not including intentionally detached messages)
    pub sender_state_reset: bool,
    /// We likely lost state: sender's observed_heads contains IDs we don't recognize
    /// This means the peer saw messages from us that we have no record of sending
    pub local_state_behind: bool,
}

/// The main client for Resilient Messenger (MIK-only stateless encryption)
///
/// Provides high-level API for:
/// - Sending messages to contacts (stateless, no session establishment needed)
/// - Receiving and decrypting messages
/// - Managing contacts
/// - Sending tombstones for message acknowledgment
/// - Merkle DAG tracking for message ordering and gap detection
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
    /// DAG state per contact (keyed by PublicID bytes)
    /// Tracks message ordering for gap detection
    dag_state: Mutex<HashMap<[u8; 32], ConversationDag>>,
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
            dag_state: Mutex::new(HashMap::new()),
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
            dag_state: Mutex::new(HashMap::new()),
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

    /// Get the latest observed heads from the receiver tracker for a contact.
    ///
    /// Returns the content_ids of messages we've received from the peer.
    /// In 1:1 chat, this is typically just the peer's latest message.
    fn get_observed_heads(&self, dag: &ConversationDag) -> Vec<ContentId> {
        dag.observed_heads()
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
    // Conversation History Management
    // ========================================

    /// Clear conversation history with a contact and increment epoch.
    ///
    /// This increments the DAG epoch for this conversation, which:
    /// - Clears all DAG tracking state (sender chain, receiver state, peer head)
    /// - Future messages will start fresh chains
    /// - Messages referencing pre-epoch content_ids will be detected as gaps
    ///
    /// Note: This does NOT delete stored messages from local storage.
    /// Use this when both parties agree to clear history.
    pub fn clear_conversation_dag(&self, contact: &PublicID) -> u16 {
        let contact_key = contact.to_bytes();
        let mut dag_state = self.dag_state.lock().unwrap();
        let dag = dag_state.entry(contact_key).or_insert_with(ConversationDag::new);
        dag.increment_epoch();
        dag.epoch
    }

    /// Get the current epoch for a conversation.
    pub fn get_conversation_epoch(&self, contact: &PublicID) -> u16 {
        let contact_key = contact.to_bytes();
        let dag_state = self.dag_state.lock().unwrap();
        dag_state.get(&contact_key).map(|d| d.epoch).unwrap_or(0)
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
        self.send_message_internal(to, content, false).await
    }

    /// Send a detached text message (no DAG linkage).
    ///
    /// Use this for constrained transports (LoRa, BLE) where bandwidth is limited
    /// and DAG overhead should be avoided. Detached messages have no prev_self
    /// or observed_heads, making them "floating" in the message history.
    pub async fn send_text_detached(
        &self,
        to: &PublicID,
        text: &str,
    ) -> Result<MessageID, ClientError> {
        let content = Content::Text(TextContent {
            body: text.to_string(),
        });
        self.send_message_internal(to, content, true).await
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
        self.send_message_internal(to, content, false).await
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
        self.send_message_internal(to, content, false).await
    }

    /// Send a message with arbitrary content (MIK-only encryption)
    ///
    /// # Arguments
    /// * `to` - Recipient's public ID
    /// * `content` - Message content
    /// * `detached` - If true, send without DAG linkage (for constrained transports)
    async fn send_message_internal(
        &self,
        to: &PublicID,
        content: Content,
        detached: bool,
    ) -> Result<MessageID, ClientError> {
        // Generate message ID
        let outer_message_id = MessageID::new();
        let routing_key = to.routing_key();

        // Get precise timestamp for inner envelope
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Get DAG fields from conversation state
        let contact_key = to.to_bytes();
        let (prev_self, observed_heads, epoch) = {
            let dag_state = self.dag_state.lock().unwrap();
            if detached {
                // Detached messages have no DAG linkage
                let epoch = dag_state.get(&contact_key).map(|d| d.epoch).unwrap_or(0);
                (None, Vec::new(), epoch)
            } else if let Some(dag) = dag_state.get(&contact_key) {
                (dag.sender.head(), self.get_observed_heads(dag), dag.epoch)
            } else {
                (None, Vec::new(), 0)
            }
        };

        // Create inner envelope with DAG fields
        let mut inner = InnerEnvelope {
            from: *self.identity.public_id(),
            created_at_ms: now_ms,
            content: content.clone(),
            signature: None,
            prev_self,
            observed_heads,
            epoch,
            flags: if detached { FLAG_DETACHED } else { 0 },
        };

        // Compute content_id before signing (we need it for DAG tracking)
        let content_id = inner.content_id();

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
        let contact_id = self.storage.get_contact_id(to)?;
        self.storage
            .store_sent_message(contact_id, outer_message_id, &content)?;

        // Update DAG tracking after successful storage
        // Skip tracking for detached messages - they're not part of the chain
        if !detached {
            let mut dag_state = self.dag_state.lock().unwrap();
            let dag = dag_state.entry(contact_key).or_insert_with(ConversationDag::new);
            dag.sender.on_send(content_id, prev_self);
        }

        // Only submit to transport after successful local storage
        self.transport.submit_message(outer).await?;

        debug!("Message sent to contact (MIK-only encryption, content_id: {:?})", content_id);
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
    /// The recipient binding is verified both explicitly (routing key check) and
    /// cryptographically (sealed box ECDH binds to recipient).
    pub async fn process_message(
        &self,
        outer: &OuterEnvelope,
    ) -> Result<ReceivedMessage, ClientError> {
        // Defense in depth: verify routing key matches our identity before decryption.
        // This catches misrouted messages early without wasting crypto operations.
        // The cryptographic binding (ECDH) is the actual security guarantee.
        if outer.routing_key != self.routing_key() {
            return Err(ClientError::WrongRecipient);
        }

        // Decrypt using MIK (stateless decryption)
        // This also verifies AAD binding (message_id must match)
        let inner = decrypt_with_mik(
            &outer.ephemeral_key,
            &outer.inner_ciphertext,
            &self.private_key(),
            &outer.message_id,
        )
        .map_err(|e| match e {
            EncryptionError::DecryptionFailed => ClientError::DecryptionFailed,
            other => other.into(),
        })?;

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

        // Compute content_id for DAG tracking
        let content_id = inner.content_id();

        // Store received message - fail if storage fails to prevent data loss
        self.storage.store_received_message(
            contact_id,
            outer.message_id,
            &inner.content,
        )?;

        // Update DAG tracking and detect state anomalies
        let contact_key = sender_id.to_bytes();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let (has_gaps, sender_state_reset, local_state_behind) = {
            let mut dag_state = self.dag_state.lock().unwrap();
            let dag = dag_state.entry(contact_key).or_insert_with(ConversationDag::new);

            // Check if peer has advanced their epoch (intentional history clear)
            // If so, reset our tracking to match their new epoch
            let peer_epoch_advanced = inner.epoch > dag.epoch;
            if peer_epoch_advanced {
                // Peer intentionally cleared - advance to their epoch
                dag.advance_to_peer_epoch(inner.epoch);
            }

            // Detect sender state reset:
            // We have history from sender, but they sent prev_self=None without DETACHED flag
            // AND their epoch hasn't advanced (epoch advance = intentional clear, not state loss)
            let sender_reset = dag.has_peer_history()
                && inner.prev_self.is_none()
                && !inner.is_detached()
                && !peer_epoch_advanced;

            // Detect local state behind:
            // Sender's observed_heads contains IDs we don't remember sending
            let local_behind = dag.has_unknown_observed(&inner.observed_heads);

            // Track this message in the receiver
            let gap_result = dag.receiver.on_receive(content_id, inner.prev_self, now_ms);

            let gaps = matches!(gap_result, reme_message::GapResult::Gap { .. });

            // Only update peer heads for complete messages (not orphans)
            // Otherwise we'd advertise orphans in observed_heads, causing sender
            // to think we have their ancestors when we don't
            if let reme_message::GapResult::Complete { resolved_orphans } = gap_result {
                // Update peer_heads for this message
                dag.update_peer_heads(content_id, inner.prev_self);
                // Also update peer_heads for any orphans that were just resolved
                for (orphan_id, orphan_prev_self) in resolved_orphans {
                    dag.update_peer_heads(orphan_id, Some(orphan_prev_self));
                }
            }
            (gaps, sender_reset, local_behind)
        };

        debug!(
            "Message received (content_id: {:?}, has_gaps: {}, sender_reset: {}, local_behind: {})",
            content_id, has_gaps, sender_state_reset, local_state_behind
        );

        Ok(ReceivedMessage {
            message_id: outer.message_id,
            from: inner.from,
            content: inner.content,
            created_at_ms: inner.created_at_ms,
            content_id,
            has_gaps,
            sender_state_reset,
            local_state_behind,
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

    #[tokio::test]
    async fn test_detached_message_has_no_dag_fields() {
        use reme_encryption::decrypt_with_mik;

        let shared_transport = Arc::new(MockTransport::new());

        let alice_identity = Identity::generate();
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, shared_transport.clone(), alice_storage);

        let bob_identity = Identity::generate();
        let bob_private_key = bob_identity.to_bytes();

        alice.add_contact(bob_identity.public_id(), Some("Bob")).unwrap();

        // Send a detached message
        alice
            .send_text_detached(bob_identity.public_id(), "Detached!")
            .await
            .unwrap();

        let messages = shared_transport.take_messages();
        assert_eq!(messages.len(), 1);

        // Decrypt and verify it's detached
        let inner = decrypt_with_mik(
            &messages[0].ephemeral_key,
            &messages[0].inner_ciphertext,
            &bob_private_key,
            &messages[0].message_id,
        )
        .unwrap();

        assert!(inner.is_detached());
        assert!(inner.prev_self.is_none());
        assert!(inner.observed_heads.is_empty());
    }

    #[tokio::test]
    async fn test_linked_messages_have_dag_chain() {
        use reme_encryption::decrypt_with_mik;

        let shared_transport = Arc::new(MockTransport::new());

        let alice_identity = Identity::generate();
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, shared_transport.clone(), alice_storage);

        let bob_identity = Identity::generate();
        let bob_private_key = bob_identity.to_bytes();

        alice.add_contact(bob_identity.public_id(), Some("Bob")).unwrap();

        // Send first linked message
        alice.send_text(bob_identity.public_id(), "First").await.unwrap();

        // Send second linked message
        alice.send_text(bob_identity.public_id(), "Second").await.unwrap();

        let messages = shared_transport.take_messages();
        assert_eq!(messages.len(), 2);

        // Decrypt both
        let inner1 = decrypt_with_mik(
            &messages[0].ephemeral_key,
            &messages[0].inner_ciphertext,
            &bob_private_key,
            &messages[0].message_id,
        )
        .unwrap();

        let inner2 = decrypt_with_mik(
            &messages[1].ephemeral_key,
            &messages[1].inner_ciphertext,
            &bob_private_key,
            &messages[1].message_id,
        )
        .unwrap();

        // First message has no prev_self (but may have observed_heads if we received from Bob)
        assert!(inner1.prev_self.is_none());

        // Second message should link to first
        assert!(inner2.prev_self.is_some());
        assert_eq!(inner2.prev_self.unwrap(), inner1.content_id());
    }

    #[tokio::test]
    async fn test_epoch_management() {
        let shared_transport = Arc::new(MockTransport::new());

        let alice_identity = Identity::generate();
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, shared_transport.clone(), alice_storage);

        let bob_identity = Identity::generate();

        alice.add_contact(bob_identity.public_id(), Some("Bob")).unwrap();

        // Initial epoch is 0
        assert_eq!(alice.get_conversation_epoch(bob_identity.public_id()), 0);

        // Send a message to establish state
        alice.send_text(bob_identity.public_id(), "Hello").await.unwrap();

        // Clear conversation DAG
        let new_epoch = alice.clear_conversation_dag(bob_identity.public_id());
        assert_eq!(new_epoch, 1);
        assert_eq!(alice.get_conversation_epoch(bob_identity.public_id()), 1);

        // Clear again
        let newer_epoch = alice.clear_conversation_dag(bob_identity.public_id());
        assert_eq!(newer_epoch, 2);
    }

    #[tokio::test]
    async fn test_detached_doesnt_update_dag_chain() {
        use reme_encryption::decrypt_with_mik;

        let shared_transport = Arc::new(MockTransport::new());

        let alice_identity = Identity::generate();
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, shared_transport.clone(), alice_storage);

        let bob_identity = Identity::generate();
        let bob_private_key = bob_identity.to_bytes();

        alice.add_contact(bob_identity.public_id(), Some("Bob")).unwrap();

        // Send linked message
        alice.send_text(bob_identity.public_id(), "Linked 1").await.unwrap();

        // Send detached message (should NOT update chain)
        alice
            .send_text_detached(bob_identity.public_id(), "Detached")
            .await
            .unwrap();

        // Send another linked message (should link to "Linked 1", not "Detached")
        alice.send_text(bob_identity.public_id(), "Linked 2").await.unwrap();

        let messages = shared_transport.take_messages();
        assert_eq!(messages.len(), 3);

        let inner1 = decrypt_with_mik(
            &messages[0].ephemeral_key,
            &messages[0].inner_ciphertext,
            &bob_private_key,
            &messages[0].message_id,
        )
        .unwrap();

        let inner3 = decrypt_with_mik(
            &messages[2].ephemeral_key,
            &messages[2].inner_ciphertext,
            &bob_private_key,
            &messages[2].message_id,
        )
        .unwrap();

        // Third message (Linked 2) should link to first (Linked 1), skipping detached
        assert_eq!(inner3.prev_self.unwrap(), inner1.content_id());
    }

    #[tokio::test]
    async fn test_sender_state_reset_detection() {
        // Scenario: Alice sends messages to Bob, then Alice loses state and sends
        // a new message with prev_self=None (but not flagged as detached).
        // Bob should detect this as a sender state reset.
        use reme_encryption::encrypt_to_mik;
        use reme_message::{InnerEnvelope, TextContent};

        let shared_transport = Arc::new(MockTransport::new());

        let alice_identity = Identity::generate();
        let alice_private_key = alice_identity.to_bytes(); // Capture before move
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, shared_transport.clone(), alice_storage);

        let bob_identity = Identity::generate();
        let bob_storage = Storage::in_memory().unwrap();
        let bob = Client::new(bob_identity, shared_transport.clone(), bob_storage);

        // Alice adds Bob, Bob adds Alice
        alice.add_contact(bob.public_id(), Some("Bob")).unwrap();
        bob.add_contact(alice.public_id(), Some("Alice")).unwrap();

        // Alice sends first message (establishes history)
        alice.send_text(bob.public_id(), "Hello Bob!").await.unwrap();
        let messages = shared_transport.take_messages();
        let received1 = bob.process_message(&messages[0]).await.unwrap();

        // First message should not trigger state reset detection
        assert!(!received1.sender_state_reset);
        assert!(!received1.local_state_behind);

        // Alice sends second message (with valid prev_self chain)
        alice.send_text(bob.public_id(), "How are you?").await.unwrap();
        let messages = shared_transport.take_messages();
        let received2 = bob.process_message(&messages[0]).await.unwrap();

        // Second message should not trigger state reset
        assert!(!received2.sender_state_reset);
        assert!(!received2.local_state_behind);

        // Now simulate Alice losing state: create a message with prev_self=None
        // but WITHOUT the DETACHED flag (signaling unintentional state loss)
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let message_id = MessageID::new();
        let mut inner = InnerEnvelope {
            from: *alice.public_id(),
            created_at_ms: now_ms,
            content: Content::Text(TextContent {
                body: "I lost my state!".to_string(),
            }),
            signature: None,
            prev_self: None,           // No previous message (state lost)
            observed_heads: Vec::new(),
            epoch: 0,                  // Fresh epoch
            flags: 0,                  // NOT detached - this indicates state loss
        };

        // Sign the message
        let signable = inner.signable_bytes(&message_id);
        inner.signature = Some(InnerEnvelope::sign(&signable, &alice_private_key));

        // Encrypt and create outer envelope
        let bob_routing_key = bob.public_id().routing_key();
        let (ephemeral_key, ciphertext) =
            encrypt_to_mik(&inner, bob.public_id(), &message_id).unwrap();
        let outer = OuterEnvelope {
            version: reme_message::CURRENT_VERSION,
            routing_key: bob_routing_key,
            timestamp_hours: reme_message::now_hours(),
            ttl_hours: None,
            message_id,
            ephemeral_key,
            inner_ciphertext: ciphertext,
        };

        // Bob processes this message
        let received3 = bob.process_message(&outer).await.unwrap();

        // Bob should detect sender state reset!
        // We had history from Alice (received1, received2), but she sent prev_self=None
        // without the DETACHED flag
        assert!(
            received3.sender_state_reset,
            "Bob should detect that Alice lost her state"
        );
        assert!(!received3.local_state_behind);
    }

    #[tokio::test]
    async fn test_detached_message_not_detected_as_state_reset() {
        // Scenario: Alice sends a detached message (with FLAG_DETACHED set).
        // Bob should NOT detect this as a state reset.
        use reme_encryption::encrypt_to_mik;
        use reme_message::{InnerEnvelope, TextContent, FLAG_DETACHED};

        let shared_transport = Arc::new(MockTransport::new());

        let alice_identity = Identity::generate();
        let alice_private_key = alice_identity.to_bytes(); // Capture before move
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, shared_transport.clone(), alice_storage);

        let bob_identity = Identity::generate();
        let bob_storage = Storage::in_memory().unwrap();
        let bob = Client::new(bob_identity, shared_transport.clone(), bob_storage);

        // Alice adds Bob, Bob adds Alice
        alice.add_contact(bob.public_id(), Some("Bob")).unwrap();
        bob.add_contact(alice.public_id(), Some("Alice")).unwrap();

        // Alice sends first message (establishes history)
        alice.send_text(bob.public_id(), "Hello Bob!").await.unwrap();
        let messages = shared_transport.take_messages();
        bob.process_message(&messages[0]).await.unwrap();

        // Now Alice sends a detached message (intentionally, e.g., via LoRa)
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let message_id = MessageID::new();
        let mut inner = InnerEnvelope {
            from: *alice.public_id(),
            created_at_ms: now_ms,
            content: Content::Text(TextContent {
                body: "Detached via LoRa".to_string(),
            }),
            signature: None,
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: FLAG_DETACHED,  // Intentionally detached!
        };

        // Sign the message
        let signable = inner.signable_bytes(&message_id);
        inner.signature = Some(InnerEnvelope::sign(&signable, &alice_private_key));

        // Encrypt and create outer envelope
        let bob_routing_key = bob.public_id().routing_key();
        let (ephemeral_key, ciphertext) =
            encrypt_to_mik(&inner, bob.public_id(), &message_id).unwrap();
        let outer = OuterEnvelope {
            version: reme_message::CURRENT_VERSION,
            routing_key: bob_routing_key,
            timestamp_hours: reme_message::now_hours(),
            ttl_hours: None,
            message_id,
            ephemeral_key,
            inner_ciphertext: ciphertext,
        };

        // Bob processes this detached message
        let received = bob.process_message(&outer).await.unwrap();

        // Bob should NOT detect state reset (it's intentionally detached)
        assert!(
            !received.sender_state_reset,
            "Detached messages should not trigger state reset detection"
        );
        assert!(!received.local_state_behind);
    }

    #[tokio::test]
    async fn test_local_state_behind_detection() {
        // Scenario: Bob sends a message to Alice with observed_heads containing
        // content IDs that Alice doesn't recognize (e.g., Alice lost some state).
        // Alice should detect that she's behind.
        use reme_encryption::encrypt_to_mik;
        use reme_message::{ContentId, InnerEnvelope, TextContent};

        let shared_transport = Arc::new(MockTransport::new());

        let alice_identity = Identity::generate();
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, shared_transport.clone(), alice_storage);

        let bob_identity = Identity::generate();
        let bob_private_key = bob_identity.to_bytes(); // Capture before move
        let bob_storage = Storage::in_memory().unwrap();
        let bob = Client::new(bob_identity, shared_transport.clone(), bob_storage);

        // Alice adds Bob, Bob adds Alice
        alice.add_contact(bob.public_id(), Some("Bob")).unwrap();
        bob.add_contact(alice.public_id(), Some("Alice")).unwrap();

        // Alice sends a message (this will be tracked in her DAG)
        alice.send_text(bob.public_id(), "Hello!").await.unwrap();
        let messages = shared_transport.take_messages();
        bob.process_message(&messages[0]).await.unwrap();

        // Now Bob sends a message with observed_heads containing an unknown content ID.
        // This simulates Bob having received messages from Alice that Alice's
        // current state doesn't know about (perhaps Alice restored from old backup).
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let message_id = MessageID::new();

        // Create a fake observed_head that Alice won't recognize
        let unknown_content_id: ContentId = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];

        let mut inner = InnerEnvelope {
            from: *bob.public_id(),
            created_at_ms: now_ms,
            content: Content::Text(TextContent {
                body: "I saw your messages!".to_string(),
            }),
            signature: None,
            prev_self: None,  // Bob's first message
            observed_heads: vec![unknown_content_id],  // Claims to have seen this from Alice
            epoch: 0,
            flags: 0,
        };

        // Sign with Bob's key
        let signable = inner.signable_bytes(&message_id);
        inner.signature = Some(InnerEnvelope::sign(&signable, &bob_private_key));

        // Encrypt for Alice
        let alice_routing_key = alice.public_id().routing_key();
        let (ephemeral_key, ciphertext) =
            encrypt_to_mik(&inner, alice.public_id(), &message_id).unwrap();
        let outer = OuterEnvelope {
            version: reme_message::CURRENT_VERSION,
            routing_key: alice_routing_key,
            timestamp_hours: reme_message::now_hours(),
            ttl_hours: None,
            message_id,
            ephemeral_key,
            inner_ciphertext: ciphertext,
        };

        // Alice processes this message
        let received = alice.process_message(&outer).await.unwrap();

        // Alice should detect that she's behind (Bob references unknown content_id)
        assert!(!received.sender_state_reset);
        assert!(
            received.local_state_behind,
            "Alice should detect she's missing messages Bob claims to have seen"
        );
    }
}
