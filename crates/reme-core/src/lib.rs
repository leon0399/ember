//! reme-core: Client business logic for Resilient Messenger
//!
//! This crate provides the high-level client API for:
//! - Identity management
//! - MIK-only stateless encryption (Session V1-style)
//! - Sending and receiving encrypted messages
//! - Contact management
//! - Resilient delivery via outbox with retry policies

use reme_encryption::{decrypt_with_mik, encrypt_to_mik, EncryptionError};
use reme_identity::{Identity, PublicID};
use reme_message::{
    Content, ContentId, ConversationDag, DeviceID, InnerEnvelope, MessageID, OuterEnvelope,
    ReceiptContent, ReceiptKind, RoutingKey, TextContent, TombstoneEnvelope, TombstoneStatus,
    CURRENT_VERSION, FLAG_DETACHED,
};
use reme_outbox::{
    AttemptError, AttemptResult, ClientOutbox, DeliveryState, OutboxConfig, OutboxEntryId,
    PendingMessage, TieredDeliveryPhase, TransportRetryPolicy,
};
use reme_storage::{Storage, StorageError};
use reme_transport::{
    DeliveryResult, TargetId, TieredDeliveryConfig, Transport, TransportCoordinator, TransportError,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptionError),

    #[error("Outbox error: {0}")]
    Outbox(StorageError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Contact not found")]
    ContactNotFound,

    #[error("Outbox entry not found")]
    OutboxEntryNotFound,

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
/// - Resilient delivery via outbox with configurable retry policies
///
/// With MIK-only encryption, each message includes an ephemeral key for
/// stateless ECDH. No session state is maintained between messages.
///
/// The outbox provides:
/// - Persistent queue of pending messages
/// - Per-transport retry scheduling
/// - DAG-based delivery confirmation
/// - Gap detection triggers automatic retry
///
/// ## Tiered Delivery (with TransportCoordinator)
///
/// When using `Client<TransportCoordinator>`, additional methods are available
/// for tiered delivery with quorum semantics:
/// - `send_text_tiered()` - Send through P2P → Internet → Radio tiers
/// - `process_urgent_retries()` - Background task for urgent phase retries
/// - `process_maintenance()` - Background task for maintenance refreshes
pub struct Client<T: Transport> {
    identity: Identity,
    transport: Arc<T>,
    storage: Arc<Storage>,
    /// Device ID for tombstone sequence management (unique per device)
    device_id: DeviceID,
    /// Monotonically increasing tombstone sequence counter
    tombstone_sequence: AtomicU64,
    /// DAG state per contact (keyed by PublicID bytes)
    /// Tracks message ordering for gap detection
    dag_state: Mutex<HashMap<[u8; 32], ConversationDag>>,
    /// Client outbox for resilient delivery tracking
    outbox: ClientOutbox<Arc<Storage>>,
    /// Configuration for tiered delivery (when using TransportCoordinator)
    tiered_config: TieredDeliveryConfig,
}

/// Prepared message ready for delivery.
///
/// This struct contains everything needed to send a message via any transport
/// mechanism. The message has been encrypted and stored locally.
struct PreparedMessage {
    /// The outer envelope ready for transmission
    outer: OuterEnvelope,
    /// Content ID for DAG tracking
    content_id: ContentId,
    /// Message/outbox entry ID (unified identity)
    ///
    /// This is both the wire message ID and the outbox entry key.
    entry_id: OutboxEntryId,
}

impl<T: Transport> Client<T> {
    /// Create a new client with the given identity, transport, and storage
    ///
    /// Generates a random device ID for tombstone sequence management.
    /// Uses default outbox configuration.
    pub fn new(identity: Identity, transport: Arc<T>, storage: Storage) -> Self {
        Self::with_config(identity, transport, storage, OutboxConfig::default())
    }

    /// Create a new client with custom outbox configuration.
    pub fn with_config(
        identity: Identity,
        transport: Arc<T>,
        storage: Storage,
        outbox_config: OutboxConfig,
    ) -> Self {
        Self::with_full_config(
            identity,
            transport,
            storage,
            outbox_config,
            TieredDeliveryConfig::default(),
        )
    }

    /// Create a new client with custom outbox and tiered delivery configuration.
    pub fn with_full_config(
        identity: Identity,
        transport: Arc<T>,
        storage: Storage,
        outbox_config: OutboxConfig,
        tiered_config: TieredDeliveryConfig,
    ) -> Self {
        // Generate random device ID
        let mut device_id = [0u8; 16];
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(&mut device_id);

        // Wrap storage in Arc for shared access between Client and ClientOutbox
        let storage = Arc::new(storage);

        // Create outbox with shared storage reference
        let outbox = ClientOutbox::new(Arc::clone(&storage), outbox_config);

        Self {
            identity,
            transport,
            storage,
            device_id,
            tombstone_sequence: AtomicU64::new(1), // Start at 1
            dag_state: Mutex::new(HashMap::new()),
            outbox,
            tiered_config,
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
        // Wrap storage in Arc for shared access between Client and ClientOutbox
        let storage = Arc::new(storage);

        // Create outbox with default config and shared storage
        let outbox = ClientOutbox::new(Arc::clone(&storage), OutboxConfig::default());

        Self {
            identity,
            transport,
            storage,
            device_id,
            tombstone_sequence: AtomicU64::new(initial_sequence),
            dag_state: Mutex::new(HashMap::new()),
            outbox,
            tiered_config: TieredDeliveryConfig::default(),
        }
    }

    /// Get the current tiered delivery configuration.
    pub fn tiered_config(&self) -> &TieredDeliveryConfig {
        &self.tiered_config
    }

    /// Update the tiered delivery configuration.
    pub fn set_tiered_config(&mut self, config: TieredDeliveryConfig) {
        self.tiered_config = config;
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

    /// Prepare a message for delivery (common logic for all send methods).
    ///
    /// This method handles:
    /// - Message ID generation
    /// - DAG field extraction
    /// - Inner envelope creation and signing
    /// - Encryption to recipient's MIK
    /// - Outer envelope creation
    /// - Local storage
    /// - DAG state updates
    /// - Outbox enqueueing
    ///
    /// After calling this, use the returned `PreparedMessage` with either
    /// legacy single-target delivery or tiered delivery.
    fn prepare_message(
        &self,
        to: &PublicID,
        content: Content,
        detached: bool,
    ) -> Result<PreparedMessage, ClientError> {
        // Generate message ID
        let outer_message_id = MessageID::new();
        let routing_key = to.routing_key();

        // Get precise timestamp
        let now = now_ms();

        // Get DAG fields from conversation state
        let contact_key = to.to_bytes();
        let (prev_self, observed_heads, epoch) = {
            let dag_state = self.dag_state.lock().unwrap();
            if detached {
                let epoch = dag_state.get(&contact_key).map(|d| d.epoch).unwrap_or(0);
                (None, Vec::new(), epoch)
            } else if let Some(dag) = dag_state.get(&contact_key) {
                (dag.sender.head(), self.get_observed_heads(dag), dag.epoch)
            } else {
                (None, Vec::new(), 0)
            }
        };

        // Create inner envelope with DAG fields
        let inner = InnerEnvelope {
            from: *self.identity.public_id(),
            created_at_ms: now,
            content: content.clone(),
            prev_self,
            observed_heads,
            epoch,
            flags: if detached { FLAG_DETACHED } else { 0 },
        };

        // Compute content_id
        let content_id = inner.content_id();

        // Encrypt to recipient's MIK (signing happens inside encrypt_to_mik)
        let (ephemeral_key, ciphertext) =
            encrypt_to_mik(&inner, to, &outer_message_id, &self.private_key())?;

        // Create outer envelope
        // TODO: Add outer signature support after encrypt_to_mik is updated
        // to return commitment_pub and outer_signature for anonymous verification.
        let outer = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: reme_message::now_hours(),
            ttl_hours: Some(7 * 24), // 7 days default TTL
            message_id: outer_message_id,
            ephemeral_key,
            commitment_pub: None,     // Will be populated after VXEdDSA integration
            outer_signature: None,    // Will be populated after VXEdDSA integration
            inner_ciphertext: ciphertext,
        };

        // Store locally first
        let contact_id = self.storage.get_contact_id(to)?;
        self.storage
            .store_sent_message(contact_id, outer_message_id, &content)?;

        // Update DAG tracking (skip for detached)
        if !detached {
            let mut dag_state = self.dag_state.lock().unwrap();
            let dag = dag_state.entry(contact_key).or_insert_with(ConversationDag::new);
            dag.sender.on_send(content_id, prev_self);
        }

        // Serialize envelopes for outbox storage
        let envelope_bytes = bincode::encode_to_vec(&outer, bincode::config::standard())
            .map_err(|e| ClientError::Serialization(format!("envelope: {}", e)))?;
        let inner_bytes = bincode::encode_to_vec(&inner, bincode::config::standard())
            .map_err(|e| ClientError::Serialization(format!("inner: {}", e)))?;

        // Enqueue to outbox
        let entry_id = self
            .outbox
            .enqueue(to, content_id, outer_message_id, &envelope_bytes, &inner_bytes, None)
            .map_err(ClientError::Outbox)?;

        Ok(PreparedMessage {
            outer,
            content_id,
            entry_id,
        })
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
        // Prepare message (common logic)
        let prepared = self.prepare_message(to, content, detached)?;

        // Attempt delivery via current transport
        let transport_id = self.transport_id();
        let attempt_result = match self.transport.submit_message(prepared.outer).await {
            Ok(()) => AttemptResult::Sent,
            Err(e) => AttemptResult::Failed(transport_error_to_attempt_error(&e)),
        };

        // Record the attempt (regardless of success/failure)
        self.outbox
            .record_attempt(prepared.entry_id, &transport_id, attempt_result.clone())
            .map_err(ClientError::Outbox)?;

        // Log result
        match &attempt_result {
            AttemptResult::Sent => {
                debug!(
                    "Message sent to contact (MIK-only encryption, content_id: {:?}, outbox_id: {:?})",
                    prepared.content_id, prepared.entry_id
                );
            }
            AttemptResult::Failed(e) => {
                debug!(
                    "Message delivery failed, queued for retry (content_id: {:?}, outbox_id: {:?}, error: {})",
                    prepared.content_id, prepared.entry_id, e
                );
            }
        }

        Ok(prepared.entry_id)
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
        // This also verifies:
        // - AAD binding (message_id must match)
        // - Sender signature (sign-all-bytes - signature verified during decryption)
        let inner = decrypt_with_mik(
            &outer.ephemeral_key,
            &outer.inner_ciphertext,
            &self.private_key(),
            &outer.message_id,
        )
        .map_err(|e| match e {
            EncryptionError::DecryptionFailed => ClientError::DecryptionFailed,
            EncryptionError::InvalidSenderSignature => ClientError::InvalidSenderSignature,
            other => other.into(),
        })?;

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

        // Check for delivery confirmations in the peer's observed_heads
        // This is the DAG-based implicit ACK mechanism
        if !inner.observed_heads.is_empty() {
            match self
                .outbox
                .on_peer_message_received(&sender_id, &inner.observed_heads, content_id)
            {
                Ok(confirmed) => {
                    if !confirmed.is_empty() {
                        debug!(
                            "DAG confirmation: {} messages confirmed by peer's observed_heads",
                            confirmed.len()
                        );
                    }
                }
                Err(e) => {
                    // Log at warn level - confirmation failures may indicate storage issues
                    // that could prevent proper message acknowledgment
                    warn!("Outbox confirmation check failed: {} - message may be re-sent", e);
                }
            }

            // If gap detected and retry triggers are enabled, schedule retry for unacked messages
            if has_gaps {
                match self.outbox.find_unacked_messages(&sender_id, &inner.observed_heads) {
                    Ok(unacked) if !unacked.is_empty() => {
                        debug!(
                            "Gap detected: scheduling retry for {} unacknowledged messages",
                            unacked.len()
                        );
                        if let Err(e) = self.outbox.schedule_immediate_retry(&unacked) {
                            warn!(
                                "Failed to schedule immediate retry for {} messages: {}",
                                unacked.len(), e
                            );
                        }
                    }
                    Ok(_) => {} // No unacked messages
                    Err(e) => {
                        warn!("Failed to find unacked messages for gap recovery: {}", e);
                    }
                }
            }
        }

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

    // ========================================
    // Outbox Management
    // ========================================

    /// Set retry policy for a transport type.
    ///
    /// # Arguments
    /// * `transport_prefix` - Transport type prefix (e.g., "http", "lora", "ble", "p2p")
    /// * `policy` - Retry policy for this transport type
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Configure LoRa with longer retry intervals
    /// client.set_transport_policy("lora", TransportRetryPolicy::lora());
    ///
    /// // Configure BLE for device discovery scenarios
    /// client.set_transport_policy("ble", TransportRetryPolicy::ble());
    /// ```
    pub fn set_transport_policy(&mut self, transport_prefix: &str, policy: TransportRetryPolicy) {
        self.outbox.set_transport_policy(transport_prefix, policy);
    }

    /// Get the transport ID for the current transport.
    ///
    /// Format: `"{type}:{identifier}"` based on transport configuration.
    /// Currently defaults to "http:default" - will be enhanced when
    /// multi-transport support is added.
    fn transport_id(&self) -> String {
        // TODO: Extract transport identifier from transport instance
        // For now, use a default identifier
        "http:default".to_string()
    }

    /// Attempt to deliver a pending message via the current transport.
    ///
    /// This is the core delivery method that:
    /// 1. Submits the message to the transport
    /// 2. Records the attempt result in the outbox
    ///
    /// # Arguments
    /// * `entry_id` - Outbox entry ID to deliver
    ///
    /// # Returns
    /// The attempt result (Sent or Failed with error details)
    pub async fn attempt_delivery(&self, entry_id: OutboxEntryId) -> Result<AttemptResult, ClientError> {
        let pending = self.outbox.get_by_id(entry_id)
            .map_err(ClientError::Outbox)?
            .ok_or(ClientError::OutboxEntryNotFound)?;

        let transport_id = self.transport_id();

        // Deserialize the outer envelope
        let outer: OuterEnvelope = bincode::decode_from_slice(
            &pending.envelope_bytes,
            bincode::config::standard(),
        )
        .map(|(envelope, _)| envelope)
        .map_err(|e| ClientError::Outbox(StorageError::Serialization(e.to_string())))?;

        // Attempt delivery
        let result = match self.transport.submit_message(outer).await {
            Ok(()) => AttemptResult::Sent,
            Err(e) => AttemptResult::Failed(transport_error_to_attempt_error(&e)),
        };

        // Record the attempt
        self.outbox
            .record_attempt(entry_id, &transport_id, result.clone())
            .map_err(ClientError::Outbox)?;

        Ok(result)
    }

    /// Retry delivery via a specific transport.
    ///
    /// Use this for user-initiated transport override (e.g., "send via LoRa").
    /// This schedules the message for immediate retry.
    ///
    /// # Arguments
    /// * `entry_id` - Outbox entry ID to retry
    pub fn schedule_retry(&self, entry_id: OutboxEntryId) -> Result<(), ClientError> {
        self.outbox
            .schedule_immediate_retry(&[entry_id])
            .map_err(ClientError::Outbox)
    }

    /// Get messages ready for retry.
    ///
    /// Returns pending messages whose retry time has passed.
    pub fn get_ready_for_retry(&self) -> Result<Vec<PendingMessage>, ClientError> {
        self.outbox.get_ready_for_retry().map_err(ClientError::Outbox)
    }

    /// Get all pending (unconfirmed) messages.
    pub fn get_pending_messages(&self) -> Result<Vec<PendingMessage>, ClientError> {
        self.outbox.get_all_pending().map_err(ClientError::Outbox)
    }

    /// Get pending messages for a specific recipient.
    pub fn get_pending_for(&self, recipient: &PublicID) -> Result<Vec<PendingMessage>, ClientError> {
        self.outbox
            .get_pending_for(recipient)
            .map_err(ClientError::Outbox)
    }

    /// Get delivery state for a message.
    pub fn get_delivery_state(&self, entry_id: OutboxEntryId) -> Result<Option<DeliveryState>, ClientError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let timeout_ms = self.outbox.config().attempt_timeout_ms;

        self.outbox
            .get_by_id(entry_id)
            .map(|opt| opt.map(|msg| msg.state(now_ms, timeout_ms)))
            .map_err(ClientError::Outbox)
    }

    /// Process outbox tick: retry due messages and check expirations.
    ///
    /// Call this periodically (e.g., every 30 seconds) to process
    /// pending retries and clean up expired messages.
    ///
    /// # Returns
    /// Tuple of (messages_retried, messages_expired)
    pub async fn outbox_tick(&self) -> Result<(usize, u64), ClientError> {
        // Check for expired messages first
        let expired = self.outbox.check_expirations().map_err(ClientError::Outbox)?;

        // Get messages due for retry
        let due = self.outbox.get_ready_for_retry().map_err(ClientError::Outbox)?;
        let mut retried = 0;

        for pending in due {
            // Skip messages in confirmed/expired state
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let state = pending.state(now_ms, self.outbox.config().attempt_timeout_ms);

            match state {
                DeliveryState::Pending | DeliveryState::AwaitingRetry => {
                    // Attempt delivery
                    match self.attempt_delivery(pending.id).await {
                        Ok(_) => {
                            retried += 1;
                        }
                        Err(e) => {
                            // Log error but continue processing other messages
                            warn!(entry_id = ?pending.id, error = %e, "Outbox tick: delivery attempt failed");
                        }
                    }
                }
                DeliveryState::InFlight => {
                    // Already in flight, skip
                }
                DeliveryState::Confirmed | DeliveryState::Expired => {
                    // Already done, skip
                }
            }
        }

        Ok((retried, expired))
    }

    /// Clean up old confirmed/expired outbox entries.
    pub fn outbox_cleanup(&self) -> Result<u64, ClientError> {
        self.outbox.cleanup().map_err(ClientError::Outbox)
    }
}

/// Convert transport error to attempt error.
fn transport_error_to_attempt_error(e: &TransportError) -> AttemptError {
    match e {
        TransportError::Network(msg) => AttemptError::network_transient(msg.clone()),
        TransportError::Serialization(msg) => AttemptError::Encoding {
            message: msg.clone(),
        },
        TransportError::AuthenticationFailed => AttemptError::Rejected {
            message: "authentication failed".to_string(),
            is_transient: false,
        },
        TransportError::NotFound => AttemptError::Rejected {
            message: "not found".to_string(),
            is_transient: false,
        },
        TransportError::ServerError(msg) => AttemptError::rejected_transient(msg.clone()),
        TransportError::ChannelClosed => AttemptError::Unavailable {
            message: "channel closed".to_string(),
        },
        TransportError::TlsConfig(msg) => AttemptError::Rejected {
            message: format!("TLS configuration error: {}", msg),
            is_transient: false,
        },
        TransportError::CertificatePinMismatch {
            hostname,
            expected,
            actual,
        } => AttemptError::Rejected {
            message: format!(
                "Certificate pin mismatch for {}: expected {}, got {}",
                hostname, expected, actual
            ),
            is_transient: false,
        },
        TransportError::Timeout => AttemptError::Rejected {
            message: "request timed out".to_string(),
            is_transient: true,
        },
    }
}

/// Get current time in milliseconds since epoch.
///
/// # Panics
/// Panics if system time is before Unix epoch, which indicates a serious
/// system configuration error that would break all time-based operations.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("System time is before Unix epoch - check system clock configuration")
        .as_millis() as u64
}

// ========================================================================
// TIERED DELIVERY IMPLEMENTATION (TransportCoordinator only)
// ========================================================================

/// Specialized implementation for tiered delivery with quorum semantics.
///
/// These methods are only available when using `TransportCoordinator` as the
/// transport, enabling multi-tier delivery (P2P → Internet → Radio) with
/// configurable quorum requirements.
impl Client<TransportCoordinator> {
    /// Send a text message using tiered delivery with quorum semantics.
    ///
    /// This method attempts delivery through multiple tiers:
    /// 1. **P2P (Ephemeral)**: Race all ephemeral targets, exit on any success
    /// 2. **Internet (Stable)**: Broadcast to all stable targets, require quorum
    /// 3. **Radio**: Best effort delivery (future)
    ///
    /// The message is tracked in the outbox with the tiered delivery state machine:
    /// - **Urgent phase**: Aggressive retry until quorum reached
    /// - **Distributed phase**: Periodic maintenance refresh
    /// - **Confirmed phase**: Message acknowledged by recipient
    pub async fn send_text_tiered(
        &self,
        to: &PublicID,
        text: &str,
    ) -> Result<(MessageID, TieredDeliveryPhase), ClientError> {
        let content = Content::Text(TextContent {
            body: text.to_string(),
        });
        self.send_message_tiered_internal(to, content, false).await
    }

    /// Send a detached text message using tiered delivery.
    ///
    /// Detached messages have no DAG linkage, suitable for constrained transports.
    pub async fn send_text_detached_tiered(
        &self,
        to: &PublicID,
        text: &str,
    ) -> Result<(MessageID, TieredDeliveryPhase), ClientError> {
        let content = Content::Text(TextContent {
            body: text.to_string(),
        });
        self.send_message_tiered_internal(to, content, true).await
    }

    /// Send a message with tiered delivery and record results in outbox.
    async fn send_message_tiered_internal(
        &self,
        to: &PublicID,
        content: Content,
        detached: bool,
    ) -> Result<(MessageID, TieredDeliveryPhase), ClientError> {
        // Prepare message (common logic)
        let prepared = self.prepare_message(to, content, detached)?;

        // Attempt tiered delivery
        let result = self
            .transport
            .submit_tiered(&prepared.outer, &self.tiered_config)
            .await;

        // Record result in outbox and get new phase
        let phase = self
            .outbox
            .record_tiered_delivery_result(prepared.entry_id, &result, &self.tiered_config)
            .map_err(ClientError::Outbox)?;

        // Log result based on phase
        match &phase {
            TieredDeliveryPhase::Urgent => {
                warn!(
                    message_id = ?prepared.entry_id,
                    content_id = ?prepared.content_id,
                    success_count = result.success_count(),
                    "Message quorum not reached, will retry"
                );
            }
            TieredDeliveryPhase::Distributed { confidence, .. } => {
                if confidence.is_direct() {
                    info!(
                        message_id = ?prepared.entry_id,
                        "Message delivered directly via P2P"
                    );
                } else {
                    debug!(
                        message_id = ?prepared.entry_id,
                        success_count = result.success_count(),
                        "Message distributed, awaiting ACK"
                    );
                }
            }
            TieredDeliveryPhase::Confirmed { .. } => {
                // Shouldn't happen on initial send
            }
        }

        Ok((prepared.entry_id, phase))
    }

    /// Process urgent retries (Phase 1 messages).
    ///
    /// This background task should be called periodically to retry messages
    /// that haven't yet reached quorum. Uses the full delivery pipeline:
    /// P2P first (recipient may be online now), then Internet tier.
    ///
    /// # Returns
    /// Number of messages retried and their new phases.
    pub async fn process_urgent_retries(&self) -> Result<Vec<(OutboxEntryId, TieredDeliveryPhase)>, ClientError> {
        let due = self.outbox.get_urgent_retry_due().map_err(ClientError::Outbox)?;
        let mut results = Vec::new();

        for pending in due {
            match self.attempt_tiered_delivery(&pending).await {
                Ok(phase) => {
                    results.push((pending.id, phase));
                }
                Err(e) => {
                    warn!(
                        entry_id = ?pending.id,
                        error = %e,
                        "Urgent retry failed"
                    );
                }
            }
        }

        Ok(results)
    }

    /// Process maintenance refreshes (Phase 2 messages).
    ///
    /// This background task should be called periodically to refresh messages
    /// that have reached quorum but haven't been acknowledged. Ensures copies
    /// still exist on target nodes (they may have crashed).
    ///
    /// Uses the full delivery pipeline: P2P first (recipient may be online now),
    /// then refresh ALL Internet tier targets.
    ///
    /// # Returns
    /// Number of messages refreshed.
    pub async fn process_maintenance(&self) -> Result<usize, ClientError> {
        let maintenance_interval_ms = self.tiered_config.maintenance_interval.as_millis() as u64;
        let due = self
            .outbox
            .get_maintenance_due(maintenance_interval_ms)
            .map_err(ClientError::Outbox)?;

        let mut refreshed = 0;

        for pending in due {
            match self.attempt_maintenance_refresh(&pending).await {
                Ok(_) => {
                    refreshed += 1;
                }
                Err(e) => {
                    warn!(
                        entry_id = ?pending.id,
                        error = %e,
                        "Maintenance refresh failed"
                    );
                }
            }
        }

        Ok(refreshed)
    }

    /// Attempt tiered delivery for a pending message.
    ///
    /// For urgent retries, this uses selective Internet tier targeting:
    /// only retry failed targets, skip already-successful ones.
    async fn attempt_tiered_delivery(
        &self,
        pending: &PendingMessage,
    ) -> Result<TieredDeliveryPhase, ClientError> {
        // Deserialize the outer envelope
        let outer: OuterEnvelope = bincode::decode_from_slice(
            &pending.envelope_bytes,
            bincode::config::standard(),
        )
        .map(|(envelope, _)| envelope)
        .map_err(|e| ClientError::Serialization(format!("envelope: {}", e)))?;

        // Try Direct tier first - recipient may be online now
        let direct_result = self.transport.try_direct_tier(&outer, &self.tiered_config).await;

        if direct_result.any_success() {
            // Direct delivery! Upgrade to DirectDelivery confidence
            if let Some(target) = direct_result.first_success_target() {
                self.outbox
                    .upgrade_to_direct_delivery(pending.id, &target)
                    .map_err(ClientError::Outbox)?;

                info!(
                    entry_id = ?pending.id,
                    target = %target,
                    "Upgraded to direct delivery via Direct tier"
                );

                return Ok(TieredDeliveryPhase::Distributed {
                    confidence: reme_outbox::DeliveryConfidence::DirectDelivery {
                        target: target.clone(),
                    },
                    reached_at_ms: now_ms(),
                    last_maintenance_ms: None,
                });
            }
        }

        // Get all Quorum tier targets and filter to failed ones
        let all_quorum_targets = self.transport.quorum_target_ids(&self.tiered_config);
        let failed_targets: Vec<TargetId> = pending.failed_targets(all_quorum_targets.iter());

        // Handle edge case: no quorum targets configured
        if all_quorum_targets.is_empty() {
            warn!(
                entry_id = ?pending.id,
                "No quorum targets available, scheduling retry with backoff"
            );
            // Build an empty result to trigger proper retry scheduling
            let empty_result = DeliveryResult {
                quorum_reached: false,
                confidence: reme_transport::DeliveryConfidence::QuorumReached {
                    count: 0,
                    required: 1,
                },
                target_results: Vec::new(),
                completed_tier: None,
            };
            let phase = self
                .outbox
                .record_tiered_delivery_result(pending.id, &empty_result, &self.tiered_config)
                .map_err(ClientError::Outbox)?;
            return Ok(phase);
        }

        // If all targets succeeded, no need to retry Quorum tier
        if failed_targets.is_empty() {
            // Just record that we checked - outbox state unchanged
            return self
                .outbox
                .get_by_id(pending.id)
                .map_err(ClientError::Outbox)?
                .map(|p| p.tiered_phase)
                .ok_or(ClientError::OutboxEntryNotFound);
        }

        // Retry failed Quorum tier targets only
        let quorum_result = self
            .transport
            .try_quorum_tier_selective(&outer, &failed_targets, &self.tiered_config)
            .await;

        // Calculate combined success count before moving results
        let quorum_success_count = quorum_result.success_count();
        let total_success = pending.success_count() as u32 + quorum_success_count;
        let total_targets = self.transport.quorum_target_count(&self.tiered_config);

        // Combine Direct and Quorum results
        let mut all_results = direct_result.results;
        all_results.extend(quorum_result.results);

        let combined_result = DeliveryResult {
            quorum_reached: self.tiered_config.quorum.is_satisfied(total_success, total_targets),
            confidence: reme_transport::DeliveryConfidence::QuorumReached {
                count: total_success,
                required: self.tiered_config.quorum.required_count(total_targets),
            },
            target_results: all_results,
            completed_tier: if quorum_success_count > 0 {
                Some(reme_transport::DeliveryTier::Quorum)
            } else {
                None
            },
        };

        // Record result in outbox
        let phase = self
            .outbox
            .record_tiered_delivery_result(pending.id, &combined_result, &self.tiered_config)
            .map_err(ClientError::Outbox)?;

        Ok(phase)
    }

    /// Attempt maintenance refresh for a distributed message.
    ///
    /// Refreshes ALL Quorum tier targets to ensure copies still exist.
    async fn attempt_maintenance_refresh(&self, pending: &PendingMessage) -> Result<(), ClientError> {
        // Deserialize the outer envelope
        let outer: OuterEnvelope = bincode::decode_from_slice(
            &pending.envelope_bytes,
            bincode::config::standard(),
        )
        .map(|(envelope, _)| envelope)
        .map_err(|e| ClientError::Serialization(format!("envelope: {}", e)))?;

        // Try Direct tier first - recipient may be online now
        let direct_result = self.transport.try_direct_tier(&outer, &self.tiered_config).await;

        if direct_result.any_success() {
            // Upgrade to direct delivery
            if let Some(target) = direct_result.first_success_target() {
                self.outbox
                    .upgrade_to_direct_delivery(pending.id, &target)
                    .map_err(ClientError::Outbox)?;

                info!(
                    entry_id = ?pending.id,
                    target = %target,
                    "Maintenance: upgraded to direct delivery"
                );

                return Ok(());
            }
        }

        // Refresh ALL Quorum tier targets
        let quorum_result = self
            .transport
            .try_quorum_tier_all(&outer, &self.tiered_config)
            .await;

        // Check refresh results and log appropriately
        let success_count = quorum_result.success_count();
        let total_targets = quorum_result.results.len();

        if success_count == 0 && total_targets > 0 {
            // All targets failed - don't record maintenance so we retry sooner
            warn!(
                entry_id = ?pending.id,
                total_targets,
                "Maintenance refresh failed: all {} targets unreachable, will retry sooner",
                total_targets
            );
            // Don't record maintenance - message will be picked up on next tick
            return Ok(());
        }

        if success_count < total_targets as u32 {
            debug!(
                entry_id = ?pending.id,
                success_count,
                total_targets,
                "Maintenance refresh partial: {}/{} targets succeeded",
                success_count, total_targets
            );
        }

        // Record maintenance timestamp (only if at least one target succeeded)
        self.outbox
            .record_maintenance_refresh(pending.id)
            .map_err(ClientError::Outbox)?;

        debug!(
            entry_id = ?pending.id,
            success_count,
            "Maintenance refresh completed"
        );

        Ok(())
    }

    /// Combined outbox tick for tiered delivery.
    ///
    /// Processes:
    /// 1. Expired messages
    /// 2. Urgent retries (Phase 1)
    /// 3. Maintenance refreshes (Phase 2)
    ///
    /// # Returns
    /// Tuple of (urgent_retried, maintenance_refreshed, expired)
    pub async fn tiered_outbox_tick(&self) -> Result<(usize, usize, u64), ClientError> {
        // Check for expired messages first
        let expired = self.outbox.check_expirations().map_err(ClientError::Outbox)?;

        // Process urgent retries
        let urgent_results = self.process_urgent_retries().await?;

        // Process maintenance refreshes
        let maintenance_count = self.process_maintenance().await?;

        Ok((urgent_results.len(), maintenance_count, expired))
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
        let inner = InnerEnvelope {
            from: *alice.public_id(),
            created_at_ms: now_ms,
            content: Content::Text(TextContent {
                body: "I lost my state!".to_string(),
            }),
            prev_self: None,           // No previous message (state lost)
            observed_heads: Vec::new(),
            epoch: 0,                  // Fresh epoch
            flags: 0,                  // NOT detached - this indicates state loss
        };

        // Encrypt and create outer envelope (signing happens inside encrypt_to_mik)
        let bob_routing_key = bob.public_id().routing_key();
        let (ephemeral_key, ciphertext) =
            encrypt_to_mik(&inner, bob.public_id(), &message_id, &alice_private_key).unwrap();
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
        let inner = InnerEnvelope {
            from: *alice.public_id(),
            created_at_ms: now_ms,
            content: Content::Text(TextContent {
                body: "Detached via LoRa".to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: FLAG_DETACHED,  // Intentionally detached!
        };

        // Encrypt and create outer envelope (signing happens inside encrypt_to_mik)
        let bob_routing_key = bob.public_id().routing_key();
        let (ephemeral_key, ciphertext) =
            encrypt_to_mik(&inner, bob.public_id(), &message_id, &alice_private_key).unwrap();
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

        let inner = InnerEnvelope {
            from: *bob.public_id(),
            created_at_ms: now_ms,
            content: Content::Text(TextContent {
                body: "I saw your messages!".to_string(),
            }),
            prev_self: None,  // Bob's first message
            observed_heads: vec![unknown_content_id],  // Claims to have seen this from Alice
            epoch: 0,
            flags: 0,
        };

        // Encrypt for Alice (signing happens inside encrypt_to_mik)
        let alice_routing_key = alice.public_id().routing_key();
        let (ephemeral_key, ciphertext) =
            encrypt_to_mik(&inner, alice.public_id(), &message_id, &bob_private_key).unwrap();
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
