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
    Content, ContentId, ConversationDag, InnerEnvelope, MessageID, OuterEnvelope, ReceiptContent,
    ReceiptKind, RoutingKey, SignedAckTombstone, TextContent, CURRENT_VERSION, FLAG_DETACHED,
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
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
#[non_exhaustive]
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

    #[error("Ack secret not found for message (already tombstoned or never sent)")]
    AckSecretNotFound,

    #[error("Message not intended for this recipient (routing key mismatch)")]
    WrongRecipient,

    #[error("Message decryption failed (wrong recipient, tampered, or corrupted)")]
    DecryptionFailed,

    #[error("Invalid sender signature: message may be forged or tampered")]
    InvalidSenderSignature,

    #[error("Conflicting duplicate message ID: {0:?}")]
    ConflictingDuplicate(MessageID),

    #[error("Lock poisoned")]
    LockPoisoned,
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
    /// Sender likely lost state: we have history from them but they sent `prev_self=None`
    /// (not including intentionally detached messages)
    pub sender_state_reset: bool,
    /// We likely lost state: sender's `observed_heads` contains IDs we don't recognize
    /// This means the peer saw messages from us that we have no record of sending
    pub local_state_behind: bool,
}

/// Result of local message processing (decrypt + store + DAG).
/// Contains the decrypted message for display and an optional tombstone to send.
pub struct ProcessedMessage {
    /// The decrypted message ready for display
    pub received: ReceivedMessage,
    /// Tombstone to fire-and-forget (None for detached messages)
    pub pending_tombstone: Option<SignedAckTombstone>,
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
/// ## Tiered Delivery (with `TransportCoordinator`)
///
/// When using `Client<TransportCoordinator>`, additional methods are available
/// for tiered delivery with quorum semantics:
/// - `send_text_tiered()` - Send through Direct → Quorum → `BestEffort` tiers
/// - `process_urgent_retries()` - Background task for urgent phase retries
/// - `process_maintenance()` - Background task for maintenance refreshes
pub struct Client<T: Transport> {
    identity: Identity,
    transport: Arc<T>,
    storage: Arc<Storage>,
    /// DAG state per contact (keyed by `PublicID` bytes)
    /// Tracks message ordering for gap detection
    dag_state: Mutex<HashMap<[u8; 32], ConversationDag>>,
    /// Client outbox for resilient delivery tracking
    outbox: ClientOutbox<Arc<Storage>>,
    /// Configuration for tiered delivery (when using `TransportCoordinator`)
    tiered_config: TieredDeliveryConfig,
}

/// Prepared message ready for delivery.
///
/// This struct contains everything needed to send a message via any transport
/// mechanism. The message has been encrypted and stored locally.
pub struct PreparedMessage {
    /// The outer envelope ready for transmission
    pub outer: OuterEnvelope,
    /// Content ID for DAG tracking
    pub content_id: ContentId,
    /// Message/outbox entry ID (unified identity)
    ///
    /// This is both the wire message ID and the outbox entry key.
    pub entry_id: OutboxEntryId,
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
        // Wrap storage in Arc for shared access between Client and ClientOutbox
        let storage = Arc::new(storage);

        // Create outbox with shared storage reference
        let outbox = ClientOutbox::new(Arc::clone(&storage), outbox_config);

        // Load persisted DAG state from storage
        let dag_state = match storage.load_all_dag_states() {
            Ok(persisted) => {
                let map: HashMap<_, _> = persisted
                    .into_iter()
                    .map(|(contact_key, (epoch, sender_head, peer_heads))| {
                        let dag = ConversationDag::from_persisted(epoch, sender_head, peer_heads);
                        (contact_key, dag)
                    })
                    .collect();
                if !map.is_empty() {
                    debug!("restored DAG state for {} contacts", map.len());
                }
                Mutex::new(map)
            }
            Err(e) => {
                warn!(
                    "failed to load DAG state from storage: {} — starting fresh",
                    e
                );
                Mutex::new(HashMap::new())
            }
        };

        Self {
            identity,
            transport,
            storage,
            dag_state,
            outbox,
            tiered_config,
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

    /// Get the client's public identity (MIK)
    pub fn public_id(&self) -> &PublicID {
        self.identity.public_id()
    }

    /// Get the routing key for this client's mailbox
    pub fn routing_key(&self) -> RoutingKey {
        self.identity.public_id().routing_key()
    }

    /// Persist DAG state for a contact to storage.
    ///
    /// Best-effort: logs a warning on failure rather than propagating the error,
    /// since DAG persistence is an optimization (avoids false gaps) not a
    /// correctness requirement.
    ///
    /// Callers should extract fields from the DAG while holding the lock,
    /// drop the lock, then call this method to avoid holding the DAG mutex
    /// across `SQLite` I/O.
    fn persist_dag_state(
        &self,
        contact_key: &[u8; 32],
        epoch: u16,
        sender_head: Option<ContentId>,
        peer_heads: &[ContentId],
    ) {
        if let Err(e) = self
            .storage
            .save_dag_state(contact_key, epoch, sender_head, peer_heads)
        {
            warn!("failed to persist DAG state: {}", e);
        }
    }

    /// Get the identity's private key bytes (for decryption)
    fn private_key(&self) -> [u8; 32] {
        self.identity.to_bytes()
    }

    /// Get the latest observed heads from the receiver tracker for a contact.
    ///
    /// Returns the `content_ids` of messages we've received from the peer.
    /// In 1:1 chat, this is typically just the peer's latest message.
    #[allow(clippy::unused_self)] // Method for consistency with other dag accessors
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
            .map(|(id, public_id, name)| Contact {
                id,
                public_id,
                name,
            })
            .collect())
    }

    /// Retrieve messages for a contact, ordered chronologically (oldest first).
    ///
    /// Uses cursor-based pagination. Pass `before_id` from the oldest message's
    /// `StoredMessage::id` to load earlier pages.
    pub fn get_messages(
        &self,
        contact_id: i64,
        limit: u32,
        before_id: Option<i64>,
    ) -> Result<Vec<reme_storage::StoredMessage>, ClientError> {
        Ok(self.storage.get_messages(contact_id, limit, before_id)?)
    }

    /// Get the most recent text message body for each of the given contact IDs.
    pub fn get_last_message_per_contact(
        &self,
        contact_ids: &[i64],
    ) -> Result<std::collections::HashMap<i64, String>, ClientError> {
        Ok(self.storage.get_last_message_per_contact(contact_ids)?)
    }

    // ========================================
    // Conversation History Management
    // ========================================

    /// Clear conversation history with a contact and increment epoch.
    ///
    /// This increments the DAG epoch for this conversation, which:
    /// - Clears all DAG tracking state (sender chain, receiver state, peer head)
    /// - Future messages will start fresh chains
    /// - Messages referencing pre-epoch `content_ids` will be detected as gaps
    ///
    /// Note: This does NOT delete stored messages from local storage.
    /// Use this when both parties agree to clear history.
    pub fn clear_conversation_dag(&self, contact: &PublicID) -> Result<u16, ClientError> {
        let contact_key = contact.to_bytes();
        let (epoch, sender_head, peer_heads) = {
            let mut dag_state = self
                .dag_state
                .lock()
                .map_err(|_| ClientError::LockPoisoned)?;
            let dag = dag_state.entry(contact_key).or_default();
            dag.increment_epoch();
            (dag.epoch, dag.sender.head(), dag.observed_heads())
        };
        self.persist_dag_state(&contact_key, epoch, sender_head, &peer_heads);
        Ok(epoch)
    }

    /// Get the current epoch for a conversation.
    pub fn get_conversation_epoch(&self, contact: &PublicID) -> Result<u16, ClientError> {
        let contact_key = contact.to_bytes();
        let dag_state = self
            .dag_state
            .lock()
            .map_err(|_| ClientError::LockPoisoned)?;
        Ok(dag_state.get(&contact_key).map_or(0, |d| d.epoch))
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
    /// Use this for constrained transports (`LoRa`, BLE) where bandwidth is limited
    /// and DAG overhead should be avoided. Detached messages have no `prev_self`
    /// or `observed_heads`, making them "floating" in the message history.
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
    #[allow(clippy::needless_pass_by_value)] // Content is cloned into envelope, ref wouldn't save alloc
    pub fn prepare_message(
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
            let dag_state = self
                .dag_state
                .lock()
                .map_err(|_| ClientError::LockPoisoned)?;
            if detached {
                let epoch = dag_state.get(&contact_key).map_or(0, |d| d.epoch);
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
        let enc_output = encrypt_to_mik(&inner, to, &outer_message_id, &self.private_key())?;

        // Create outer envelope
        let outer = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: reme_message::now_hours(),
            ttl_hours: Some(7 * 24), // 7 days default TTL
            message_id: outer_message_id,
            ephemeral_key: enc_output.ephemeral_public,
            ack_hash: enc_output.ack_hash,
            inner_ciphertext: enc_output.ciphertext,
        };

        // Store ack_secret for sender-side tombstone (retraction capability)
        self.storage
            .store_pending_ack(outer_message_id, enc_output.ack_secret)?;

        // Store locally first
        let contact_id = self.storage.get_contact_id(to)?;
        self.storage
            .store_sent_message(contact_id, outer_message_id, &content)?;

        // Update DAG tracking (skip for detached)
        if !detached {
            let (epoch, sender_head, peer_heads) = {
                let mut dag_state = self
                    .dag_state
                    .lock()
                    .map_err(|_| ClientError::LockPoisoned)?;
                let dag = dag_state.entry(contact_key).or_default();
                dag.sender.on_send(content_id, prev_self);
                (dag.epoch, dag.sender.head(), dag.observed_heads())
            };
            self.persist_dag_state(&contact_key, epoch, sender_head, &peer_heads);
        }

        // Serialize envelopes for outbox storage
        let envelope_bytes = postcard::to_allocvec(&outer)
            .map_err(|e| ClientError::Serialization(format!("envelope: {e}")))?;
        let inner_bytes = postcard::to_allocvec(&inner)
            .map_err(|e| ClientError::Serialization(format!("inner: {e}")))?;

        // Enqueue to outbox
        let entry_id = self
            .outbox
            .enqueue(
                to,
                content_id,
                outer_message_id,
                &envelope_bytes,
                &inner_bytes,
                None,
            )
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
            .record_attempt(prepared.entry_id, &transport_id, &attempt_result)
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

    /// Process a raw envelope into a decrypted message (sync: decrypt, store, DAG).
    ///
    /// This performs all local processing without any network I/O:
    /// 1. Routing key verification
    /// 2. MIK decryption + signature verification
    /// 3. Pending ack storage
    /// 4. Contact, message storage, dedup
    /// 5. DAG tracking and outbox confirmations
    ///
    /// Returns a [`ProcessedMessage`] containing the decrypted message and an
    /// optional tombstone to send via [`send_tombstone`](Self::send_tombstone).
    #[allow(clippy::too_many_lines, clippy::cast_possible_truncation)] // Message processing has many steps
    pub fn process_message_local(
        &self,
        outer: &OuterEnvelope,
    ) -> Result<ProcessedMessage, ClientError> {
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
        let dec_output = decrypt_with_mik(
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

        // Extract inner envelope and ack_secret
        let inner = dec_output.inner;
        let ack_secret = dec_output.ack_secret;

        // For non-detached messages, store ack_secret FIRST for tombstone retry capability.
        // This ensures we never lose the ability to tombstone if auto-send fails.
        // We'll send the tombstone AFTER successful message storage to prevent data loss.
        let should_tombstone = !inner.is_detached();
        if should_tombstone {
            self.storage
                .store_pending_ack(outer.message_id, ack_secret)?;
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

        // Store received message. Duplicate delivery is expected once fetch becomes
        // non-destructive, so treat an existing message_id as idempotent.
        let is_duplicate =
            match self
                .storage
                .store_received_message(contact_id, outer.message_id, &inner.content)
            {
                Ok(()) => false,
                Err(StorageError::AlreadyExists) => {
                    if !self.storage.received_message_matches(
                        contact_id,
                        outer.message_id,
                        &inner.content,
                    )? {
                        return Err(ClientError::ConflictingDuplicate(outer.message_id));
                    }
                    debug!(message_id = ?outer.message_id, "Duplicate message delivery");
                    true
                }
                Err(e) => return Err(e.into()),
            };

        // Build tombstone for caller to send asynchronously (fire-and-forget).
        // This ensures we never lose the message: if storage fails above, we never
        // reach here. If the caller fails to send the tombstone, the ack_secret is
        // persisted for retry via acknowledge_received().
        let pending_tombstone = if should_tombstone {
            Some(SignedAckTombstone::new(
                outer.message_id,
                ack_secret,
                &self.private_key(),
            ))
        } else {
            None
        };

        // Update DAG tracking and detect state anomalies
        let contact_key = sender_id.to_bytes();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let (
            has_gaps,
            sender_state_reset,
            local_state_behind,
            persist_epoch,
            persist_head,
            persist_peers,
        ) = {
            let mut dag_state = self
                .dag_state
                .lock()
                .map_err(|_| ClientError::LockPoisoned)?;
            let dag = dag_state.entry(contact_key).or_default();

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
            // Extract fields for persistence outside the lock
            let epoch = dag.epoch;
            let head = dag.sender.head();
            let peers = dag.observed_heads();
            (gaps, sender_reset, local_behind, epoch, head, peers)
        };
        self.persist_dag_state(&contact_key, persist_epoch, persist_head, &persist_peers);

        // Check for delivery confirmations in the peer's observed_heads
        // This is the DAG-based implicit ACK mechanism
        if !inner.observed_heads.is_empty() {
            match self.outbox.on_peer_message_received(
                &sender_id,
                &inner.observed_heads,
                content_id,
            ) {
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
                    warn!(
                        "Outbox confirmation check failed: {} - message may be re-sent",
                        e
                    );
                }
            }

            // If gap detected and retry triggers are enabled, schedule retry for unacked messages
            if has_gaps {
                match self
                    .outbox
                    .find_unacked_messages(&sender_id, &inner.observed_heads)
                {
                    Ok(unacked) if !unacked.is_empty() => {
                        debug!(
                            "Gap detected: scheduling retry for {} unacknowledged messages",
                            unacked.len()
                        );
                        if let Err(e) = self.outbox.schedule_immediate_retry(&unacked) {
                            warn!(
                                "Failed to schedule immediate retry for {} messages: {}",
                                unacked.len(),
                                e
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
            "Message received (content_id: {:?}, duplicate: {}, has_gaps: {}, sender_reset: {}, local_behind: {})",
            content_id, is_duplicate, has_gaps, sender_state_reset, local_state_behind
        );

        Ok(ProcessedMessage {
            received: ReceivedMessage {
                message_id: outer.message_id,
                from: inner.from,
                content: inner.content,
                created_at_ms: inner.created_at_ms,
                content_id,
                has_gaps,
                sender_state_reset,
                local_state_behind,
            },
            pending_tombstone,
        })
    }

    /// Send an auto-tombstone for a processed message.
    ///
    /// On success, removes the stored `pending_ack`. On failure, the
    /// `ack_secret` remains stored for retry via `acknowledge_received()`.
    pub async fn send_tombstone(
        &self,
        message_id: MessageID,
        tombstone: SignedAckTombstone,
    ) -> Result<(), ClientError> {
        self.transport
            .submit_ack_tombstone(tombstone)
            .await
            .map_err(ClientError::Transport)?;
        if let Err(e) = self.storage.remove_pending_ack(&message_id) {
            warn!(
                message_id = ?message_id,
                error = %e,
                "Failed to remove pending_ack after successful tombstone"
            );
        }
        debug!(message_id = ?message_id, "Auto-tombstone sent successfully");
        Ok(())
    }

    /// Process a raw envelope into a decrypted message
    ///
    /// This is a convenience wrapper around [`process_message_local`](Self::process_message_local)
    /// and [`send_tombstone`](Self::send_tombstone) that preserves the original
    /// behavior: decrypt, store, send tombstone (fire-and-forget), return message.
    ///
    /// For non-blocking UI updates, prefer calling `process_message_local` directly
    /// and sending the tombstone asynchronously.
    pub async fn process_message(
        &self,
        outer: &OuterEnvelope,
    ) -> Result<ReceivedMessage, ClientError> {
        let processed = self.process_message_local(outer)?;
        if let Some(tombstone) = processed.pending_tombstone {
            if let Err(e) = self.send_tombstone(outer.message_id, tombstone).await {
                warn!(
                    message_id = ?outer.message_id,
                    error = %e,
                    "Failed to send auto-tombstone (ack_secret stored for retry)"
                );
            }
        }
        Ok(processed.received)
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
    // Tombstone V2 (Signed Ack) Management
    // ========================================

    /// Retract a sent message (sender-initiated tombstone).
    ///
    /// Use this to delete a message from relay nodes before the recipient
    /// fetches it. This is the "unsend" or "retract" functionality.
    ///
    /// The `ack_secret` is retrieved from local storage (stored during
    /// message preparation). If the message has already been acknowledged
    /// by the recipient, this will fail at the node with 404.
    ///
    /// # Arguments
    /// * `message_id` - The message ID to retract
    ///
    /// # Errors
    /// - `ClientError::AckSecretNotFound` if no `pending_ack` exists for this message
    /// - `ClientError::Transport` if the tombstone submission fails
    pub async fn acknowledge_sent(&self, message_id: MessageID) -> Result<(), ClientError> {
        // Retrieve stored ack_secret
        let ack_secret = self
            .storage
            .get_pending_ack(&message_id)?
            .ok_or(ClientError::AckSecretNotFound)?;

        // Create and submit tombstone
        let tombstone = SignedAckTombstone::new(message_id, ack_secret, &self.private_key());

        self.transport.submit_ack_tombstone(tombstone).await?;

        // Remove from pending_acks after successful submission
        self.storage.remove_pending_ack(&message_id)?;

        debug!(
            message_id = ?message_id,
            "Sender-initiated tombstone sent (message retracted)"
        );

        Ok(())
    }

    /// Manually acknowledge a received message (retry for failed auto-tombstone).
    ///
    /// Use this when the auto-tombstone in `process_message()` failed and you
    /// want to retry clearing the message from relay nodes.
    ///
    /// The `ack_secret` is automatically retrieved from storage (stored during
    /// `process_message()` before attempting auto-tombstone).
    ///
    /// # Arguments
    /// * `message_id` - The message ID to acknowledge
    ///
    /// # Errors
    /// - `ClientError::AckSecretNotFound` if no `pending_ack` exists for this message
    /// - `ClientError::Transport` if the tombstone submission fails
    pub async fn acknowledge_received(&self, message_id: MessageID) -> Result<(), ClientError> {
        // Retrieve stored ack_secret
        let ack_secret = self
            .storage
            .get_pending_ack(&message_id)?
            .ok_or(ClientError::AckSecretNotFound)?;

        let tombstone = SignedAckTombstone::new(message_id, ack_secret, &self.private_key());

        self.transport.submit_ack_tombstone(tombstone).await?;

        // Remove from pending_acks after successful submission
        self.storage.remove_pending_ack(&message_id)?;

        debug!(
            message_id = ?message_id,
            "Manual tombstone sent for received message"
        );

        Ok(())
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
    /// Currently defaults to "<http:default>" - will be enhanced when
    /// multi-transport support is added.
    #[allow(clippy::unused_self)] // Will use self when multi-transport is implemented
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
    pub async fn attempt_delivery(
        &self,
        entry_id: OutboxEntryId,
    ) -> Result<AttemptResult, ClientError> {
        let pending = self
            .outbox
            .get_by_id(entry_id)
            .map_err(ClientError::Outbox)?
            .ok_or(ClientError::OutboxEntryNotFound)?;

        let transport_id = self.transport_id();

        // Deserialize the outer envelope
        let outer: OuterEnvelope = postcard::from_bytes(&pending.envelope_bytes)
            .map_err(|e| ClientError::Outbox(StorageError::Serialization(e.to_string())))?;

        // Attempt delivery
        let result = match self.transport.submit_message(outer).await {
            Ok(()) => AttemptResult::Sent,
            Err(e) => AttemptResult::Failed(transport_error_to_attempt_error(&e)),
        };

        // Record the attempt
        self.outbox
            .record_attempt(entry_id, &transport_id, &result)
            .map_err(ClientError::Outbox)?;

        Ok(result)
    }

    /// Retry delivery via a specific transport.
    ///
    /// Use this for user-initiated transport override (e.g., "send via `LoRa`").
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
        self.outbox
            .get_ready_for_retry()
            .map_err(ClientError::Outbox)
    }

    /// Get all pending (unconfirmed) messages.
    pub fn get_pending_messages(&self) -> Result<Vec<PendingMessage>, ClientError> {
        self.outbox.get_all_pending().map_err(ClientError::Outbox)
    }

    /// Get pending messages for a specific recipient.
    pub fn get_pending_for(
        &self,
        recipient: &PublicID,
    ) -> Result<Vec<PendingMessage>, ClientError> {
        self.outbox
            .get_pending_for(recipient)
            .map_err(ClientError::Outbox)
    }

    /// Get delivery state for a message.
    #[allow(clippy::cast_possible_truncation)] // Milliseconds since epoch fit in u64
    pub fn get_delivery_state(
        &self,
        entry_id: OutboxEntryId,
    ) -> Result<Option<DeliveryState>, ClientError> {
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
    /// Tuple of (`messages_retried`, `messages_expired`)
    #[allow(clippy::cast_possible_truncation)] // Milliseconds since epoch fit in u64
    pub async fn outbox_tick(&self) -> Result<(usize, u64), ClientError> {
        // Check for expired messages first
        let expired = self
            .outbox
            .check_expirations()
            .map_err(ClientError::Outbox)?;

        // Get messages due for retry
        let due = self
            .outbox
            .get_ready_for_retry()
            .map_err(ClientError::Outbox)?;
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
                DeliveryState::InFlight | DeliveryState::Confirmed | DeliveryState::Expired => {
                    // Skip: already in flight or completed
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
            message: format!("TLS configuration error: {msg}"),
            is_transient: false,
        },
        TransportError::CertificatePinMismatch {
            hostname,
            expected,
            actual,
        } => AttemptError::Rejected {
            message: format!(
                "Certificate pin mismatch for {hostname}: expected {expected}, got {actual}"
            ),
            is_transient: false,
        },
        TransportError::Timeout => AttemptError::Rejected {
            message: "request timed out".to_string(),
            is_transient: true,
        },
        TransportError::SignatureVerificationFailed => AttemptError::Rejected {
            message: "signature verification failed".to_string(),
            is_transient: false,
        },
    }
}

/// Get current time in milliseconds since epoch.
///
/// # Panics
/// Panics if system time is before Unix epoch, which indicates a serious
/// system configuration error that would break all time-based operations.
#[allow(clippy::cast_possible_truncation)] // Milliseconds since epoch fit in u64 for centuries
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
/// transport, enabling multi-tier delivery (Direct → Quorum → `BestEffort`) with
/// configurable quorum requirements.
impl Client<TransportCoordinator> {
    /// Send a text message using tiered delivery with quorum semantics.
    ///
    /// This method attempts delivery through multiple tiers:
    /// 1. **Direct (Ephemeral)**: Race all ephemeral targets, exit on any success
    /// 2. **Quorum (Stable)**: Broadcast to all stable targets, require quorum
    /// 3. **`BestEffort`**: Best effort delivery (future)
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

    /// Submit a previously prepared message via tiered delivery and record the result.
    ///
    /// This is the async half of the prepare/submit split. Call `prepare_message()` first
    /// (synchronous), then spawn this method in a background task.
    pub async fn submit_prepared_tiered(
        &self,
        prepared: &PreparedMessage,
    ) -> Result<TieredDeliveryPhase, ClientError> {
        let result = self
            .transport
            .submit_tiered(&prepared.outer, &self.tiered_config)
            .await;

        let phase = self
            .outbox
            .record_tiered_delivery_result(prepared.entry_id, &result, &self.tiered_config)
            .map_err(ClientError::Outbox)?;

        log_tiered_delivery_phase(prepared.entry_id, prepared.content_id, &result, &phase);

        Ok(phase)
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

        log_tiered_delivery_phase(prepared.entry_id, prepared.content_id, &result, &phase);

        Ok((prepared.entry_id, phase))
    }

    /// Process urgent retries (Phase 1 messages).
    ///
    /// This background task should be called periodically to retry messages
    /// that haven't yet reached quorum. Uses the full delivery pipeline:
    /// Direct first (recipient may be online now), then Quorum tier.
    ///
    /// # Returns
    /// Number of messages retried and their new phases.
    pub async fn process_urgent_retries(
        &self,
    ) -> Result<Vec<(OutboxEntryId, TieredDeliveryPhase)>, ClientError> {
        let due = self
            .outbox
            .get_urgent_retry_due()
            .map_err(ClientError::Outbox)?;
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
    /// Uses the full delivery pipeline: Direct first (recipient may be online now),
    /// then refresh ALL Quorum tier targets.
    ///
    /// # Returns
    /// Number of messages refreshed.
    #[allow(clippy::cast_possible_truncation)] // Interval ms fits in u64
    pub async fn process_maintenance(&self) -> Result<usize, ClientError> {
        let maintenance_interval_ms = self.tiered_config.maintenance_interval.as_millis() as u64;
        let due = self
            .outbox
            .get_maintenance_due(maintenance_interval_ms)
            .map_err(ClientError::Outbox)?;

        let mut refreshed = 0;

        for pending in due {
            match self.attempt_maintenance_refresh(&pending).await {
                Ok(()) => {
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
    /// For urgent retries, this uses selective Quorum tier targeting:
    /// only retry failed targets, skip already-successful ones.
    #[allow(clippy::cast_possible_truncation)] // Success counts and targets fit in u32
    async fn attempt_tiered_delivery(
        &self,
        pending: &PendingMessage,
    ) -> Result<TieredDeliveryPhase, ClientError> {
        // Deserialize the outer envelope
        let outer: OuterEnvelope = postcard::from_bytes(&pending.envelope_bytes)
            .map_err(|e| ClientError::Serialization(format!("envelope: {e}")))?;

        // Try Direct tier first - recipient may be online now
        let direct_result = self
            .transport
            .try_direct_tier(&outer, &self.tiered_config)
            .await;

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
            quorum_reached: self
                .tiered_config
                .quorum
                .is_satisfied(total_success, total_targets),
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
    #[allow(clippy::cast_possible_truncation)] // Target counts fit in u32
    async fn attempt_maintenance_refresh(
        &self,
        pending: &PendingMessage,
    ) -> Result<(), ClientError> {
        // Deserialize the outer envelope
        let outer: OuterEnvelope = postcard::from_bytes(&pending.envelope_bytes)
            .map_err(|e| ClientError::Serialization(format!("envelope: {e}")))?;

        // Try Direct tier first - recipient may be online now
        let direct_result = self
            .transport
            .try_direct_tier(&outer, &self.tiered_config)
            .await;

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
    /// Tuple of (`urgent_retried`, `maintenance_refreshed`, expired)
    pub async fn tiered_outbox_tick(&self) -> Result<(usize, usize, u64), ClientError> {
        // Check for expired messages first
        let expired = self
            .outbox
            .check_expirations()
            .map_err(ClientError::Outbox)?;

        // Process urgent retries
        let urgent_results = self.process_urgent_retries().await?;

        // Process maintenance refreshes
        let maintenance_count = self.process_maintenance().await?;

        Ok((urgent_results.len(), maintenance_count, expired))
    }
}

/// Log a tracing message describing the outcome of a tiered delivery attempt.
fn log_tiered_delivery_phase(
    entry_id: OutboxEntryId,
    content_id: ContentId,
    result: &DeliveryResult,
    phase: &TieredDeliveryPhase,
) {
    match phase {
        TieredDeliveryPhase::Urgent => {
            warn!(
                message_id = ?entry_id,
                content_id = ?content_id,
                success_count = result.success_count(),
                "Message quorum not reached, will retry"
            );
        }
        TieredDeliveryPhase::Distributed { confidence, .. } => {
            if confidence.is_direct() {
                info!(
                    message_id = ?entry_id,
                    "Message delivered directly (Direct tier)"
                );
            } else {
                debug!(
                    message_id = ?entry_id,
                    success_count = result.success_count(),
                    "Message distributed, awaiting ACK"
                );
            }
        }
        TieredDeliveryPhase::Confirmed { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use reme_message::SignedAckTombstone;
    use std::sync::Mutex;

    /// Mock transport for testing (MIK-only, no prekeys)
    struct MockTransport {
        messages: Mutex<Vec<OuterEnvelope>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                messages: Mutex::new(Vec::new()),
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

        async fn submit_ack_tombstone(
            &self,
            _tombstone: SignedAckTombstone,
        ) -> Result<(), TransportError> {
            // Mock implementation - just accept
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
        let msg_id = alice
            .send_text(bob_identity.public_id(), "Hello Bob!")
            .await
            .unwrap();
        assert!(!msg_id.as_bytes().is_empty());

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
        let _msg_id = alice
            .send_text(bob.public_id(), "Hello Bob!")
            .await
            .unwrap();

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
    async fn test_process_message_is_idempotent_for_duplicate_delivery() {
        let shared_transport = Arc::new(MockTransport::new());

        let alice_identity = Identity::generate();
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, shared_transport.clone(), alice_storage);

        let bob_identity = Identity::generate();
        let bob_storage = Storage::in_memory().unwrap();
        let bob = Client::new(bob_identity, shared_transport.clone(), bob_storage);

        alice.add_contact(bob.public_id(), Some("Bob")).unwrap();
        alice
            .send_text(bob.public_id(), "Hello twice")
            .await
            .unwrap();

        let messages = shared_transport.take_messages();
        assert_eq!(messages.len(), 1);

        let first = bob.process_message(&messages[0]).await.unwrap();
        let second = bob.process_message(&messages[0]).await.unwrap();

        assert_eq!(first.message_id, second.message_id);
        assert_eq!(first.from, second.from);
        match (first.content, second.content) {
            (Content::Text(first_text), Content::Text(second_text)) => {
                assert_eq!(first_text.body, "Hello twice");
                assert_eq!(second_text.body, "Hello twice");
            }
            _ => panic!("Expected text content"),
        }
    }

    #[tokio::test]
    #[allow(clippy::cast_possible_truncation)] // Test code, ms since epoch fits in u64
    async fn test_duplicate_delivery_preserves_gap_detection() {
        use reme_encryption::encrypt_to_mik;
        use reme_message::{ContentId, InnerEnvelope, TextContent};

        let shared_transport = Arc::new(MockTransport::new());

        let alice_identity = Identity::generate();
        let alice_private_key = alice_identity.to_bytes();
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, shared_transport.clone(), alice_storage);

        let bob_identity = Identity::generate();
        let bob_storage = Storage::in_memory().unwrap();
        let bob = Client::new(bob_identity, shared_transport.clone(), bob_storage);

        bob.add_contact(alice.public_id(), Some("Alice")).unwrap();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let message_id = MessageID::new();
        let missing_parent: ContentId = [0xAA; 8];
        let inner = InnerEnvelope {
            from: *alice.public_id(),
            created_at_ms: now_ms,
            content: Content::Text(TextContent {
                body: "Out of order".to_string(),
            }),
            prev_self: Some(missing_parent),
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        };

        let enc_output =
            encrypt_to_mik(&inner, bob.public_id(), &message_id, &alice_private_key).unwrap();
        let outer = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key: bob.public_id().routing_key(),
            timestamp_hours: reme_message::now_hours(),
            ttl_hours: None,
            message_id,
            ephemeral_key: enc_output.ephemeral_public,
            ack_hash: enc_output.ack_hash,
            inner_ciphertext: enc_output.ciphertext,
        };

        let first = bob.process_message(&outer).await.unwrap();
        let second = bob.process_message(&outer).await.unwrap();

        assert!(first.has_gaps);
        assert!(second.has_gaps);
        assert_eq!(first.content_id, second.content_id);
    }

    #[tokio::test]
    #[allow(clippy::cast_possible_truncation)] // Test code, ms since epoch fits in u64
    async fn test_conflicting_duplicate_message_id_is_rejected() {
        use reme_encryption::encrypt_to_mik;
        use reme_message::{InnerEnvelope, TextContent};

        let shared_transport = Arc::new(MockTransport::new());

        let alice_identity = Identity::generate();
        let alice_private_key = alice_identity.to_bytes();
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, shared_transport.clone(), alice_storage);

        let bob_identity = Identity::generate();
        let bob_storage = Storage::in_memory().unwrap();
        let bob = Client::new(bob_identity, shared_transport.clone(), bob_storage);

        bob.add_contact(alice.public_id(), Some("Alice")).unwrap();

        let message_id = MessageID::new();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let make_outer = |body: &str, created_at_ms: u64| {
            let inner = InnerEnvelope {
                from: *alice.public_id(),
                created_at_ms,
                content: Content::Text(TextContent {
                    body: body.to_string(),
                }),
                prev_self: None,
                observed_heads: Vec::new(),
                epoch: 0,
                flags: 0,
            };

            let enc_output =
                encrypt_to_mik(&inner, bob.public_id(), &message_id, &alice_private_key).unwrap();
            OuterEnvelope {
                version: CURRENT_VERSION,
                routing_key: bob.public_id().routing_key(),
                timestamp_hours: reme_message::now_hours(),
                ttl_hours: None,
                message_id,
                ephemeral_key: enc_output.ephemeral_public,
                ack_hash: enc_output.ack_hash,
                inner_ciphertext: enc_output.ciphertext,
            }
        };

        let first = make_outer("Original", now_ms);
        bob.process_message(&first).await.unwrap();

        let conflicting = make_outer("Tampered", now_ms + 1);
        let result = bob.process_message(&conflicting).await;

        assert!(matches!(
            result,
            Err(ClientError::ConflictingDuplicate(id)) if id == message_id
        ));
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
        alice
            .send_text(bob.public_id(), "Secret message")
            .await
            .unwrap();

        // Eve tries to decrypt (should fail)
        let messages = shared_transport.take_messages();
        let result = eve.process_message(&messages[0]).await;
        assert!(result.is_err());
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

        alice
            .add_contact(bob_identity.public_id(), Some("Bob"))
            .unwrap();

        // Send a detached message
        alice
            .send_text_detached(bob_identity.public_id(), "Detached!")
            .await
            .unwrap();

        let messages = shared_transport.take_messages();
        assert_eq!(messages.len(), 1);

        // Decrypt and verify it's detached
        let dec_output = decrypt_with_mik(
            &messages[0].ephemeral_key,
            &messages[0].inner_ciphertext,
            &bob_private_key,
            &messages[0].message_id,
        )
        .unwrap();

        assert!(dec_output.inner.is_detached());
        assert!(dec_output.inner.prev_self.is_none());
        assert!(dec_output.inner.observed_heads.is_empty());
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

        alice
            .add_contact(bob_identity.public_id(), Some("Bob"))
            .unwrap();

        // Send first linked message
        alice
            .send_text(bob_identity.public_id(), "First")
            .await
            .unwrap();

        // Send second linked message
        alice
            .send_text(bob_identity.public_id(), "Second")
            .await
            .unwrap();

        let messages = shared_transport.take_messages();
        assert_eq!(messages.len(), 2);

        // Decrypt both
        let dec1 = decrypt_with_mik(
            &messages[0].ephemeral_key,
            &messages[0].inner_ciphertext,
            &bob_private_key,
            &messages[0].message_id,
        )
        .unwrap();

        let dec2 = decrypt_with_mik(
            &messages[1].ephemeral_key,
            &messages[1].inner_ciphertext,
            &bob_private_key,
            &messages[1].message_id,
        )
        .unwrap();

        // First message has no prev_self (but may have observed_heads if we received from Bob)
        assert!(dec1.inner.prev_self.is_none());

        // Second message should link to first
        assert!(dec2.inner.prev_self.is_some());
        assert_eq!(dec2.inner.prev_self.unwrap(), dec1.inner.content_id());
    }

    #[tokio::test]
    async fn test_epoch_management() {
        let shared_transport = Arc::new(MockTransport::new());

        let alice_identity = Identity::generate();
        let alice_storage = Storage::in_memory().unwrap();
        let alice = Client::new(alice_identity, shared_transport.clone(), alice_storage);

        let bob_identity = Identity::generate();

        alice
            .add_contact(bob_identity.public_id(), Some("Bob"))
            .unwrap();

        // Initial epoch is 0
        assert_eq!(
            alice
                .get_conversation_epoch(bob_identity.public_id())
                .unwrap(),
            0
        );

        // Send a message to establish state
        alice
            .send_text(bob_identity.public_id(), "Hello")
            .await
            .unwrap();

        // Clear conversation DAG
        let new_epoch = alice
            .clear_conversation_dag(bob_identity.public_id())
            .unwrap();
        assert_eq!(new_epoch, 1);
        assert_eq!(
            alice
                .get_conversation_epoch(bob_identity.public_id())
                .unwrap(),
            1
        );

        // Clear again
        let newer_epoch = alice
            .clear_conversation_dag(bob_identity.public_id())
            .unwrap();
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

        alice
            .add_contact(bob_identity.public_id(), Some("Bob"))
            .unwrap();

        // Send linked message
        alice
            .send_text(bob_identity.public_id(), "Linked 1")
            .await
            .unwrap();

        // Send detached message (should NOT update chain)
        alice
            .send_text_detached(bob_identity.public_id(), "Detached")
            .await
            .unwrap();

        // Send another linked message (should link to "Linked 1", not "Detached")
        alice
            .send_text(bob_identity.public_id(), "Linked 2")
            .await
            .unwrap();

        let messages = shared_transport.take_messages();
        assert_eq!(messages.len(), 3);

        let dec1 = decrypt_with_mik(
            &messages[0].ephemeral_key,
            &messages[0].inner_ciphertext,
            &bob_private_key,
            &messages[0].message_id,
        )
        .unwrap();

        let dec3 = decrypt_with_mik(
            &messages[2].ephemeral_key,
            &messages[2].inner_ciphertext,
            &bob_private_key,
            &messages[2].message_id,
        )
        .unwrap();

        // Third message (Linked 2) should link to first (Linked 1), skipping detached
        assert_eq!(dec3.inner.prev_self.unwrap(), dec1.inner.content_id());
    }

    #[tokio::test]
    #[allow(clippy::cast_possible_truncation)] // Test code, ms since epoch fits in u64
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
        alice
            .send_text(bob.public_id(), "Hello Bob!")
            .await
            .unwrap();
        let messages = shared_transport.take_messages();
        let received1 = bob.process_message(&messages[0]).await.unwrap();

        // First message should not trigger state reset detection
        assert!(!received1.sender_state_reset);
        assert!(!received1.local_state_behind);

        // Alice sends second message (with valid prev_self chain)
        alice
            .send_text(bob.public_id(), "How are you?")
            .await
            .unwrap();
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
            prev_self: None, // No previous message (state lost)
            observed_heads: Vec::new(),
            epoch: 0, // Fresh epoch
            flags: 0, // NOT detached - this indicates state loss
        };

        // Encrypt and create outer envelope (signing happens inside encrypt_to_mik)
        let bob_routing_key = bob.public_id().routing_key();
        let enc_output =
            encrypt_to_mik(&inner, bob.public_id(), &message_id, &alice_private_key).unwrap();
        let outer = OuterEnvelope {
            version: reme_message::CURRENT_VERSION,
            routing_key: bob_routing_key,
            timestamp_hours: reme_message::now_hours(),
            ttl_hours: None,
            message_id,
            ephemeral_key: enc_output.ephemeral_public,
            ack_hash: enc_output.ack_hash,
            inner_ciphertext: enc_output.ciphertext,
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
    #[allow(clippy::cast_possible_truncation)] // Test code, ms since epoch fits in u64
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
        alice
            .send_text(bob.public_id(), "Hello Bob!")
            .await
            .unwrap();
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
            flags: FLAG_DETACHED, // Intentionally detached!
        };

        // Encrypt and create outer envelope (signing happens inside encrypt_to_mik)
        let bob_routing_key = bob.public_id().routing_key();
        let enc_output =
            encrypt_to_mik(&inner, bob.public_id(), &message_id, &alice_private_key).unwrap();
        let outer = OuterEnvelope {
            version: reme_message::CURRENT_VERSION,
            routing_key: bob_routing_key,
            timestamp_hours: reme_message::now_hours(),
            ttl_hours: None,
            message_id,
            ephemeral_key: enc_output.ephemeral_public,
            ack_hash: enc_output.ack_hash,
            inner_ciphertext: enc_output.ciphertext,
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
    #[allow(clippy::cast_possible_truncation)] // Test code, ms since epoch fits in u64
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
            prev_self: None,                          // Bob's first message
            observed_heads: vec![unknown_content_id], // Claims to have seen this from Alice
            epoch: 0,
            flags: 0,
        };

        // Encrypt for Alice (signing happens inside encrypt_to_mik)
        let alice_routing_key = alice.public_id().routing_key();
        let enc_output =
            encrypt_to_mik(&inner, alice.public_id(), &message_id, &bob_private_key).unwrap();
        let outer = OuterEnvelope {
            version: reme_message::CURRENT_VERSION,
            routing_key: alice_routing_key,
            timestamp_hours: reme_message::now_hours(),
            ttl_hours: None,
            message_id,
            ephemeral_key: enc_output.ephemeral_public,
            ack_hash: enc_output.ack_hash,
            inner_ciphertext: enc_output.ciphertext,
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

    /// Test that DAG state persists across Client restarts.
    ///
    /// Uses a file-backed database so that a second Client can be created
    /// from the same path, verifying true restart behavior: the second
    /// client's `prepare_message` should produce a `prev_self` that links
    /// back to the first session's message.
    #[tokio::test]
    async fn test_dag_state_persists_across_restart() {
        let db_path = format!(
            "{}/reme-test-dag-persist-{}-{}.db",
            std::env::temp_dir().display(),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Save key bytes so we can reconstruct Identity after drop
        let alice_bytes = Identity::generate().to_bytes();
        let bob = Identity::generate();
        let bob_pub = *bob.public_id();

        // --- Session 1: send a message to establish DAG state ---
        let first_head = {
            let alice = Identity::from_bytes(&alice_bytes);
            let storage = Storage::open(&db_path).unwrap();
            let transport = Arc::new(MockTransport::new());
            let client = Client::new(alice, Arc::clone(&transport), storage);

            client.add_contact(&bob_pub, Some("Bob")).unwrap();
            client
                .send_text(&bob_pub, "Hello from session 1")
                .await
                .unwrap();

            // Capture the sender head before dropping
            let dag_state = client
                .dag_state
                .lock()
                .map_err(|_| ClientError::LockPoisoned)
                .unwrap();
            let contact_key = bob_pub.to_bytes();
            let dag = dag_state.get(&contact_key).unwrap();
            let head = dag.sender.head();
            assert!(head.is_some(), "sender head should exist after send");
            head
            // client + storage dropped here, simulating shutdown
        };

        // --- Session 2: create a new Client from the same DB file ---
        {
            let alice = Identity::from_bytes(&alice_bytes);
            let storage = Storage::open(&db_path).unwrap();
            let transport = Arc::new(MockTransport::new());
            let client = Client::new(alice, Arc::clone(&transport), storage);

            // Verify the restored DAG state
            let dag_state = client
                .dag_state
                .lock()
                .map_err(|_| ClientError::LockPoisoned)
                .unwrap();
            let contact_key = bob_pub.to_bytes();
            let dag = dag_state.get(&contact_key).unwrap();

            assert_eq!(
                dag.sender.head(),
                first_head,
                "restored DAG should have the same sender head from session 1"
            );
            assert_eq!(dag.epoch, 0);
        }

        // Cleanup
        let _ = std::fs::remove_file(&db_path);
    }

    /// Test that epoch changes are persisted.
    #[tokio::test]
    async fn test_dag_epoch_persists() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let storage = Storage::in_memory().unwrap();
        let transport = Arc::new(MockTransport::new());
        let client = Client::new(alice, Arc::clone(&transport), storage);

        client.add_contact(bob.public_id(), Some("Bob")).unwrap();

        // Clear conversation DAG (increments epoch)
        let new_epoch = client.clear_conversation_dag(bob.public_id()).unwrap();
        assert_eq!(new_epoch, 1);

        // Verify epoch was persisted
        let persisted = client.storage.load_all_dag_states().unwrap();
        let contact_key = bob.public_id().to_bytes();
        let (epoch, _, _) = &persisted[&contact_key];
        assert_eq!(*epoch, 1);
    }
}
