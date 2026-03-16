use bincode::enc::Encoder;
use bincode::error::EncodeError;
use bincode::{impl_borrow_decode, Decode, Encode};
use derive_more::From;
pub use reme_identity::{PublicID, RoutingKey};
use uuid::Uuid;

pub mod dag;
pub mod tombstone;
pub mod wire;

pub use dag::{ConversationDag, GapResult, ReceiverGapDetector, SenderGapDetector};

// ============================================
// Timestamp utilities (shared with tombstone)
// ============================================

/// One hour in seconds
pub const HOUR_SECS: u64 = 60 * 60;

/// Get current time as hours since Unix epoch (u32)
///
/// Using hours instead of milliseconds:
/// - Saves 4 bytes per timestamp (u32 vs i64)
/// - Matches the hour-granularity privacy protection
/// - Range: ~490,000 years from 1970 (sufficient)
#[allow(clippy::cast_possible_truncation)] // Hours since 1970 won't overflow u32 for ~490,000 years
pub fn now_hours() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() / HOUR_SECS) as u32)
        .unwrap_or(0)
}

/// Get current time in seconds since Unix epoch
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================
// Bincode configuration
// ============================================

/// Bincode configuration for message serialization.
///
/// Returns the standard bincode v2 config. Forward compatibility is built-in:
/// - `decode_from_slice` returns `(T, bytes_consumed)`, ignoring trailing bytes
/// - New fields can be added at the end of structs without breaking older clients
/// - Older clients simply don't consume bytes they don't understand
///
/// # Example
/// ```ignore
/// let bytes = bincode::encode_to_vec(&envelope, bincode_config())?;
/// let (decoded, _bytes_read) = bincode::decode_from_slice(&bytes, bincode_config())?;
/// ```
pub fn bincode_config() -> impl bincode::config::Config {
    bincode::config::standard()
}

pub use tombstone::{
    // Tombstone V2 (signed ack)
    Attribution,
    SignedAckTombstone,
    // Constants
    ACK_HASH_DOMAIN,
    CLOCK_SKEW_ALLOWANCE_HOURS,
    TOMBSTONE_MAX_AGE_HOURS,
};
pub use wire::{WirePayload, WireType};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, From)]
pub struct MessageID(Uuid);

impl MessageID {
    pub fn new() -> Self {
        MessageID(Uuid::new_v4())
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        MessageID(Uuid::from_bytes(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for MessageID {
    fn default() -> Self {
        Self::new()
    }
}

impl bincode::Encode for MessageID {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.0.as_bytes().encode(encoder)
    }
}

impl<C> bincode::Decode<C> for MessageID {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let bytes: [u8; 16] = Decode::decode(decoder)?;
        let uuid = Uuid::from_bytes(bytes);
        Ok(MessageID(uuid))
    }
}

impl_borrow_decode!(MessageID);

// ============================================
// Content-addressed ID for Merkle DAG
// ============================================

/// Content-addressed ID for DAG references.
///
/// 8 bytes (64 bits) - sufficient for per-conversation uniqueness.
/// Birthday bound ~4 billion messages - more than any conversation will have.
///
/// Computed as truncated BLAKE3 hash of (from, `created_at_ms`, content).
/// BLAKE3 is designed as an XOF (extendable output function) where
/// truncation is safe and expected.
pub type ContentId = [u8; 8];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

/// Current protocol version (0.0 - `PoC`)
/// Using u8 for major/minor: max version 255.255, saves 2 bytes per envelope
///
/// Note: `ack_hash` was added to `OuterEnvelope` in this version.
/// No version bump needed since this is a `PoC` with no deployed clients.
pub const CURRENT_VERSION: Version = Version { major: 0, minor: 0 };

/// Outer envelope for MIK-only encryption (Session V1-style stateless)
///
/// Each message includes an ephemeral X25519 public key. The sender:
/// 1. Generates ephemeral keypair (e, E)
/// 2. Computes `shared_secret` = X25519(e, `recipient_MIK`)
/// 3. Derives encryption key from `shared_secret`
/// 4. Encrypts `InnerEnvelope` with derived key
///
/// The recipient:
/// 1. Computes `shared_secret` = `X25519(mik_private`, `ephemeral_key`)
/// 2. Derives same encryption key
/// 3. Decrypts `InnerEnvelope`
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct OuterEnvelope {
    pub version: Version,

    pub routing_key: RoutingKey,

    /// Coarse timestamp as hours since Unix epoch (u32)
    /// Hour granularity limits timing analysis while saving 4 bytes vs i64 ms.
    pub timestamp_hours: u32,

    /// Time-to-live in hours (u16, max ~7.5 years)
    /// None means use server default.
    pub ttl_hours: Option<u16>,

    pub message_id: MessageID,

    /// Ephemeral X25519 public key for this message (32 bytes)
    /// Used with recipient's MIK to derive the encryption key.
    pub ephemeral_key: [u8; 32],

    // ===== Tombstone V2: Ack Hash =====
    /// Ack hash (16 bytes) for tombstone authorization.
    /// Computed as `BLAKE3(ack_secret)`[0..16] where
    /// `ack_secret` = BLAKE3_KDF("reme-ack-v1", `shared_secret` || `message_id`).
    /// Allows nodes to verify tombstones with O(1) hash check.
    pub ack_hash: [u8; 16],

    pub inner_ciphertext: Vec<u8>,
}

impl OuterEnvelope {
    /// Create a new envelope for MIK-only encryption
    ///
    /// # Arguments
    /// * `routing_key` - 16-byte routing key (truncated blake3 hash of recipient `PublicID`)
    /// * `ttl_hours` - Optional time-to-live in hours
    /// * `ephemeral_key` - 32-byte ephemeral X25519 public key used for ECDH
    /// * `ack_hash` - 16-byte hash for tombstone authorization
    /// * `inner_ciphertext` - Encrypted `InnerEnvelope` bytes
    pub fn new(
        routing_key: RoutingKey,
        ttl_hours: Option<u16>,
        ephemeral_key: [u8; 32],
        ack_hash: [u8; 16],
        inner_ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: now_hours(),
            ttl_hours,
            message_id: MessageID::new(),
            ephemeral_key,
            ack_hash,
            inner_ciphertext,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard()).unwrap()
    }
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct InnerEnvelope {
    /// Sender's public identity (32 bytes)
    pub from: PublicID,

    /// Precise timestamp in milliseconds since Unix epoch
    /// (outer envelope has coarse hour-granularity for metadata privacy)
    pub created_at_ms: u64,

    /// Message content
    pub content: Content,

    // Note: Signature is no longer stored in the struct.
    // With sign-all-bytes (#25), the signature is appended to the serialized
    // InnerEnvelope before encryption. This enables forward compatibility:
    // newer versions can add fields, and the signature covers all bytes.

    // =============================================
    // Merkle DAG fields for message ordering
    // =============================================
    /// My previous message's `content_id` (per-sender continuity).
    /// None for first message in conversation or detached messages.
    pub prev_self: Option<ContentId>,

    /// Latest `content_id(s)` observed from peer(s).
    /// Enables sender-side gap detection.
    /// Usually 1 element, can be 2+ in multi-party or fork scenarios.
    /// Empty for detached messages (constrained transports).
    pub observed_heads: Vec<ContentId>,

    /// Conversation epoch (increments on history clear).
    /// Allows breaking DAG cleanly when history is deleted.
    /// u16 = 65K clears, sufficient for any realistic usage.
    pub epoch: u16,

    /// Message flags (1 byte, extensible).
    /// See FLAG_* constants for bit definitions.
    pub flags: u8,
}

/// Flag: Message is intentionally detached (no DAG linkage).
/// Used for constrained transports (`LoRa`, BLE) where bandwidth is limited.
/// When set, `prev_self=None` and `observed_heads`=[] is intentional, not state loss.
pub const FLAG_DETACHED: u8 = 0x01;

// Bits 1-7 reserved for future use

// Removed fields (per envelope optimization design):
// - version: Use outer envelope version
// - to: Cryptographically bound via sealed box ECDH (only intended recipient can decrypt)
// - outer_message_id: Bound via AAD + nonce derivation (triple binding)

impl InnerEnvelope {
    /// Compute content-addressed ID for this message.
    ///
    /// Uses BLAKE3 truncated to 8 bytes. BLAKE3 is designed as an XOF
    /// (extendable output function) where truncation is safe and expected.
    ///
    /// Hash covers: identity + timestamp + content (NOT DAG fields).
    /// This ensures the same content can be resent with different DAG
    /// fields while maintaining the same `content_id`.
    pub fn content_id(&self) -> ContentId {
        let mut hasher = blake3::Hasher::new();

        // Domain separation
        hasher.update(b"reme-content-id-v1");

        // Sender identity (prevents cross-user collision)
        hasher.update(&self.from.to_bytes());

        // Timestamp (prevents same-user collision for identical content)
        hasher.update(&self.created_at_ms.to_le_bytes());

        // Content
        let content_bytes = bincode::encode_to_vec(&self.content, bincode::config::standard())
            .expect("content serialization");
        hasher.update(&content_bytes);

        // Truncate to 8 bytes - safe for BLAKE3 (XOF design)
        let hash = hasher.finalize();
        hash.as_bytes()[..8].try_into().unwrap()
    }

    /// Check if this is an intentionally detached (unlinked) message.
    ///
    /// Detached messages have the `FLAG_DETACHED` flag set and are used on
    /// constrained transports (`LoRa`, BLE). They can be linked into the DAG
    /// later when a subsequent message references them via `prev_self`.
    ///
    /// Note: This checks the explicit flag, not just empty DAG fields.
    /// A message with empty DAG fields but no flag may indicate state loss.
    pub fn is_detached(&self) -> bool {
        (self.flags & FLAG_DETACHED) != 0
    }

    // Note: signable_bytes(), sign(), verify_signature(), and has_signature()
    // have been removed as part of #25 (sign-all-bytes).
    // Signing now happens in reme-encryption::encrypt_to_mik() by signing
    // the serialized InnerEnvelope bytes || outer_message_id.
}

#[derive(Debug, Clone, Encode, Decode)]
#[non_exhaustive]
pub enum Content {
    Text(TextContent),
    Receipt(ReceiptContent),
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct TextContent {
    /// UTF-8 encoded.
    pub body: String,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct ReceiptContent {
    pub target_message_id: MessageID,
    pub kind: ReceiptKind,
}

#[derive(Debug, Clone, Copy, Encode, Decode)]
#[non_exhaustive]
pub enum ReceiptKind {
    Delivered,
    Read,
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_identity::Identity;

    fn create_test_inner(body: &str, created_at_ms: u64) -> InnerEnvelope {
        let sender = Identity::generate();
        InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms,
            content: Content::Text(TextContent {
                body: body.to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        }
    }

    #[test]
    fn test_content_id_is_8_bytes() {
        let inner = create_test_inner("Hello", 1_234_567_890);
        let content_id = inner.content_id();
        assert_eq!(content_id.len(), 8);
    }

    #[test]
    fn test_content_id_deterministic() {
        let sender = Identity::generate();
        let inner1 = InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms: 1_234_567_890,
            content: Content::Text(TextContent {
                body: "Hello".to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        };
        let inner2 = InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms: 1_234_567_890,
            content: Content::Text(TextContent {
                body: "Hello".to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        };
        assert_eq!(inner1.content_id(), inner2.content_id());
    }

    #[test]
    fn test_content_id_different_content() {
        let sender = Identity::generate();
        let inner1 = InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms: 1_234_567_890,
            content: Content::Text(TextContent {
                body: "Hello".to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        };
        let inner2 = InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms: 1_234_567_890,
            content: Content::Text(TextContent {
                body: "World".to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        };
        assert_ne!(inner1.content_id(), inner2.content_id());
    }

    #[test]
    fn test_content_id_different_timestamp() {
        let sender = Identity::generate();
        let inner1 = InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms: 1_234_567_890,
            content: Content::Text(TextContent {
                body: "Hello".to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        };
        let inner2 = InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms: 1_234_567_891,
            content: Content::Text(TextContent {
                body: "Hello".to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        };
        // Same content, different timestamp = different content_id
        assert_ne!(inner1.content_id(), inner2.content_id());
    }

    #[test]
    fn test_content_id_different_sender() {
        let sender1 = Identity::generate();
        let sender2 = Identity::generate();
        let inner1 = InnerEnvelope {
            from: *sender1.public_id(),
            created_at_ms: 1_234_567_890,
            content: Content::Text(TextContent {
                body: "Hello".to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        };
        let inner2 = InnerEnvelope {
            from: *sender2.public_id(),
            created_at_ms: 1_234_567_890,
            content: Content::Text(TextContent {
                body: "Hello".to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        };
        // Same content, different sender = different content_id
        assert_ne!(inner1.content_id(), inner2.content_id());
    }

    #[test]
    fn test_content_id_ignores_dag_fields() {
        let sender = Identity::generate();
        let prev_id: ContentId = [1, 2, 3, 4, 5, 6, 7, 8];
        let observed: ContentId = [9, 10, 11, 12, 13, 14, 15, 16];

        let inner1 = InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms: 1_234_567_890,
            content: Content::Text(TextContent {
                body: "Hello".to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        };
        let inner2 = InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms: 1_234_567_890,
            content: Content::Text(TextContent {
                body: "Hello".to_string(),
            }),
            prev_self: Some(prev_id),
            observed_heads: vec![observed],
            epoch: 5,
            flags: 0,
        };
        // DAG fields should NOT affect content_id
        assert_eq!(inner1.content_id(), inner2.content_id());
    }

    #[test]
    fn test_is_detached() {
        let sender = Identity::generate();

        // Message with FLAG_DETACHED set is detached
        let inner1 = InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms: 1_234_567_890,
            content: Content::Text(TextContent {
                body: "Hello".to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: FLAG_DETACHED,
        };
        assert!(inner1.is_detached());

        // Message without FLAG_DETACHED is not detached (even with empty DAG fields)
        let inner2 = InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms: 1_234_567_890,
            content: Content::Text(TextContent {
                body: "Hello".to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        };
        assert!(!inner2.is_detached());

        // Message with DAG fields and FLAG_DETACHED is still detached
        // (flag takes precedence - unusual but valid)
        let inner3 = InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms: 1_234_567_890,
            content: Content::Text(TextContent {
                body: "Hello".to_string(),
            }),
            prev_self: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            observed_heads: vec![[9, 10, 11, 12, 13, 14, 15, 16]],
            epoch: 0,
            flags: FLAG_DETACHED,
        };
        assert!(inner3.is_detached());
    }

    // Note: test_signable_bytes_includes_dag_fields was removed as part of #25.
    // Signing now happens in reme-encryption, not in InnerEnvelope.

    #[test]
    fn test_dag_fields_serialization() {
        let sender = Identity::generate();
        let prev_id: ContentId = [1, 2, 3, 4, 5, 6, 7, 8];
        let observed: ContentId = [9, 10, 11, 12, 13, 14, 15, 16];

        let inner = InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms: 1_234_567_890,
            content: Content::Text(TextContent {
                body: "Hello".to_string(),
            }),
            prev_self: Some(prev_id),
            observed_heads: vec![observed],
            epoch: 42,
            flags: 0,
        };

        // Serialize and deserialize
        let bytes = bincode::encode_to_vec(&inner, bincode::config::standard()).unwrap();
        let (decoded, _): (InnerEnvelope, _) =
            bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap();

        assert_eq!(decoded.prev_self, Some(prev_id));
        assert_eq!(decoded.observed_heads, vec![observed]);
        assert_eq!(decoded.epoch, 42);
    }
}
