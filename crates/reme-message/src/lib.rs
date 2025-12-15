use bincode::enc::Encoder;
use bincode::error::EncodeError;
use bincode::{impl_borrow_decode, Decode, Encode};
pub use reme_identity::PublicID;
use uuid::Uuid;

pub mod tombstone;

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
pub use tombstone::{
    DetailedReceipt, DeviceID, TombstoneEnvelope, TombstoneStatus, TombstoneValidationError,
    WirePayload, WireType, CLOCK_SKEW_ALLOWANCE_HOURS, TOMBSTONE_MAX_AGE_HOURS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageID(Uuid);

impl MessageID {
    pub fn new() -> Self {
        MessageID(Uuid::new_v4())
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl From<Uuid> for MessageID {
    fn from(uuid: Uuid) -> Self {
        MessageID(uuid)
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

pub type RoutingKey = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
}

pub const CURRENT_VERSION: Version = Version { major: 0, minor: 2 };

/// Outer envelope for MIK-only encryption (Session V1-style stateless)
///
/// Each message includes an ephemeral X25519 public key. The sender:
/// 1. Generates ephemeral keypair (e, E)
/// 2. Computes shared_secret = X25519(e, recipient_MIK)
/// 3. Derives encryption key from shared_secret
/// 4. Encrypts InnerEnvelope with derived key
///
/// The recipient:
/// 1. Computes shared_secret = X25519(mik_private, ephemeral_key)
/// 2. Derives same encryption key
/// 3. Decrypts InnerEnvelope
#[derive(Debug, Clone, Encode, Decode)]
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

    pub inner_ciphertext: Vec<u8>,
}

impl OuterEnvelope {
    /// Create a new envelope for MIK-only encryption
    ///
    /// # Arguments
    /// * `routing_key` - 16-byte routing key (truncated blake3 hash of recipient PublicID)
    /// * `ephemeral_key` - 32-byte ephemeral X25519 public key used for ECDH
    /// * `inner_ciphertext` - Encrypted InnerEnvelope bytes
    /// * `ttl_hours` - Optional time-to-live in hours
    pub fn new(
        routing_key: RoutingKey,
        ephemeral_key: [u8; 32],
        inner_ciphertext: Vec<u8>,
        ttl_hours: Option<u16>,
    ) -> Self {
        Self {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: now_hours(),
            ttl_hours,
            message_id: MessageID::new(),
            ephemeral_key,
            inner_ciphertext,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::encode_to_vec(&self, bincode::config::standard()).unwrap()
    }
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct InnerEnvelope {
    pub version: Version,

    pub from: PublicID,

    pub to: PublicID,

    pub created_at_ms: u64,

    /// Echo of the message ID of the outer envelope.
    pub outer_message_id: MessageID,

    pub content: Content,

    /// XEdDSA signature over all preceding fields, proving sender authenticity.
    /// Signs: version || from || to || created_at_ms || outer_message_id || content
    pub sender_signature: [u8; 64],
}

impl InnerEnvelope {
    /// Returns the bytes that are covered by the sender signature.
    /// This is all fields except the signature itself.
    pub fn signable_bytes(&self) -> Vec<u8> {
        // Manually serialize all fields except signature
        let mut bytes = Vec::new();

        // version (4 bytes)
        bytes.extend_from_slice(&self.version.major.to_le_bytes());
        bytes.extend_from_slice(&self.version.minor.to_le_bytes());

        // from (32 bytes)
        bytes.extend_from_slice(&self.from.to_bytes());

        // to (32 bytes)
        bytes.extend_from_slice(&self.to.to_bytes());

        // created_at_ms (8 bytes)
        bytes.extend_from_slice(&self.created_at_ms.to_le_bytes());

        // outer_message_id (16 bytes)
        bytes.extend_from_slice(self.outer_message_id.as_bytes());

        // content - serialize with bincode for consistency
        let content_bytes =
            bincode::encode_to_vec(&self.content, bincode::config::standard()).unwrap();
        bytes.extend_from_slice(&content_bytes);

        bytes
    }

    /// Sign this envelope with the sender's private key.
    /// Returns the signature bytes.
    pub fn sign(signable_bytes: &[u8], sender_private: &[u8; 32]) -> [u8; 64] {
        use rand_core::OsRng;
        use xeddsa::{xed25519, Sign};

        let private_key = xed25519::PrivateKey(*sender_private);
        private_key.sign(signable_bytes, OsRng)
    }

    /// Verify that the sender_signature is valid for the from field.
    /// Returns true if the signature is valid.
    pub fn verify_sender_signature(&self) -> bool {
        use xeddsa::{xed25519, Verify};

        let public_key = xed25519::PublicKey(self.from.to_bytes());
        let signable = self.signable_bytes();

        public_key.verify(&signable, &self.sender_signature).is_ok()
    }
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
