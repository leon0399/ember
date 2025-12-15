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
    pub major: u8,
    pub minor: u8,
}

/// Current protocol version (0.0 - PoC)
/// Using u8 for major/minor: max version 255.255, saves 2 bytes per envelope
pub const CURRENT_VERSION: Version = Version { major: 0, minor: 0 };

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
    /// * `ttl_hours` - Optional time-to-live in hours
    /// * `ephemeral_key` - 32-byte ephemeral X25519 public key used for ECDH
    /// * `inner_ciphertext` - Encrypted InnerEnvelope bytes
    pub fn new(
        routing_key: RoutingKey,
        ttl_hours: Option<u16>,
        ephemeral_key: [u8; 32],
        inner_ciphertext: Vec<u8>,
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

/// Signature type alias for clarity
pub type Signature = [u8; 64];

#[derive(Debug, Clone, Encode, Decode)]
pub struct InnerEnvelope {
    /// Sender's public identity (32 bytes)
    pub from: PublicID,

    /// Precise timestamp in milliseconds since Unix epoch
    /// (outer envelope has coarse hour-granularity for metadata privacy)
    pub created_at_ms: u64,

    /// Message content
    pub content: Content,

    /// XEdDSA signature proving sender authenticity (optional for future session messages)
    /// Signs: from || created_at_ms || content || outer_message_id (from outer envelope)
    ///
    /// Currently always Some (MIK-only encryption requires signature).
    /// Will be None for session-encrypted messages where ECDH provides authentication.
    pub signature: Option<Signature>,
}

// Removed fields (per envelope optimization design):
// - version: Use outer envelope version
// - to: Cryptographically bound via sealed box ECDH (only intended recipient can decrypt)
// - outer_message_id: Bound via AAD + nonce derivation (triple binding)

impl InnerEnvelope {
    /// Returns the bytes that are covered by the sender signature.
    ///
    /// The outer_message_id is passed as a parameter (not stored in InnerEnvelope)
    /// to enable triple binding: the signature binds the inner content to the outer
    /// message_id without duplicating it in the wire format.
    pub fn signable_bytes(&self, outer_message_id: &MessageID) -> Vec<u8> {
        let mut bytes = Vec::new();

        // from (32 bytes)
        bytes.extend_from_slice(&self.from.to_bytes());

        // created_at_ms (8 bytes)
        bytes.extend_from_slice(&self.created_at_ms.to_le_bytes());

        // content - serialize with bincode for consistency
        let content_bytes =
            bincode::encode_to_vec(&self.content, bincode::config::standard()).unwrap();
        bytes.extend_from_slice(&content_bytes);

        // outer_message_id (16 bytes) - binds signature to outer envelope
        bytes.extend_from_slice(outer_message_id.as_bytes());

        bytes
    }

    /// Sign this envelope with the sender's private key.
    /// Returns the signature bytes.
    pub fn sign(signable_bytes: &[u8], sender_private: &[u8; 32]) -> Signature {
        use rand_core::OsRng;
        use xeddsa::{xed25519, Sign};

        let private_key = xed25519::PrivateKey(*sender_private);
        private_key.sign(signable_bytes, OsRng)
    }

    /// Verify that the signature is valid for the sender (from field).
    ///
    /// The outer_message_id must be provided to verify the binding between
    /// inner content and outer envelope.
    ///
    /// Returns true if signature is present and valid, false otherwise.
    pub fn verify_signature(&self, outer_message_id: &MessageID) -> bool {
        use xeddsa::{xed25519, Verify};

        match &self.signature {
            Some(sig) => {
                let public_key = xed25519::PublicKey(self.from.to_bytes());
                let signable = self.signable_bytes(outer_message_id);
                public_key.verify(&signable, sig).is_ok()
            }
            None => false, // No signature present
        }
    }

    /// Check if this envelope has a signature.
    pub fn has_signature(&self) -> bool {
        self.signature.is_some()
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
