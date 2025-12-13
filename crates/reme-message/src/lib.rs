use bincode::enc::Encoder;
use bincode::error::EncodeError;
use bincode::{impl_borrow_decode, Decode, Encode};
pub use reme_identity::PublicID;
use uuid::Uuid;

pub mod tombstone;
pub use tombstone::{
    DetailedReceipt, DeviceID, TombstoneEnvelope, TombstoneStatus, TombstoneValidationError,
    WirePayload, WireType, CLOCK_SKEW_ALLOWANCE_MS, TOMBSTONE_MAX_AGE_MS,
};

/// Session establishment data included in the first message from initiator
/// This allows the recipient to derive the same session keys
#[derive(Debug, Clone, Encode, Decode)]
pub struct SessionEstablishment {
    /// Sender's identity public key (32 bytes)
    pub sender_identity: [u8; 32],
    /// Sender's ephemeral public key used in X3DH (32 bytes)
    pub ephemeral_public: [u8; 32],
    /// ID of the one-time prekey used (if any)
    pub used_one_time_prekey_id: Option<[u8; 16]>,
}

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

pub const CURRENT_VERSION: Version = Version { major: 0, minor: 1 };

/// Flags for OuterEnvelope
pub mod flags {
    /// Message contains session establishment data
    pub const SESSION_INIT: u8 = 0x01;
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct OuterEnvelope {
    pub version: Version,

    /// Flags indicating special message properties
    /// - 0x01: SESSION_INIT - contains session establishment data
    pub flags: u8,

    pub routing_key: RoutingKey,

    pub created_at_ms: Option<u64>,

    pub ttl: Option<u32>,

    pub message_id: MessageID,

    /// Session establishment data (present when flags & SESSION_INIT)
    /// This is sent in the first message to allow recipient to derive session keys
    pub session_init: Option<SessionEstablishment>,

    pub inner_ciphertext: Vec<u8>,
}

impl OuterEnvelope {
    pub fn new(routing_key: RoutingKey, inner_ciphertext: Vec<u8>, ttl: Option<u32>) -> Self {
        Self {
            version: CURRENT_VERSION,
            flags: 0,
            routing_key,
            created_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_millis() as u64),
            ttl,
            message_id: MessageID::new(),
            session_init: None,
            inner_ciphertext,
        }
    }

    /// Create an envelope with session establishment data (for first message)
    pub fn with_session_init(
        routing_key: RoutingKey,
        inner_ciphertext: Vec<u8>,
        ttl: Option<u32>,
        session_init: SessionEstablishment,
    ) -> Self {
        Self {
            version: CURRENT_VERSION,
            flags: flags::SESSION_INIT,
            routing_key,
            created_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_millis() as u64),
            ttl,
            message_id: MessageID::new(),
            session_init: Some(session_init),
            inner_ciphertext,
        }
    }

    /// Check if this message contains session establishment data
    pub fn has_session_init(&self) -> bool {
        self.flags & flags::SESSION_INIT != 0
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
