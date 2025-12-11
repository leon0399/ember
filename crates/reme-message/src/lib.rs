use bincode::enc::Encoder;
use bincode::error::{DecodeError, EncodeError};
use bincode::{impl_borrow_decode, Decode, Encode};
use bincode::de::BorrowDecoder;
pub use reme_identity::PublicID;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageID(Uuid);

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

#[derive(Debug, Clone, Encode, Decode)]
pub struct OuterEnvelope {
    pub version: Version,

    pub flags: u8,

    pub routing_key: RoutingKey,

    pub created_at: Option<u64>,

    pub ttl: Option<u32>,

    pub message_id: MessageID,

    pub inner_ciphertext: Vec<u8>,
}

impl OuterEnvelope {
    pub fn new(routing_key: RoutingKey, inner_ciphertext: Vec<u8>, ttl: Option<u32>) -> Self {
        Self {
            version: CURRENT_VERSION,
            flags: 0,
            routing_key,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs()),
            ttl,
            message_id: MessageID(Uuid::new_v4()),
            inner_ciphertext,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::encode_to_vec(&self, bincode::config::standard()).unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct InnerEnvelope {
    pub version: Version,

    pub from: PublicID,

    pub to: PublicID,

    pub created_at: u64,

    /// Echo of the message ID of the outer envelope.
    pub outer_message_id: MessageID,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Content {
    Text(TextContent),
    Receipt(ReceiptContent),
}

#[derive(Debug, Clone)]
pub struct TextContent {
    /// UTF-8 encoded.
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct ReceiptContent {
    pub target_message_id: MessageID,
    pub kind: ReceiptKind,
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum ReceiptKind {
    Delivered,
    Read,
}
