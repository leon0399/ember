//! Wire format types for network transmission
//!
//! This module defines the unified wire format for messages and tombstones.
//! All payloads are prefixed with a 1-byte type discriminator to enable
//! multiplexing on the same transport.
//!
//! # Wire Format
//!
//! ```text
//! [type: u8][payload: bincode bytes]
//! ```
//!
//! Type discriminators:
//! - `0x00`: Message (OuterEnvelope)
//! - `0x02`: AckTombstone (SignedAckTombstone)

use strum::FromRepr;

use crate::tombstone::SignedAckTombstone;
use crate::{MessageID, OuterEnvelope, RoutingKey};

/// Wire payload type discriminator
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
pub enum WireType {
    Message = 0x00,
    /// Tombstone V2: Signed Ack (96 bytes)
    AckTombstone = 0x02,
}

/// Unified wire payload for messages and tombstones
///
/// Wire format: `[type: u8][payload: bincode bytes]`
/// - type 0x00: Message (OuterEnvelope)
/// - type 0x02: AckTombstone (SignedAckTombstone)
#[derive(Debug, Clone)]
pub enum WirePayload {
    Message(OuterEnvelope),
    /// Tombstone V2: Signed Ack
    AckTombstone(SignedAckTombstone),
}

impl WirePayload {
    /// Decode wire payload from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("Empty payload".to_string());
        }

        let wire_type = WireType::from_repr(bytes[0])
            .ok_or_else(|| format!("Unknown wire type: 0x{:02x}", bytes[0]))?;

        match wire_type {
            WireType::Message => {
                let (envelope, _): (OuterEnvelope, _) =
                    bincode::decode_from_slice(&bytes[1..], bincode::config::standard())
                        .map_err(|e| format!("Invalid message: {}", e))?;
                Ok(WirePayload::Message(envelope))
            }
            WireType::AckTombstone => {
                let (tombstone, _): (SignedAckTombstone, _) =
                    bincode::decode_from_slice(&bytes[1..], bincode::config::standard())
                        .map_err(|e| format!("Invalid ack tombstone: {}", e))?;
                Ok(WirePayload::AckTombstone(tombstone))
            }
        }
    }

    /// Encode wire payload to bytes
    pub fn encode(&self) -> Vec<u8> {
        match self {
            WirePayload::Message(envelope) => {
                let mut bytes = vec![WireType::Message as u8];
                bytes
                    .extend(bincode::encode_to_vec(envelope, bincode::config::standard()).unwrap());
                bytes
            }
            WirePayload::AckTombstone(tombstone) => {
                let mut bytes = vec![WireType::AckTombstone as u8];
                bytes.extend(
                    bincode::encode_to_vec(tombstone, bincode::config::standard()).unwrap(),
                );
                bytes
            }
        }
    }

    /// Get the routing key for this payload (only for Message)
    pub fn routing_key(&self) -> Option<&RoutingKey> {
        match self {
            WirePayload::Message(envelope) => Some(&envelope.routing_key),
            WirePayload::AckTombstone(_) => None, // V2 tombstones don't have routing_key
        }
    }

    /// Get the message_id for this payload
    pub fn message_id(&self) -> &MessageID {
        match self {
            WirePayload::Message(envelope) => &envelope.message_id,
            WirePayload::AckTombstone(tombstone) => &tombstone.message_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// Generate an X25519 keypair for testing
    fn generate_test_keypair() -> ([u8; 32], [u8; 32]) {
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let static_secret = StaticSecret::from(secret);
        let public = PublicKey::from(&static_secret);
        (*public.as_bytes(), secret)
    }

    #[test]
    fn test_wire_type_conversion() {
        assert_eq!(WireType::from_repr(0x00), Some(WireType::Message));
        assert_eq!(WireType::from_repr(0x02), Some(WireType::AckTombstone));
        assert_eq!(WireType::from_repr(0x01), None); // V1 tombstone type no longer supported
        assert_eq!(WireType::from_repr(0x03), None);
    }

    #[test]
    fn test_ack_tombstone_wire_payload_roundtrip() {
        let (_, priv_key) = generate_test_keypair();
        let message_id = MessageID::new();
        let ack_secret: [u8; 16] = [0x42; 16];

        let tombstone = SignedAckTombstone::new(message_id, ack_secret, &priv_key);
        let payload = WirePayload::AckTombstone(tombstone.clone());

        let bytes = payload.encode();
        let decoded = WirePayload::decode(&bytes).unwrap();

        match decoded {
            WirePayload::AckTombstone(restored) => {
                assert_eq!(restored.message_id, tombstone.message_id);
                assert_eq!(restored.ack_secret, tombstone.ack_secret);
            }
            _ => panic!("Expected AckTombstone"),
        }
    }
}
