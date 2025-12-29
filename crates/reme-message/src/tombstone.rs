//! Cryptographically authenticated tombstones for message acknowledgment
//!
//! Tombstones serve dual purposes:
//! 1. **Network-layer**: Enable cache clearing and prevent duplicate delivery
//! 2. **Application-layer**: Optional read receipts for user-facing delivery confirmation
//!
//! # Wire Format
//!
//! Tombstones are transmitted with a 1-byte type discriminator (0x02) to distinguish
//! them from regular messages (0x00) on the same transport.
//!
//! # Security Properties
//!
//! - **Authorization**: Nodes verify hash(ack_secret) == ack_hash (O(1))
//! - **Attribution**: Signature allows clients to verify who acknowledged
//! - **Privacy**: No identity in wire format (nodes don't know sender/recipient)
//! - **Replay prevention**: message_id binding in ack_secret derivation

use crate::wire::WireType;
use crate::MessageID;
use bincode::{Decode, Encode};
use subtle::ConstantTimeEq;
use xeddsa::{xed25519, Sign, Verify};

/// Maximum age for tombstone validation (10 days in hours)
pub const TOMBSTONE_MAX_AGE_HOURS: u32 = 10 * 24;

/// Domain string for ack_hash derivation.
/// Used for domain separation in KDFs to prevent cross-protocol confusion.
pub const ACK_HASH_DOMAIN: &str = "reme-ack-hash-v1";

/// Clock skew allowance (1 hour)
/// Since we use hour granularity, 1 hour allowance handles clock drift.
pub const CLOCK_SKEW_ALLOWANCE_HOURS: u32 = 1;

// ============================================
// Tombstone V2: Signed Ack Tombstone
// ============================================

/// Signed Ack Tombstone (V2) - 96 bytes total
///
/// A lightweight tombstone that proves the creator knows the ack_secret
/// derived from the ECDH shared secret. Both sender and recipient can
/// create valid tombstones without leaking identity.
///
/// # Security Properties
///
/// - **Authorization**: Node verifies hash(ack_secret) == ack_hash (O(1))
/// - **Attribution**: Signature allows clients to verify who acknowledged
/// - **Privacy**: No identity in wire format (nodes don't know sender/recipient)
/// - **Replay prevention**: message_id binding in ack_secret derivation
///
/// # Wire Format
///
/// ```text
/// message_id:  16 bytes (UUID)
/// ack_secret:  16 bytes (truncated BLAKE3 KDF output)
/// signature:   64 bytes (XEdDSA)
/// Total:       96 bytes
/// ```
#[derive(Debug, Clone, Encode, Decode)]
pub struct SignedAckTombstone {
    /// ID of the message being acknowledged
    pub message_id: MessageID,

    /// Ack secret derived from ECDH shared secret + message_id
    /// ack_secret = BLAKE3_KDF("reme-ack-v1", shared_secret || message_id)[0..16]
    pub ack_secret: [u8; 16],

    /// XEdDSA signature over (message_id || ack_secret)
    /// Signed by sender or recipient's X25519 private key
    pub signature: [u8; 64],
}

/// Who created a tombstone (for delivery confirmation)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribution {
    /// Tombstone was signed by the message sender
    Sender,
    /// Tombstone was signed by the message recipient
    Recipient,
    /// Signature doesn't match either party
    Invalid,
}

impl SignedAckTombstone {
    /// Create a new signed ack tombstone
    ///
    /// # Arguments
    /// * `message_id` - ID of the message being acknowledged
    /// * `ack_secret` - 16-byte secret derived from ECDH shared secret
    /// * `signer_private` - X25519 private key for signing (sender or recipient)
    pub fn new(
        message_id: MessageID,
        ack_secret: [u8; 16],
        signer_private: &[u8; 32],
    ) -> Self {
        use rand_core::OsRng;

        let mut tombstone = Self {
            message_id,
            ack_secret,
            signature: [0u8; 64],
        };

        let signable = tombstone.signable_bytes();
        let xed_private = xed25519::PrivateKey(*signer_private);
        tombstone.signature = xed_private.sign(&signable, OsRng);

        tombstone
    }

    /// Bytes covered by signature: message_id || ack_secret
    fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(self.message_id.as_bytes());
        bytes.extend_from_slice(&self.ack_secret);
        bytes
    }

    /// Verify tombstone is authorized (for nodes).
    ///
    /// Nodes verify that hash(ack_secret) matches the ack_hash stored with
    /// the message. This is O(1) and doesn't require knowing the sender or
    /// recipient's public key.
    ///
    /// Uses:
    /// - Domain-separated derivation: BLAKE3_KDF("reme-ack-hash-v1", ack_secret)
    /// - Constant-time comparison to prevent timing side-channel attacks
    pub fn verify_authorization(&self, expected_ack_hash: &[u8; 16]) -> bool {
        let derived = blake3::derive_key(ACK_HASH_DOMAIN, &self.ack_secret);
        derived[..16].ct_eq(expected_ack_hash).into()
    }

    /// Verify signature and determine who created the tombstone.
    ///
    /// Clients use this to determine if the recipient actually acknowledged
    /// the message (delivery confirmation) or if the sender retracted it.
    pub fn verify_attribution(
        &self,
        sender_pub: &[u8; 32],
        recipient_pub: &[u8; 32],
    ) -> Attribution {
        let signable = self.signable_bytes();

        // Try recipient first (most common for delivery confirmation)
        let recipient_xed = xed25519::PublicKey(*recipient_pub);
        if recipient_xed.verify(&signable, &self.signature).is_ok() {
            return Attribution::Recipient;
        }

        // Try sender
        let sender_xed = xed25519::PublicKey(*sender_pub);
        if sender_xed.verify(&signable, &self.signature).is_ok() {
            return Attribution::Sender;
        }

        Attribution::Invalid
    }

    /// Serialize to bytes with wire type prefix (0x02)
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![WireType::AckTombstone as u8];
        bytes.extend(bincode::encode_to_vec(self, bincode::config::standard()).unwrap());
        bytes
    }

    /// Serialize to bytes without wire type prefix
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard()).unwrap()
    }

    /// Deserialize from bytes (without wire type prefix)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (tombstone, _): (SignedAckTombstone, _) =
            bincode::decode_from_slice(bytes, bincode::config::standard())
                .map_err(|e| format!("Failed to decode ack tombstone: {}", e))?;
        Ok(tombstone)
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

    /// Helper function to derive ack_hash from ack_secret (mirrors internal logic)
    fn derive_ack_hash_for_test(ack_secret: &[u8; 16]) -> [u8; 16] {
        let derived = blake3::derive_key(ACK_HASH_DOMAIN, ack_secret);
        derived[..16].try_into().unwrap()
    }

    #[test]
    fn test_ack_hash_verification_success() {
        let (_, priv_key) = generate_test_keypair();
        let message_id = MessageID::new();
        let ack_secret: [u8; 16] = [0x42; 16];

        let tombstone = SignedAckTombstone::new(message_id, ack_secret, &priv_key);
        let expected_hash = derive_ack_hash_for_test(&ack_secret);

        assert!(
            tombstone.verify_authorization(&expected_hash),
            "Authorization should pass with correct ack_hash"
        );
    }

    #[test]
    fn test_ack_hash_verification_failure() {
        let (_, priv_key) = generate_test_keypair();
        let message_id = MessageID::new();
        let ack_secret: [u8; 16] = [0x42; 16];
        let wrong_hash: [u8; 16] = [0xDE; 16];

        let tombstone = SignedAckTombstone::new(message_id, ack_secret, &priv_key);

        assert!(
            !tombstone.verify_authorization(&wrong_hash),
            "Authorization should fail with wrong ack_hash"
        );
    }

    #[test]
    fn test_ack_hash_deterministic() {
        let ack_secret: [u8; 16] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

        let hash1 = derive_ack_hash_for_test(&ack_secret);
        let hash2 = derive_ack_hash_for_test(&ack_secret);

        assert_eq!(hash1, hash2, "Same ack_secret should produce same ack_hash");
    }

    #[test]
    fn test_ack_hash_different_secrets_produce_different_hashes() {
        let secret1: [u8; 16] = [0x11; 16];
        let secret2: [u8; 16] = [0x22; 16];

        let hash1 = derive_ack_hash_for_test(&secret1);
        let hash2 = derive_ack_hash_for_test(&secret2);

        assert_ne!(hash1, hash2, "Different ack_secrets should produce different ack_hashes");
    }

    #[test]
    fn test_signature_attribution_sender() {
        let (sender_pub, sender_priv) = generate_test_keypair();
        let (recipient_pub, _) = generate_test_keypair();
        let message_id = MessageID::new();
        let ack_secret: [u8; 16] = [0x42; 16];

        let tombstone = SignedAckTombstone::new(message_id, ack_secret, &sender_priv);

        assert_eq!(
            tombstone.verify_attribution(&sender_pub, &recipient_pub),
            Attribution::Sender,
            "Attribution should identify sender"
        );
    }

    #[test]
    fn test_signature_attribution_recipient() {
        let (sender_pub, _) = generate_test_keypair();
        let (recipient_pub, recipient_priv) = generate_test_keypair();
        let message_id = MessageID::new();
        let ack_secret: [u8; 16] = [0x42; 16];

        let tombstone = SignedAckTombstone::new(message_id, ack_secret, &recipient_priv);

        assert_eq!(
            tombstone.verify_attribution(&sender_pub, &recipient_pub),
            Attribution::Recipient,
            "Attribution should identify recipient"
        );
    }

    #[test]
    fn test_signature_attribution_invalid() {
        let (sender_pub, _) = generate_test_keypair();
        let (recipient_pub, _) = generate_test_keypair();
        let (_, mallory_priv) = generate_test_keypair();
        let message_id = MessageID::new();
        let ack_secret: [u8; 16] = [0x42; 16];

        let tombstone = SignedAckTombstone::new(message_id, ack_secret, &mallory_priv);

        assert_eq!(
            tombstone.verify_attribution(&sender_pub, &recipient_pub),
            Attribution::Invalid,
            "Attribution should be Invalid for unknown signer"
        );
    }

    #[test]
    fn test_ack_tombstone_wire_roundtrip() {
        let (_, priv_key) = generate_test_keypair();
        let message_id = MessageID::new();
        let ack_secret: [u8; 16] = [0x42; 16];

        let original = SignedAckTombstone::new(message_id, ack_secret, &priv_key);

        let bytes = original.to_wire_bytes();
        assert_eq!(bytes[0], 0x02, "Wire type should be AckTombstone (0x02)");

        let restored = SignedAckTombstone::from_bytes(&bytes[1..]).unwrap();

        assert_eq!(restored.message_id, original.message_id);
        assert_eq!(restored.ack_secret, original.ack_secret);
        assert_eq!(restored.signature, original.signature);

        let expected_hash = derive_ack_hash_for_test(&ack_secret);
        assert!(restored.verify_authorization(&expected_hash));
    }

    #[test]
    fn test_ack_tombstone_size() {
        let (_, priv_key) = generate_test_keypair();
        let message_id = MessageID::new();
        let ack_secret: [u8; 16] = [0x42; 16];

        let tombstone = SignedAckTombstone::new(message_id, ack_secret, &priv_key);
        let bytes = tombstone.to_bytes();

        // SignedAckTombstone should be 96 bytes
        assert_eq!(bytes.len(), 96, "SignedAckTombstone should be exactly 96 bytes");
    }

}
