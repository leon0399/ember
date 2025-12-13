//! Cryptographically authenticated tombstones for message acknowledgment
//!
//! Tombstones serve dual purposes:
//! 1. **Network-layer**: Enable cache clearing and prevent duplicate delivery
//! 2. **Application-layer**: Optional read receipts for user-facing delivery confirmation
//!
//! # Wire Format
//!
//! Tombstones are transmitted with a 1-byte type discriminator (0x01) to distinguish
//! them from regular messages (0x00) on the same transport.
//!
//! # Security Properties
//!
//! - **Authentication**: Signed by recipient's Ed25519 identity key
//! - **Replay prevention**: Timestamp + sequence + device_id in signature
//! - **Privacy**: Coarse timestamp (hour granularity), optional encrypted receipt

use crate::{MessageID, RoutingKey, Version, CURRENT_VERSION};
use bincode::{Decode, Encode};
use xeddsa::{xed25519, Sign, Verify};

/// Maximum age for tombstone validation (10 days in milliseconds)
pub const TOMBSTONE_MAX_AGE_MS: i64 = 10 * 24 * 60 * 60 * 1000;

/// Clock skew allowance (5 minutes in milliseconds)
pub const CLOCK_SKEW_ALLOWANCE_MS: i64 = 5 * 60 * 1000;

/// One hour in milliseconds
const HOUR_MS: i64 = 60 * 60 * 1000;

/// Device identifier for multi-device sequence management
pub type DeviceID = [u8; 16];

/// Tombstone status indicating how message was processed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum TombstoneStatus {
    /// Message arrived at recipient's device
    Delivered = 0,
    /// User explicitly opened/read the message (opt-in)
    Read = 1,
    /// Message deleted without reading
    Deleted = 2,
}

/// Cryptographically authenticated tombstone envelope
///
/// Proves that the recipient (holder of `recipient_id_pub`) has processed
/// the message identified by `target_message_id`. Any node can verify the
/// signature to confirm authenticity without being able to decrypt the message.
///
/// # Two-Layer Design
///
/// - **Public layer**: Visible to all relays/caches for verification and cache clearing
/// - **Encrypted layer**: Optional detailed receipt only the sender can decrypt
#[derive(Debug, Clone, Encode, Decode)]
pub struct TombstoneEnvelope {
    /// Protocol version for forward compatibility
    pub version: Version,

    /// ID of the message being acknowledged
    pub target_message_id: MessageID,

    /// Routing key where the message was stored
    pub routing_key: RoutingKey,

    /// Recipient's identity public key (for signature verification)
    pub recipient_id_pub: [u8; 32],

    /// Device identifier (enables per-device sequence numbers)
    pub device_id: DeviceID,

    /// Coarse timestamp (rounded to hour) - limits timing analysis
    /// Also included in signature to prevent replay attacks
    pub coarse_timestamp: i64,

    /// Monotonically increasing sequence number per device
    pub sequence: u64,

    /// Ed25519 signature over signable_bytes()
    pub signature: [u8; 64],

    /// Optional encrypted receipt for sender (contains precise details)
    pub encrypted_receipt: Option<Vec<u8>>,
}

/// Decrypted content of encrypted_receipt (only sender can read)
#[derive(Debug, Clone, Encode, Decode)]
pub struct DetailedReceipt {
    /// Precise timestamp when message was processed
    pub precise_timestamp: i64,

    /// Actual status (Delivered/Read/Deleted)
    pub status: TombstoneStatus,

    /// HMAC proving recipient decrypted the message content
    /// proof = BLAKE3-keyed(session_recv_key, inner_ciphertext)
    pub proof_of_content: Option<[u8; 32]>,
}

/// Tombstone validation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TombstoneValidationError {
    InvalidSignature,
    TimestampInFuture,
    TimestampTooOld,
    SequenceNotMonotonic,
    RateLimitExceeded,
}

impl std::fmt::Display for TombstoneValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "Invalid tombstone signature"),
            Self::TimestampInFuture => write!(f, "Tombstone timestamp is in the future"),
            Self::TimestampTooOld => write!(f, "Tombstone timestamp is too old"),
            Self::SequenceNotMonotonic => write!(f, "Sequence number is not monotonic"),
            Self::RateLimitExceeded => write!(f, "Rate limit exceeded for this recipient"),
        }
    }
}

impl std::error::Error for TombstoneValidationError {}

impl TombstoneEnvelope {
    /// Create a new tombstone for a received message
    ///
    /// # Arguments
    ///
    /// * `target_message_id` - ID of the message being acknowledged
    /// * `routing_key` - Routing key where the message was stored
    /// * `recipient_id_pub` - Recipient's Ed25519 public key
    /// * `recipient_secret` - Recipient's Ed25519 private key (for signing)
    /// * `device_id` - This device's unique identifier
    /// * `sequence` - Monotonically increasing sequence number for this device
    /// * `status` - How the message was processed (Delivered/Read/Deleted)
    /// * `sender_pub` - Sender's X25519 public key (for encrypted receipt)
    /// * `session_recv_key` - Session receive key (for proof of content)
    /// * `inner_ciphertext` - The encrypted message content (for proof generation)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_message_id: MessageID,
        routing_key: RoutingKey,
        recipient_id_pub: [u8; 32],
        recipient_secret: &[u8; 32],
        device_id: DeviceID,
        sequence: u64,
        status: TombstoneStatus,
        sender_pub: Option<&[u8; 32]>,
        session_recv_key: Option<&[u8; 32]>,
        inner_ciphertext: Option<&[u8]>,
    ) -> Self {
        let precise_timestamp = Self::now_ms();
        let coarse_timestamp = Self::coarsen_timestamp(precise_timestamp);

        let mut tombstone = TombstoneEnvelope {
            version: CURRENT_VERSION,
            target_message_id,
            routing_key,
            recipient_id_pub,
            device_id,
            coarse_timestamp,
            sequence,
            signature: [0u8; 64],
            encrypted_receipt: None,
        };

        // Sign the public portion
        tombstone.signature = tombstone.sign(recipient_secret);

        // Optionally create encrypted receipt for sender
        if let (Some(sender_pub), Some(session_key)) = (sender_pub, session_recv_key) {
            let proof = inner_ciphertext.map(|ct| Self::generate_proof_of_content(session_key, ct));

            let detailed = DetailedReceipt {
                precise_timestamp,
                status,
                proof_of_content: proof,
            };

            tombstone.encrypted_receipt = Some(Self::encrypt_receipt(&detailed, sender_pub));
        }

        tombstone
    }

    /// Create a simple tombstone without encrypted receipt
    ///
    /// This is a convenience method for when you don't need the sender
    /// to receive detailed receipt information.
    pub fn new_simple(
        target_message_id: MessageID,
        routing_key: RoutingKey,
        recipient_id_pub: [u8; 32],
        recipient_secret: &[u8; 32],
        device_id: DeviceID,
        sequence: u64,
    ) -> Self {
        Self::new(
            target_message_id,
            routing_key,
            recipient_id_pub,
            recipient_secret,
            device_id,
            sequence,
            TombstoneStatus::Delivered,
            None,
            None,
            None,
        )
    }

    /// Round timestamp to hour boundary (privacy protection)
    pub fn coarsen_timestamp(precise_ms: i64) -> i64 {
        (precise_ms / HOUR_MS) * HOUR_MS
    }

    /// Get current time in milliseconds since Unix epoch
    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Sign the tombstone with recipient's X25519 private key using XEdDSA
    ///
    /// XEdDSA produces Ed25519-compatible signatures from X25519 keys.
    fn sign(&self, secret_key: &[u8; 32]) -> [u8; 64] {
        use rand_core::OsRng;
        let xed_private = xed25519::PrivateKey(*secret_key);
        let message = self.signable_bytes();
        xed_private.sign(&message, OsRng)
    }

    /// Verify the tombstone signature using XEdDSA
    ///
    /// The recipient_id_pub is an X25519 public key, which is converted
    /// to Ed25519 internally for signature verification.
    pub fn verify_signature(&self) -> bool {
        let xed_public = xed25519::PublicKey(self.recipient_id_pub);
        let message = self.signable_bytes();
        xed_public.verify(&message, &self.signature).is_ok()
    }

    /// Full validation: signature + timestamp freshness
    ///
    /// This should be called by nodes before accepting a tombstone.
    pub fn validate(&self) -> Result<(), TombstoneValidationError> {
        // 1. Verify signature
        if !self.verify_signature() {
            return Err(TombstoneValidationError::InvalidSignature);
        }

        // 2. Check timestamp freshness
        let now = Self::now_ms();

        if self.coarse_timestamp > now + CLOCK_SKEW_ALLOWANCE_MS {
            return Err(TombstoneValidationError::TimestampInFuture);
        }

        if now - self.coarse_timestamp > TOMBSTONE_MAX_AGE_MS {
            return Err(TombstoneValidationError::TimestampTooOld);
        }

        Ok(())
    }

    /// Bytes that are signed
    ///
    /// Format: version || target_message_id || routing_key || device_id || coarse_timestamp || sequence
    fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.version.major.to_le_bytes());
        bytes.extend_from_slice(&self.version.minor.to_le_bytes());
        bytes.extend_from_slice(self.target_message_id.as_bytes());
        bytes.extend_from_slice(&self.routing_key);
        bytes.extend_from_slice(&self.device_id);
        bytes.extend_from_slice(&self.coarse_timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes
    }

    /// Generate HMAC proof that recipient decrypted the message
    fn generate_proof_of_content(session_recv_key: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
        let key = blake3::derive_key("tombstone-proof-v1", session_recv_key);
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(ciphertext);
        *hasher.finalize().as_bytes()
    }

    /// Encrypt detailed receipt for sender using X25519 + ChaCha20-Poly1305
    fn encrypt_receipt(receipt: &DetailedReceipt, sender_pub: &[u8; 32]) -> Vec<u8> {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
        use rand::RngCore;
        use x25519_dalek::{PublicKey, StaticSecret};

        let plaintext = bincode::encode_to_vec(receipt, bincode::config::standard()).unwrap();

        // Generate ephemeral keypair
        let mut ephemeral_secret_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut ephemeral_secret_bytes);
        let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Derive shared secret
        let sender_x25519 = PublicKey::from(*sender_pub);
        let shared_secret = ephemeral_secret.diffie_hellman(&sender_x25519);

        // Derive encryption key
        let enc_key = blake3::derive_key("tombstone-receipt-v1", shared_secret.as_bytes());

        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new((&enc_key).into());
        let nonce = [0u8; 12]; // OK because key is unique per tombstone
        let ciphertext = cipher
            .encrypt((&nonce).into(), plaintext.as_slice())
            .unwrap();

        // Prepend ephemeral public key
        let mut result = Vec::with_capacity(32 + ciphertext.len());
        result.extend_from_slice(ephemeral_public.as_bytes());
        result.extend_from_slice(&ciphertext);
        result
    }

    /// Sender decrypts the detailed receipt
    ///
    /// # Arguments
    ///
    /// * `sender_secret` - Sender's X25519 private key
    ///
    /// # Returns
    ///
    /// The decrypted `DetailedReceipt` if successful, None otherwise.
    pub fn decrypt_receipt(&self, sender_secret: &[u8; 32]) -> Option<DetailedReceipt> {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
        use x25519_dalek::{PublicKey, StaticSecret};

        let encrypted = self.encrypted_receipt.as_ref()?;
        if encrypted.len() < 33 {
            return None;
        }

        let ephemeral_pub: [u8; 32] = encrypted[..32].try_into().ok()?;
        let ciphertext = &encrypted[32..];

        // Derive shared secret
        let sender_x25519 = StaticSecret::from(*sender_secret);
        let ephemeral = PublicKey::from(ephemeral_pub);
        let shared_secret = sender_x25519.diffie_hellman(&ephemeral);

        // Derive decryption key
        let dec_key = blake3::derive_key("tombstone-receipt-v1", shared_secret.as_bytes());

        // Decrypt
        let cipher = ChaCha20Poly1305::new((&dec_key).into());
        let nonce = [0u8; 12];
        let plaintext = cipher.decrypt((&nonce).into(), ciphertext).ok()?;

        let (receipt, _): (DetailedReceipt, _) =
            bincode::decode_from_slice(&plaintext, bincode::config::standard()).ok()?;

        Some(receipt)
    }

    /// Serialize to bytes with wire type prefix
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0x01]; // Tombstone type discriminator
        bytes.extend(bincode::encode_to_vec(self, bincode::config::standard()).unwrap());
        bytes
    }

    /// Serialize to bytes without wire type prefix
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard()).unwrap()
    }

    /// Deserialize from bytes (without wire type prefix)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (tombstone, _): (TombstoneEnvelope, _) =
            bincode::decode_from_slice(bytes, bincode::config::standard())
                .map_err(|e| format!("Failed to decode tombstone: {}", e))?;
        Ok(tombstone)
    }
}

/// Wire payload type discriminator
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    Message = 0x00,
    Tombstone = 0x01,
}

impl TryFrom<u8> for WireType {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(WireType::Message),
            0x01 => Ok(WireType::Tombstone),
            _ => Err(format!("Unknown wire type: 0x{:02x}", value)),
        }
    }
}

use crate::OuterEnvelope;

/// Unified wire payload for messages and tombstones
///
/// Wire format: `[type: u8][payload: bincode bytes]`
/// - type 0x00: Message (OuterEnvelope)
/// - type 0x01: Tombstone (TombstoneEnvelope)
#[derive(Debug, Clone)]
pub enum WirePayload {
    Message(OuterEnvelope),
    Tombstone(TombstoneEnvelope),
}

impl WirePayload {
    /// Decode wire payload from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("Empty payload".to_string());
        }

        let wire_type = WireType::try_from(bytes[0])?;

        match wire_type {
            WireType::Message => {
                let (envelope, _): (OuterEnvelope, _) =
                    bincode::decode_from_slice(&bytes[1..], bincode::config::standard())
                        .map_err(|e| format!("Invalid message: {}", e))?;
                Ok(WirePayload::Message(envelope))
            }
            WireType::Tombstone => {
                let (tombstone, _): (TombstoneEnvelope, _) =
                    bincode::decode_from_slice(&bytes[1..], bincode::config::standard())
                        .map_err(|e| format!("Invalid tombstone: {}", e))?;
                Ok(WirePayload::Tombstone(tombstone))
            }
        }
    }

    /// Encode wire payload to bytes
    pub fn encode(&self) -> Vec<u8> {
        match self {
            WirePayload::Message(envelope) => {
                let mut bytes = vec![WireType::Message as u8];
                bytes.extend(bincode::encode_to_vec(envelope, bincode::config::standard()).unwrap());
                bytes
            }
            WirePayload::Tombstone(tombstone) => {
                let mut bytes = vec![WireType::Tombstone as u8];
                bytes.extend(bincode::encode_to_vec(tombstone, bincode::config::standard()).unwrap());
                bytes
            }
        }
    }

    /// Get the routing key for this payload
    pub fn routing_key(&self) -> &[u8; 16] {
        match self {
            WirePayload::Message(envelope) => &envelope.routing_key,
            WirePayload::Tombstone(tombstone) => &tombstone.routing_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// Generate an X25519 keypair for testing
    ///
    /// Returns (public_key, secret_key) where both are 32 bytes.
    /// The secret key can be used with XEdDSA for signing.
    fn generate_test_keypair() -> ([u8; 32], [u8; 32]) {
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let static_secret = StaticSecret::from(secret);
        let public = PublicKey::from(&static_secret);
        (*public.as_bytes(), secret)
    }

    /// Alias for generate_test_keypair (both generate X25519 keypairs)
    fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
        generate_test_keypair()
    }

    #[test]
    fn test_tombstone_signature_roundtrip() {
        let (pub_key, priv_key) = generate_test_keypair();
        let message_id = MessageID::new();
        let device_id = [0u8; 16];

        let tombstone = TombstoneEnvelope::new_simple(
            message_id, [0u8; 16], pub_key, &priv_key, device_id, 1,
        );

        assert!(tombstone.verify_signature());
        assert!(tombstone.validate().is_ok());
    }

    #[test]
    fn test_tombstone_tamper_detection() {
        let (pub_key, priv_key) = generate_test_keypair();
        let device_id = [0u8; 16];

        let tombstone = TombstoneEnvelope::new_simple(
            MessageID::new(),
            [0u8; 16],
            pub_key,
            &priv_key,
            device_id,
            1,
        );

        // Tamper with sequence
        let mut tampered = tombstone.clone();
        tampered.sequence += 1;
        assert!(!tampered.verify_signature());

        // Tamper with routing key
        let mut tampered2 = tombstone.clone();
        tampered2.routing_key[0] ^= 0xFF;
        assert!(!tampered2.verify_signature());

        // Tamper with device_id
        let mut tampered3 = tombstone.clone();
        tampered3.device_id[0] ^= 0xFF;
        assert!(!tampered3.verify_signature());
    }

    #[test]
    fn test_tombstone_timestamp_validation() {
        let (pub_key, priv_key) = generate_test_keypair();
        let device_id = [0u8; 16];

        // Create a fresh tombstone
        let tombstone = TombstoneEnvelope::new_simple(
            MessageID::new(),
            [0u8; 16],
            pub_key,
            &priv_key,
            device_id,
            1,
        );
        assert!(tombstone.validate().is_ok());

        // Manually create one with old timestamp
        let mut old_tombstone = TombstoneEnvelope {
            version: CURRENT_VERSION,
            target_message_id: MessageID::new(),
            routing_key: [0u8; 16],
            recipient_id_pub: pub_key,
            device_id,
            coarse_timestamp: TombstoneEnvelope::now_ms() - 11 * 24 * 60 * 60 * 1000, // 11 days ago
            sequence: 1,
            signature: [0u8; 64],
            encrypted_receipt: None,
        };
        old_tombstone.signature = old_tombstone.sign(&priv_key);

        assert!(old_tombstone.verify_signature()); // Signature is valid
        assert_eq!(
            old_tombstone.validate(),
            Err(TombstoneValidationError::TimestampTooOld)
        );
    }

    #[test]
    fn test_tombstone_future_timestamp_rejected() {
        let (pub_key, priv_key) = generate_test_keypair();
        let device_id = [0u8; 16];

        // Create tombstone with future timestamp (beyond clock skew allowance)
        let mut future_tombstone = TombstoneEnvelope {
            version: CURRENT_VERSION,
            target_message_id: MessageID::new(),
            routing_key: [0u8; 16],
            recipient_id_pub: pub_key,
            device_id,
            coarse_timestamp: TombstoneEnvelope::now_ms() + 10 * 60 * 1000, // 10 mins in future
            sequence: 1,
            signature: [0u8; 64],
            encrypted_receipt: None,
        };
        future_tombstone.signature = future_tombstone.sign(&priv_key);

        assert!(future_tombstone.verify_signature());
        assert_eq!(
            future_tombstone.validate(),
            Err(TombstoneValidationError::TimestampInFuture)
        );
    }

    #[test]
    fn test_encrypted_receipt_roundtrip() {
        let (sender_pub, sender_priv) = generate_x25519_keypair();
        let (recipient_pub, recipient_priv) = generate_test_keypair();
        let device_id = [0u8; 16];
        let session_key = [42u8; 32];
        let ciphertext = b"test ciphertext";

        let tombstone = TombstoneEnvelope::new(
            MessageID::new(),
            [0u8; 16],
            recipient_pub,
            &recipient_priv,
            device_id,
            1,
            TombstoneStatus::Read,
            Some(&sender_pub),
            Some(&session_key),
            Some(ciphertext),
        );

        assert!(tombstone.encrypted_receipt.is_some());
        assert!(tombstone.verify_signature());

        let receipt = tombstone.decrypt_receipt(&sender_priv).unwrap();
        assert_eq!(receipt.status, TombstoneStatus::Read);
        assert!(receipt.proof_of_content.is_some());
        assert!(receipt.precise_timestamp > 0);
    }

    #[test]
    fn test_encrypted_receipt_wrong_key_fails() {
        let (sender_pub, _sender_priv) = generate_x25519_keypair();
        let (_, wrong_priv) = generate_x25519_keypair();
        let (recipient_pub, recipient_priv) = generate_test_keypair();
        let device_id = [0u8; 16];

        let tombstone = TombstoneEnvelope::new(
            MessageID::new(),
            [0u8; 16],
            recipient_pub,
            &recipient_priv,
            device_id,
            1,
            TombstoneStatus::Delivered,
            Some(&sender_pub),
            Some(&[0u8; 32]),
            None,
        );

        // Wrong key should fail to decrypt
        assert!(tombstone.decrypt_receipt(&wrong_priv).is_none());
    }

    #[test]
    fn test_coarsen_timestamp() {
        let precise = 1700000000123i64; // Some arbitrary timestamp with ms precision
        let coarse = TombstoneEnvelope::coarsen_timestamp(precise);

        // Should be rounded down to hour boundary
        assert_eq!(coarse % HOUR_MS, 0);
        assert!(coarse <= precise);
        assert!(precise - coarse < HOUR_MS);
    }

    #[test]
    fn test_wire_type_conversion() {
        assert_eq!(WireType::try_from(0x00).unwrap(), WireType::Message);
        assert_eq!(WireType::try_from(0x01).unwrap(), WireType::Tombstone);
        assert!(WireType::try_from(0x02).is_err());
    }

    #[test]
    fn test_tombstone_serialization() {
        let (pub_key, priv_key) = generate_test_keypair();
        let device_id = [0u8; 16];

        let tombstone = TombstoneEnvelope::new_simple(
            MessageID::new(),
            [0u8; 16],
            pub_key,
            &priv_key,
            device_id,
            1,
        );

        let bytes = tombstone.to_bytes();
        let restored = TombstoneEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(restored.target_message_id, tombstone.target_message_id);
        assert_eq!(restored.routing_key, tombstone.routing_key);
        assert_eq!(restored.sequence, tombstone.sequence);
        assert!(restored.verify_signature());
    }

    #[test]
    fn test_tombstone_wire_format() {
        let (pub_key, priv_key) = generate_test_keypair();
        let device_id = [0u8; 16];

        let tombstone = TombstoneEnvelope::new_simple(
            MessageID::new(),
            [0u8; 16],
            pub_key,
            &priv_key,
            device_id,
            1,
        );

        let wire_bytes = tombstone.to_wire_bytes();
        assert_eq!(wire_bytes[0], 0x01); // Tombstone discriminator
    }
}
