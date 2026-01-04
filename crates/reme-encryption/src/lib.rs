use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand_core::OsRng;
use reme_identity::{is_low_order_point, PublicID};
use reme_message::{bincode_config, InnerEnvelope, MessageID, ACK_HASH_DOMAIN};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use xeddsa::{xed25519, Sign, Verify};

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid recipient public key (low-order point)")]
    InvalidRecipientKey,
    #[error("Invalid sender signature: message may be forged or tampered")]
    InvalidSenderSignature,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::error::EncodeError),
    #[error("Deserialization error: {0}")]
    DeserializationError(#[from] bincode::error::DecodeError),
}

/// Check if a shared secret is all zeros (indicates small-order input).
///
/// Per RFC 7748, implementations should check for all-zero output after
/// scalar multiplication as defense-in-depth against small-order points.
fn is_zero_shared_secret(shared_secret: &[u8; 32]) -> bool {
    shared_secret == &[0u8; 32]
}

/// Sign data with `XEdDSA` using an X25519 private key.
///
/// `XEdDSA` allows signing with X25519 keys by converting them to Ed25519-compatible
/// format internally. This enables using a single keypair for both DH and signatures.
fn xeddsa_sign(private_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let key = xed25519::PrivateKey(*private_key);
    key.sign(message, OsRng)
}

/// Verify an `XEdDSA` signature using an X25519 public key.
///
/// Returns true if the signature is valid, false otherwise.
fn xeddsa_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let key = xed25519::PublicKey(*public_key);
    key.verify(message, signature).is_ok()
}

/// Encrypt an `InnerEnvelope` to a recipient's MIK (stateless encryption)
///
/// This implements Session V1-style sealed box encryption with triple binding:
/// 1. Generates an ephemeral X25519 keypair (e, E)
/// 2. Computes `shared_secret` = X25519(e, `recipient_MIK`)
/// 3. Derives encryption key from `shared_secret` using blake3
/// 4. Signs the serialized envelope || `message_id` with `XEdDSA`
/// 5. Encrypts (`serialized_envelope` || signature) with `ChaCha20Poly1305`
///
/// Triple binding (`message_id` bound via):
/// - Nonce derivation: nonce = BLAKE3(context, `message_id` || `recipient_pk`)
/// - AAD: `message_id` passed as additional authenticated data
/// - Signature: `message_id` included in signed data
///
/// Returns `EncryptionOutput` containing `ephemeral_public`, ciphertext, and ack credentials.
pub fn encrypt_to_mik(
    inner_envelope: &InnerEnvelope,
    recipient_mik: &PublicID,
    outer_message_id: &MessageID,
    sender_private: &[u8; 32],
) -> Result<EncryptionOutput, EncryptionError> {
    // Reject small-order (weak) public keys that would produce predictable shared secrets
    if is_low_order_point(&recipient_mik.to_bytes()) {
        return Err(EncryptionError::InvalidRecipientKey);
    }

    // Generate ephemeral keypair
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // Recipient's MIK as X25519 public key
    let recipient_x25519 = X25519PublicKey::from(recipient_mik.to_bytes());

    // Compute shared secret via ECDH
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_x25519);

    // Defense-in-depth: reject all-zero shared secrets (indicates small-order input)
    // Per RFC 7748, implementations should check for all-zero output after scalar multiplication
    if is_zero_shared_secret(shared_secret.as_bytes()) {
        return Err(EncryptionError::InvalidRecipientKey);
    }

    // Derive encryption key binding both public keys (prevents key confusion attacks)
    let encryption_key = derive_key_from_shared(
        ephemeral_public.as_bytes(),
        &recipient_mik.to_bytes(),
        shared_secret.as_bytes(),
    );

    // Serialize the inner envelope into a reusable buffer
    let mut buffer = bincode::encode_to_vec(inner_envelope, bincode_config())?;
    let inner_bytes_len = buffer.len();

    // Sign: inner_bytes || outer_message_id (binding signature to outer envelope)
    buffer.extend_from_slice(outer_message_id.as_bytes());
    let signature = xeddsa_sign(sender_private, &buffer);

    // Prepare plaintext for encryption: inner_bytes || signature
    // Truncate to remove message_id, then append signature
    buffer.truncate(inner_bytes_len);
    buffer.extend_from_slice(&signature);
    let plaintext = buffer;

    // Derive nonce from message_id AND recipient_pk (recipient binding)
    let nonce_bytes = derive_nonce(outer_message_id, &recipient_mik.to_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher and encrypt with AAD (message_id binding)
    // Note: AEAD errors are intentionally discarded to prevent oracle attacks
    let cipher = ChaCha20Poly1305::new((&encryption_key).into());
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: outer_message_id.as_bytes(), // AAD binding
            },
        )
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    // Derive ack credentials for Tombstone V2
    let ack_secret = derive_ack_secret(shared_secret.as_bytes(), outer_message_id);
    let ack_hash = derive_ack_hash(&ack_secret);

    Ok(EncryptionOutput {
        ephemeral_public: ephemeral_public.to_bytes(),
        ciphertext,
        ack_secret,
        ack_hash,
    })
}

/// Decrypt a message using MIK private key (stateless decryption)
///
/// This is the receiver side of MIK encryption:
/// 1. Computes `shared_secret` = `X25519(mik_private`, `ephemeral_public`)
/// 2. Derives encryption key from `shared_secret` + both public keys
/// 3. Decrypts the ciphertext with `ChaCha20Poly1305` (with AAD verification)
/// 4. Splits signature from decrypted data (last 64 bytes)
/// 5. Verifies `XEdDSA` signature against sender's public key from `InnerEnvelope`
///
/// The `outer_message_id` is used for:
/// - Nonce derivation (with `recipient_pk`)
/// - AAD verification (tampering with `message_id` causes decryption failure)
/// - Signature verification (`message_id` is part of signed data)
///
/// Returns `DecryptionOutput` containing the inner envelope and `ack_secret` for tombstones.
///
/// # Breaking Change (v0.1)
///
/// This function expects the sign-all-bytes format where the signature is
/// appended to serialized `InnerEnvelope` bytes before encryption. Messages
/// encrypted with the previous format (signature inside `InnerEnvelope`) are
/// not compatible. This is intentional for the `PoC` stage - no migration path
/// is provided.
pub fn decrypt_with_mik(
    ephemeral_public: &[u8; 32],
    ciphertext: &[u8],
    mik_private: &[u8; 32],
    outer_message_id: &MessageID,
) -> Result<DecryptionOutput, EncryptionError> {
    // Reject small-order ephemeral keys (attacker could send malicious keys)
    if is_low_order_point(ephemeral_public) {
        return Err(EncryptionError::DecryptionFailed);
    }

    // Parse ephemeral public key
    let ephemeral_x25519 = X25519PublicKey::from(*ephemeral_public);

    // Our MIK private key as StaticSecret
    let mik_secret = StaticSecret::from(*mik_private);

    // Derive our public key from private key
    let mik_public = X25519PublicKey::from(&mik_secret);

    // Compute shared secret via ECDH
    let shared_secret = mik_secret.diffie_hellman(&ephemeral_x25519);

    // Defense-in-depth: reject all-zero shared secrets (indicates small-order input)
    if is_zero_shared_secret(shared_secret.as_bytes()) {
        return Err(EncryptionError::DecryptionFailed);
    }

    // Derive encryption key binding both public keys (prevents key confusion attacks)
    let encryption_key = derive_key_from_shared(
        ephemeral_public,
        mik_public.as_bytes(),
        shared_secret.as_bytes(),
    );

    // Derive nonce from message_id AND recipient_pk (recipient binding)
    let nonce_bytes = derive_nonce(outer_message_id, mik_public.as_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher and decrypt with AAD verification
    // Note: AEAD errors are intentionally discarded to prevent oracle attacks
    let cipher = ChaCha20Poly1305::new((&encryption_key).into());
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: outer_message_id.as_bytes(), // AAD verification
            },
        )
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    // Split signature from payload (last 64 bytes)
    if plaintext.len() < 64 {
        return Err(EncryptionError::DecryptionFailed);
    }
    let (inner_bytes, signature_bytes) = plaintext.split_at(plaintext.len() - 64);
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    // Deserialize the inner envelope (bincode v2 decode_from_slice handles trailing bytes)
    let (inner_envelope, _): (InnerEnvelope, _) =
        bincode::decode_from_slice(inner_bytes, bincode_config())?;

    // Verify signature: inner_bytes || outer_message_id
    let mut signable = inner_bytes.to_vec();
    signable.extend_from_slice(outer_message_id.as_bytes());

    let sender_pub = inner_envelope.from.to_bytes();
    if !xeddsa_verify(&sender_pub, &signable, &signature) {
        return Err(EncryptionError::InvalidSenderSignature);
    }

    // Derive ack_secret for Tombstone V2 (same as sender derived)
    let ack_secret = derive_ack_secret(shared_secret.as_bytes(), outer_message_id);

    Ok(DecryptionOutput {
        inner: inner_envelope,
        ack_secret,
    })
}

/// Derive a 32-byte encryption key from ECDH shared secret and both public keys
///
/// Binding both public keys prevents key confusion attacks where an attacker
/// might try to claim a ciphertext was intended for a different recipient.
/// This construction is inspired by the principles of `NaCl`'s `crypto_box_seal`,
/// but uses BLAKE3 KDF and does not follow the exact same nonce derivation.
///
/// Key = BLAKE3_KDF("reme-encryption-key-v0", `ephemeral_pub` || `recipient_pub` || `shared_secret`)
fn derive_key_from_shared(
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
    shared_secret: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("reme-encryption-key-v0");
    hasher.update(ephemeral_public);
    hasher.update(recipient_public);
    hasher.update(shared_secret);
    let hash = hasher.finalize();
    *hash.as_bytes()
}

/// Derive a 12-byte nonce from `MessageID` and recipient public key
///
/// Including `recipient_pk` in nonce derivation provides:
/// - Domain separation: same `message_id` to different recipients produces different nonces
/// - Recipient binding: prevents message forwarding attacks
///
/// Nonce = BLAKE3_KDF("reme-nonce-v0", `message_id` || `recipient_pk`)[0..12]
fn derive_nonce(message_id: &MessageID, recipient_pk: &[u8; 32]) -> [u8; 12] {
    let mut hasher = blake3::Hasher::new_derive_key("reme-nonce-v0");
    hasher.update(message_id.as_bytes());
    hasher.update(recipient_pk);
    let hash = hasher.finalize();

    // Take first 12 bytes as nonce
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hash.as_bytes()[0..12]);
    nonce
}

// ============================================
// Tombstone V2: Ack Secret/Hash Derivation
// ============================================

/// Derive `ack_secret` from ECDH shared secret and `message_id`.
///
/// Both sender and recipient can derive the same `ack_secret` because they
/// compute the same `shared_secret` via ECDH:
/// - Sender: `shared_secret` = `X25519(ephemeral_secret`, `recipient_mik`)
/// - Recipient: `shared_secret` = `X25519(mik_private`, `ephemeral_public`)
///
/// `ack_secret` = BLAKE3_KDF("reme-ack-v1", `shared_secret` || `message_id`)[0..16]
pub fn derive_ack_secret(shared_secret: &[u8; 32], message_id: &MessageID) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new_derive_key("reme-ack-v1");
    hasher.update(shared_secret);
    hasher.update(message_id.as_bytes());
    let hash = hasher.finalize();

    let mut ack_secret = [0u8; 16];
    ack_secret.copy_from_slice(&hash.as_bytes()[0..16]);
    ack_secret
}

/// Derive `ack_hash` from `ack_secret`.
///
/// This hash is stored in `OuterEnvelope` for tombstone verification.
/// Nodes verify tombstones by checking `hash(ack_secret)` == `ack_hash`.
///
/// `ack_hash` = BLAKE3_KDF("reme-ack-hash-v1", `ack_secret`)[0..16]
///
/// Domain separation provides defense-in-depth against:
/// - Cross-protocol confusion attacks
/// - Misuse of `ack_secret` in other contexts
pub fn derive_ack_hash(ack_secret: &[u8; 16]) -> [u8; 16] {
    let derived = blake3::derive_key(ACK_HASH_DOMAIN, ack_secret);
    let mut ack_hash = [0u8; 16];
    ack_hash.copy_from_slice(&derived[0..16]);
    ack_hash
}

// ============================================
// Receipt Signature Utilities
// ============================================

/// Domain separator for receipt signatures.
///
/// Used to prevent cross-protocol confusion attacks by ensuring receipt
/// signatures cannot be misused in other contexts.
pub const RECEIPT_DOMAIN_SEP: &[u8] = b"reme-receipt-v1:";

/// Build the data to be signed for a receipt.
///
/// Format: `"reme-receipt-v1:" || signer_pubkey || message_id`
///
/// This function allocates a `Vec<u8>` with the exact required capacity.
/// The caller is responsible for zeroizing the returned data after signing
/// if it contains sensitive information in the surrounding context.
///
/// # Arguments
/// * `signer_pubkey` - 32-byte public key of the signer
/// * `message_id` - 16-byte message ID
pub fn build_receipt_sign_data(signer_pubkey: &[u8; 32], message_id: &MessageID) -> Vec<u8> {
    let mut sign_data = Vec::with_capacity(RECEIPT_DOMAIN_SEP.len() + 32 + 16);
    sign_data.extend_from_slice(RECEIPT_DOMAIN_SEP);
    sign_data.extend_from_slice(signer_pubkey);
    sign_data.extend_from_slice(message_id.as_bytes());
    sign_data
}

/// Generate an `XEdDSA` receipt signature.
///
/// Creates a signature over the receipt data format:
/// `"reme-receipt-v1:" || signer_pubkey || message_id`
///
/// # Arguments
/// * `signer_private` - 32-byte X25519 private key of the signer
/// * `signer_pubkey` - 32-byte X25519 public key of the signer
/// * `message_id` - 16-byte message ID being acknowledged
///
/// # Returns
/// A 64-byte `XEdDSA` signature.
pub fn generate_receipt_signature(
    signer_private: &[u8; 32],
    signer_pubkey: &[u8; 32],
    message_id: &MessageID,
) -> [u8; 64] {
    let sign_data = build_receipt_sign_data(signer_pubkey, message_id);
    xeddsa_sign(signer_private, &sign_data)
}

/// Verify an `XEdDSA` receipt signature.
///
/// Verifies that the signature was created by the claimed signer over the
/// receipt data format: `"reme-receipt-v1:" || signer_pubkey || message_id`
///
/// # Arguments
/// * `signer_pubkey` - 32-byte X25519 public key of the expected signer
/// * `message_id` - 16-byte message ID that was acknowledged
/// * `signature` - 64-byte `XEdDSA` signature to verify
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
pub fn verify_receipt_signature(
    signer_pubkey: &[u8; 32],
    message_id: &MessageID,
    signature: &[u8; 64],
) -> bool {
    let sign_data = build_receipt_sign_data(signer_pubkey, message_id);
    xeddsa_verify(signer_pubkey, &sign_data, signature)
}

// ============================================
// Encryption/Decryption Output Structs
// ============================================

/// Output of `encrypt_to_mik` containing all values needed for `OuterEnvelope`.
#[derive(Debug, Clone)]
pub struct EncryptionOutput {
    /// Ephemeral X25519 public key (32 bytes)
    pub ephemeral_public: [u8; 32],
    /// Encrypted inner envelope + signature
    pub ciphertext: Vec<u8>,
    /// Ack secret for sender-side tombstone (store locally)
    pub ack_secret: [u8; 16],
    /// Ack hash to include in `OuterEnvelope`
    pub ack_hash: [u8; 16],
}

/// Output of `decrypt_with_mik` containing decrypted envelope and ack credentials.
#[derive(Debug, Clone)]
pub struct DecryptionOutput {
    /// Decrypted and verified inner envelope
    pub inner: InnerEnvelope,
    /// Ack secret for recipient-side tombstone
    pub ack_secret: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_identity::Identity;
    use reme_message::{Content, TextContent};

    /// Helper to create an `InnerEnvelope` (no signature field - signing happens during encryption)
    fn create_inner(sender: &Identity, body: &str, created_at_ms: u64) -> InnerEnvelope {
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
    fn test_encrypt_decrypt_roundtrip() {
        // Create recipient identity (Bob)
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        // Create sender identity (Alice)
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        // Create inner envelope (signature added during encryption)
        let message_id = MessageID::new();
        let inner = create_inner(&alice, "Hello Bob via MIK!", 1_234_567_890);

        // Alice encrypts to Bob's MIK (signing happens inside encrypt_to_mik)
        let enc_output = encrypt_to_mik(&inner, &bob_public, &message_id, &alice_private).unwrap();

        // Bob decrypts with his MIK private key (signature verification happens inside)
        let dec_output = decrypt_with_mik(
            &enc_output.ephemeral_public,
            &enc_output.ciphertext,
            &bob_private,
            &message_id,
        )
        .unwrap();

        assert_eq!(inner.from, dec_output.inner.from);
        assert_eq!(inner.created_at_ms, dec_output.inner.created_at_ms);

        // Signature was already verified during decryption - if we got here, it's valid

        match (inner.content, dec_output.inner.content) {
            (Content::Text(orig), Content::Text(dec)) => {
                assert_eq!(orig.body, dec.body);
            }
            _ => panic!("Content type mismatch"),
        }

        // Verify ack_secret matches between sender and recipient
        assert_eq!(
            enc_output.ack_secret, dec_output.ack_secret,
            "Sender and recipient should derive same ack_secret"
        );

        // Verify ack_hash is consistent
        assert_eq!(
            enc_output.ack_hash,
            derive_ack_hash(&enc_output.ack_secret),
            "ack_hash should match derivation from ack_secret"
        );
    }

    #[test]
    fn test_wrong_recipient_fails() {
        // Create two recipients
        let bob = Identity::generate();
        let bob_public = *bob.public_id();

        let eve = Identity::generate();
        let eve_private = eve.to_bytes();

        // Create sender
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        // Create inner envelope
        let message_id = MessageID::new();
        let inner = create_inner(&alice, "Secret message for Bob", 1_234_567_890);

        // Alice encrypts to Bob's MIK
        let enc_output = encrypt_to_mik(&inner, &bob_public, &message_id, &alice_private).unwrap();

        // Eve tries to decrypt with her private key (should fail)
        let result = decrypt_with_mik(
            &enc_output.ephemeral_public,
            &enc_output.ciphertext,
            &eve_private,
            &message_id,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::DecryptionFailed
        ));
    }

    #[test]
    fn test_different_messages_different_ephemeral() {
        let bob = Identity::generate();
        let bob_public = *bob.public_id();

        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        // Create two different messages
        let message_id1 = MessageID::new();
        let inner1 = create_inner(&alice, "Message 1", 1_234_567_890);

        let message_id2 = MessageID::new();
        let inner2 = create_inner(&alice, "Message 2", 1_234_567_891);

        // Encrypt both
        let enc1 = encrypt_to_mik(&inner1, &bob_public, &message_id1, &alice_private).unwrap();
        let enc2 = encrypt_to_mik(&inner2, &bob_public, &message_id2, &alice_private).unwrap();

        // Each message should have a different ephemeral key
        assert_ne!(enc1.ephemeral_public, enc2.ephemeral_public);

        // Each message should have different ack credentials
        assert_ne!(enc1.ack_secret, enc2.ack_secret);
        assert_ne!(enc1.ack_hash, enc2.ack_hash);
    }

    #[test]
    fn test_invalid_sender_signature_detected() {
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        let alice = Identity::generate();
        let mallory = Identity::generate();
        let mallory_private = mallory.to_bytes();

        // Mallory creates a message claiming to be from Alice
        let message_id = MessageID::new();
        let inner = InnerEnvelope {
            from: *alice.public_id(), // Claims to be Alice
            created_at_ms: 1_234_567_890,
            content: Content::Text(TextContent {
                body: "Fake message from Alice".to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        };

        // Mallory encrypts with HER private key (not Alice's)
        // The signature will be made with Mallory's key, but `from` claims Alice
        let enc_output =
            encrypt_to_mik(&inner, &bob_public, &message_id, &mallory_private).unwrap();

        // Bob decrypts - signature verification should FAIL
        // (decrypt_with_mik verifies using `from` field = Alice's pubkey, but signed with Mallory's key)
        let result = decrypt_with_mik(
            &enc_output.ephemeral_public,
            &enc_output.ciphertext,
            &bob_private,
            &message_id,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::InvalidSenderSignature
        ));
    }

    #[test]
    fn test_wrong_message_id_fails_decryption() {
        // This tests the AAD binding - tampering with message_id should fail
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        let message_id = MessageID::new();
        let wrong_message_id = MessageID::new();

        let inner = create_inner(&alice, "Test message", 1_234_567_890);

        // Encrypt with correct message_id
        let enc_output = encrypt_to_mik(&inner, &bob_public, &message_id, &alice_private).unwrap();

        // Try to decrypt with wrong message_id (should fail due to AAD mismatch)
        let result = decrypt_with_mik(
            &enc_output.ephemeral_public,
            &enc_output.ciphertext,
            &bob_private,
            &wrong_message_id,
        );
        assert!(
            result.is_err(),
            "Decryption with wrong message_id should fail"
        );
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::DecryptionFailed
        ));
    }

    #[test]
    fn test_low_order_point_rejected() {
        // Test that encryption to small-order (weak) public keys is rejected.
        // These keys produce predictable shared secrets, providing no confidentiality.
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();
        let message_id = MessageID::new();
        let inner = create_inner(&alice, "Test message", 1_234_567_890);

        // Test zero point (order 1)
        let zero_mik = PublicID::from_bytes_unchecked(&[0u8; 32]);
        let result = encrypt_to_mik(&inner, &zero_mik, &message_id, &alice_private);
        assert!(
            matches!(result, Err(EncryptionError::InvalidRecipientKey)),
            "Zero MIK should be rejected"
        );

        // Test order-2 point
        let mut order2 = [0u8; 32];
        order2[0] = 1;
        let order2_mik = PublicID::from_bytes_unchecked(&order2);
        let result = encrypt_to_mik(&inner, &order2_mik, &message_id, &alice_private);
        assert!(
            matches!(result, Err(EncryptionError::InvalidRecipientKey)),
            "Order-2 point should be rejected"
        );
    }

    #[test]
    fn test_malicious_ephemeral_key_rejected() {
        // Test that decryption rejects small-order ephemeral keys
        // An attacker could craft a message with a malicious ephemeral key
        let bob = Identity::generate();
        let bob_private = bob.to_bytes();
        let message_id = MessageID::new();

        // Fake ciphertext (doesn't matter, should reject before decryption attempt)
        let fake_ciphertext = vec![0u8; 64];

        // Test zero ephemeral key
        let zero_ephemeral = [0u8; 32];
        let result = decrypt_with_mik(&zero_ephemeral, &fake_ciphertext, &bob_private, &message_id);
        assert!(
            matches!(result, Err(EncryptionError::DecryptionFailed)),
            "Zero ephemeral key should be rejected"
        );

        // Test order-1 ephemeral key (identity point)
        let mut order1_ephemeral = [0u8; 32];
        order1_ephemeral[0] = 1;
        let result = decrypt_with_mik(
            &order1_ephemeral,
            &fake_ciphertext,
            &bob_private,
            &message_id,
        );
        assert!(
            matches!(result, Err(EncryptionError::DecryptionFailed)),
            "Order-1 ephemeral key should be rejected"
        );
    }

    #[test]
    fn test_large_message_encryption() {
        // Test encryption of messages larger than typical sizes
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        // Create a large message (~10KB)
        let large_body = "X".repeat(10 * 1024);
        let message_id = MessageID::new();
        let inner = create_inner(&alice, &large_body, 1_234_567_890);

        // Encrypt
        let enc_output = encrypt_to_mik(&inner, &bob_public, &message_id, &alice_private)
            .expect("Large message encryption should succeed");

        // Ciphertext should be larger than plaintext (due to serialization + tag + signature)
        assert!(
            enc_output.ciphertext.len() > large_body.len(),
            "Ciphertext should include overhead"
        );

        // Decrypt and verify
        let dec_output = decrypt_with_mik(
            &enc_output.ephemeral_public,
            &enc_output.ciphertext,
            &bob_private,
            &message_id,
        )
        .expect("Large message decryption should succeed");

        match dec_output.inner.content {
            Content::Text(text) => {
                assert_eq!(
                    text.body.len(),
                    large_body.len(),
                    "Decrypted body length should match"
                );
                assert_eq!(
                    text.body, large_body,
                    "Decrypted body should match original"
                );
            }
            _ => panic!("Expected text content"),
        }
    }

    #[test]
    fn test_different_senders_same_recipient_different_ciphertext() {
        // Verify that different senders to the same recipient produce different ciphertexts
        // This ensures proper key isolation between senders
        let bob = Identity::generate();
        let bob_public = *bob.public_id();

        let alice = Identity::generate();
        let alice_private = alice.to_bytes();
        let charlie = Identity::generate();
        let charlie_private = charlie.to_bytes();

        // Same message content and message_id, but different senders
        let message_id = MessageID::new();
        let inner_alice = create_inner(&alice, "Hello Bob!", 1_234_567_890);
        let inner_charlie = create_inner(&charlie, "Hello Bob!", 1_234_567_890);

        // Encrypt both
        let enc_alice =
            encrypt_to_mik(&inner_alice, &bob_public, &message_id, &alice_private).unwrap();
        let enc_charlie =
            encrypt_to_mik(&inner_charlie, &bob_public, &message_id, &charlie_private).unwrap();

        // Ephemeral keys should be different (random)
        assert_ne!(
            enc_alice.ephemeral_public, enc_charlie.ephemeral_public,
            "Ephemeral keys should differ"
        );

        // Ciphertexts should be different (different ephemeral keys = different shared secrets)
        assert_ne!(
            enc_alice.ciphertext, enc_charlie.ciphertext,
            "Ciphertexts should differ"
        );

        // Both should still decrypt correctly
        let bob_private = bob.to_bytes();
        let dec_alice = decrypt_with_mik(
            &enc_alice.ephemeral_public,
            &enc_alice.ciphertext,
            &bob_private,
            &message_id,
        )
        .unwrap();
        let dec_charlie = decrypt_with_mik(
            &enc_charlie.ephemeral_public,
            &enc_charlie.ciphertext,
            &bob_private,
            &message_id,
        )
        .unwrap();

        assert_eq!(dec_alice.inner.from, *alice.public_id());
        assert_eq!(dec_charlie.inner.from, *charlie.public_id());
    }

    #[test]
    fn test_same_sender_same_content_different_ciphertext() {
        // Even with same sender, recipient, and content, each encryption should produce
        // different ciphertext due to fresh ephemeral keys
        let bob = Identity::generate();
        let bob_public = *bob.public_id();

        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        let message_id1 = MessageID::new();
        let message_id2 = MessageID::new();

        let inner1 = create_inner(&alice, "Same content", 1_234_567_890);
        let inner2 = create_inner(&alice, "Same content", 1_234_567_890);

        let enc1 = encrypt_to_mik(&inner1, &bob_public, &message_id1, &alice_private).unwrap();
        let enc2 = encrypt_to_mik(&inner2, &bob_public, &message_id2, &alice_private).unwrap();

        // Different ephemeral keys
        assert_ne!(
            enc1.ephemeral_public, enc2.ephemeral_public,
            "Ephemeral keys should differ"
        );

        // Different ciphertexts (even with same content)
        assert_ne!(
            enc1.ciphertext, enc2.ciphertext,
            "Ciphertexts should differ even with same content"
        );
    }

    #[test]
    fn test_empty_message_content() {
        // Test encryption of empty message body
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        let message_id = MessageID::new();
        let inner = create_inner(&alice, "", 1_234_567_890);

        // Encrypt empty message
        let enc_output = encrypt_to_mik(&inner, &bob_public, &message_id, &alice_private)
            .expect("Empty message encryption should succeed");

        // Decrypt and verify
        let dec_output = decrypt_with_mik(
            &enc_output.ephemeral_public,
            &enc_output.ciphertext,
            &bob_private,
            &message_id,
        )
        .expect("Empty message decryption should succeed");

        match dec_output.inner.content {
            Content::Text(text) => assert_eq!(text.body, "", "Decrypted body should be empty"),
            _ => panic!("Expected text content"),
        }
    }

    #[test]
    fn test_is_zero_shared_secret() {
        // Test that zero shared secret is detected
        let zero_secret = [0u8; 32];
        assert!(
            is_zero_shared_secret(&zero_secret),
            "All-zero secret should be detected as zero"
        );

        // Test that non-zero shared secrets are not flagged as zero
        let mut non_zero_secret = [0u8; 32];
        non_zero_secret[0] = 1;
        assert!(
            !is_zero_shared_secret(&non_zero_secret),
            "Non-zero secret should not be detected as zero"
        );

        // Test with random non-zero secret
        let mut random_secret = [0u8; 32];
        random_secret[15] = 255;
        random_secret[31] = 128;
        assert!(
            !is_zero_shared_secret(&random_secret),
            "Random non-zero secret should not be detected as zero"
        );

        // Test with secret that's all 0xFF (maximum non-zero)
        let max_secret = [0xFFu8; 32];
        assert!(
            !is_zero_shared_secret(&max_secret),
            "All-max secret should not be detected as zero"
        );
    }

    #[test]
    fn test_receipt_signature_roundtrip() {
        use super::{generate_receipt_signature, verify_receipt_signature};

        // Create a node identity
        let node = Identity::generate();
        let node_private = node.to_bytes();
        let node_public = node.public_id().to_bytes();

        // Create a message ID
        let message_id = MessageID::new();

        // Generate receipt signature
        let signature = generate_receipt_signature(&node_private, &node_public, &message_id);

        // Verify the signature
        assert!(
            verify_receipt_signature(&node_public, &message_id, &signature),
            "Valid receipt signature should verify"
        );
    }

    #[test]
    fn test_receipt_signature_wrong_signer() {
        use super::{generate_receipt_signature, verify_receipt_signature};

        // Create two node identities
        let node1 = Identity::generate();
        let node2 = Identity::generate();

        let node1_private = node1.to_bytes();
        let node1_public = node1.public_id().to_bytes();
        let node2_public = node2.public_id().to_bytes();

        let message_id = MessageID::new();

        // Generate receipt signature with node1
        let signature = generate_receipt_signature(&node1_private, &node1_public, &message_id);

        // Verify with node2's public key should fail
        assert!(
            !verify_receipt_signature(&node2_public, &message_id, &signature),
            "Receipt signature should not verify with wrong public key"
        );
    }

    #[test]
    fn test_receipt_signature_wrong_message_id() {
        use super::{generate_receipt_signature, verify_receipt_signature};

        let node = Identity::generate();
        let node_private = node.to_bytes();
        let node_public = node.public_id().to_bytes();

        let message_id1 = MessageID::new();
        let message_id2 = MessageID::new();

        // Generate receipt signature for message_id1
        let signature = generate_receipt_signature(&node_private, &node_public, &message_id1);

        // Verify with message_id2 should fail
        assert!(
            !verify_receipt_signature(&node_public, &message_id2, &signature),
            "Receipt signature should not verify with wrong message ID"
        );
    }

    #[test]
    fn test_receipt_signature_tampered() {
        use super::{generate_receipt_signature, verify_receipt_signature};

        let node = Identity::generate();
        let node_private = node.to_bytes();
        let node_public = node.public_id().to_bytes();

        let message_id = MessageID::new();

        // Generate receipt signature
        let mut signature = generate_receipt_signature(&node_private, &node_public, &message_id);

        // Tamper with the signature
        signature[0] ^= 0xFF;

        // Verify should fail
        assert!(
            !verify_receipt_signature(&node_public, &message_id, &signature),
            "Tampered receipt signature should not verify"
        );
    }
}
