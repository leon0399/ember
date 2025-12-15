use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand_core::OsRng;
use reme_identity::PublicID;
use reme_message::{InnerEnvelope, MessageID};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid recipient public key (low-order point)")]
    InvalidRecipientKey,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::error::EncodeError),
    #[error("Deserialization error: {0}")]
    DeserializationError(#[from] bincode::error::DecodeError),
}

/// Check if a public key is a small-order (weak) point on Curve25519.
///
/// Curve25519 has 8 small-order points that produce predictable shared secrets
/// when used in ECDH. Messages encrypted to these keys have no confidentiality
/// since anyone can derive the same encryption key.
///
/// The 8 small-order points (in their canonical byte representation):
/// - Order 1: The identity point [0; 32]
/// - Order 2: [1, 0, 0, ...]
/// - Order 4: 2 points
/// - Order 8: 4 points
fn is_low_order_point(public_key: &[u8; 32]) -> bool {
    // The 8 small-order points on Curve25519 (canonical representations)
    const LOW_ORDER_POINTS: [[u8; 32]; 8] = [
        // Order 1: identity (zero)
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        // Order 2
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        // Order 4
        [0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
         0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00],
        // Order 4
        [0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
         0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],
        // Order 8
        [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
        // Order 8
        [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
        // Order 8
        [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
        // Order 8 (same as p-1 in some representations, but included for completeness)
        [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10],
    ];

    LOW_ORDER_POINTS.iter().any(|p| p == public_key)
}

/// Encrypt an InnerEnvelope to a recipient's MIK (stateless encryption)
///
/// This implements Session V1-style sealed box encryption with triple binding:
/// 1. Generates an ephemeral X25519 keypair (e, E)
/// 2. Computes shared_secret = X25519(e, recipient_MIK)
/// 3. Derives encryption key from shared_secret using blake3
/// 4. Encrypts the InnerEnvelope with ChaCha20Poly1305
///
/// Triple binding (message_id bound via):
/// - Nonce derivation: nonce = BLAKE3(context, message_id || recipient_pk)
/// - AAD: message_id passed as additional authenticated data
/// - Signature: message_id included in signed data (in InnerEnvelope)
///
/// Returns the ephemeral public key and ciphertext.
pub fn encrypt_to_mik(
    inner_envelope: &InnerEnvelope,
    recipient_mik: &PublicID,
    outer_message_id: &MessageID,
) -> Result<([u8; 32], Vec<u8>), EncryptionError> {
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

    // Derive encryption key binding both public keys (prevents key confusion attacks)
    let encryption_key = derive_key_from_shared(
        ephemeral_public.as_bytes(),
        &recipient_mik.to_bytes(),
        shared_secret.as_bytes(),
    );

    // Serialize the inner envelope
    let plaintext = bincode::encode_to_vec(inner_envelope, bincode::config::standard())?;

    // Derive nonce from message_id AND recipient_pk (recipient binding)
    let nonce_bytes = derive_nonce(outer_message_id, &recipient_mik.to_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher and encrypt with AAD (message_id binding)
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

    Ok((ephemeral_public.to_bytes(), ciphertext))
}

/// Decrypt a message using MIK private key (stateless decryption)
///
/// This is the receiver side of MIK encryption:
/// 1. Computes shared_secret = X25519(mik_private, ephemeral_public)
/// 2. Derives encryption key from shared_secret + both public keys
/// 3. Decrypts the ciphertext with ChaCha20Poly1305 (with AAD verification)
///
/// The outer_message_id is used for:
/// - Nonce derivation (with recipient_pk)
/// - AAD verification (tampering with message_id causes decryption failure)
pub fn decrypt_with_mik(
    ephemeral_public: &[u8; 32],
    ciphertext: &[u8],
    mik_private: &[u8; 32],
    outer_message_id: &MessageID,
) -> Result<InnerEnvelope, EncryptionError> {
    // Parse ephemeral public key
    let ephemeral_x25519 = X25519PublicKey::from(*ephemeral_public);

    // Our MIK private key as StaticSecret
    let mik_secret = StaticSecret::from(*mik_private);

    // Derive our public key from private key
    let mik_public = X25519PublicKey::from(&mik_secret);

    // Compute shared secret via ECDH
    let shared_secret = mik_secret.diffie_hellman(&ephemeral_x25519);

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

    // Deserialize
    let (inner_envelope, _) = bincode::decode_from_slice(&plaintext, bincode::config::standard())?;

    Ok(inner_envelope)
}

/// Derive a 32-byte encryption key from ECDH shared secret and both public keys
///
/// Binding both public keys prevents key confusion attacks where an attacker
/// might try to claim a ciphertext was intended for a different recipient.
/// This follows the standard practice used in NaCl's crypto_box_seal.
///
/// Key = BLAKE3_KDF("reme-encryption-key-v0", ephemeral_pub || recipient_pub || shared_secret)
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

/// Derive a 12-byte nonce from MessageID and recipient public key
///
/// Including recipient_pk in nonce derivation provides:
/// - Domain separation: same message_id to different recipients produces different nonces
/// - Recipient binding: prevents message forwarding attacks
///
/// Nonce = BLAKE3_KDF("reme-nonce-v0", message_id || recipient_pk)[0..12]
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

#[cfg(test)]
mod tests {
    use super::*;
    use reme_identity::Identity;
    use reme_message::{Content, TextContent};

    /// Helper to create a signed InnerEnvelope
    fn create_signed_inner(
        sender: &Identity,
        message_id: &MessageID,
        body: &str,
        created_at_ms: u64,
    ) -> InnerEnvelope {
        // Create envelope without signature first
        let mut inner = InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms,
            content: Content::Text(TextContent {
                body: body.to_string(),
            }),
            signature: None,
        };

        // Sign it (including message_id in signable bytes)
        let signable = inner.signable_bytes(message_id);
        inner.signature = Some(InnerEnvelope::sign(&signable, &sender.to_bytes()));
        inner
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Create recipient identity (Bob)
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        // Create sender identity (Alice)
        let alice = Identity::generate();

        // Create signed inner envelope
        let message_id = MessageID::new();
        let inner = create_signed_inner(&alice, &message_id, "Hello Bob via MIK!", 1234567890);

        // Alice encrypts to Bob's MIK
        let (ephemeral_pub, ciphertext) = encrypt_to_mik(&inner, &bob_public, &message_id).unwrap();

        // Bob decrypts with his MIK private key
        let decrypted = decrypt_with_mik(&ephemeral_pub, &ciphertext, &bob_private, &message_id).unwrap();

        assert_eq!(inner.from, decrypted.from);
        assert_eq!(inner.created_at_ms, decrypted.created_at_ms);

        // Verify sender signature (must pass message_id for verification)
        assert!(decrypted.verify_signature(&message_id), "Sender signature should be valid");

        match (inner.content, decrypted.content) {
            (Content::Text(orig), Content::Text(dec)) => {
                assert_eq!(orig.body, dec.body);
            }
            _ => panic!("Content type mismatch"),
        }
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

        // Create signed inner envelope
        let message_id = MessageID::new();
        let inner = create_signed_inner(&alice, &message_id, "Secret message for Bob", 1234567890);

        // Alice encrypts to Bob's MIK
        let (ephemeral_pub, ciphertext) = encrypt_to_mik(&inner, &bob_public, &message_id).unwrap();

        // Eve tries to decrypt with her private key (should fail)
        let result = decrypt_with_mik(&ephemeral_pub, &ciphertext, &eve_private, &message_id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EncryptionError::DecryptionFailed));
    }

    #[test]
    fn test_different_messages_different_ephemeral() {
        let bob = Identity::generate();
        let bob_public = *bob.public_id();

        let alice = Identity::generate();

        // Create two different signed messages
        let message_id1 = MessageID::new();
        let inner1 = create_signed_inner(&alice, &message_id1, "Message 1", 1234567890);

        let message_id2 = MessageID::new();
        let inner2 = create_signed_inner(&alice, &message_id2, "Message 2", 1234567891);

        // Encrypt both
        let (ephemeral1, _) = encrypt_to_mik(&inner1, &bob_public, &message_id1).unwrap();
        let (ephemeral2, _) = encrypt_to_mik(&inner2, &bob_public, &message_id2).unwrap();

        // Each message should have a different ephemeral key
        assert_ne!(ephemeral1, ephemeral2);
    }

    #[test]
    fn test_invalid_sender_signature_detected() {
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        let alice = Identity::generate();
        let mallory = Identity::generate();

        // Mallory creates a message claiming to be from Alice
        let message_id = MessageID::new();
        let mut inner = InnerEnvelope {
            from: *alice.public_id(), // Claims to be Alice
            created_at_ms: 1234567890,
            content: Content::Text(TextContent {
                body: "Fake message from Alice".to_string(),
            }),
            signature: None,
        };

        // Mallory signs with her own key (not Alice's)
        let signable = inner.signable_bytes(&message_id);
        inner.signature = Some(InnerEnvelope::sign(&signable, &mallory.to_bytes()));

        // Encrypt and send
        let (ephemeral_pub, ciphertext) = encrypt_to_mik(&inner, &bob_public, &message_id).unwrap();

        // Bob decrypts
        let decrypted = decrypt_with_mik(&ephemeral_pub, &ciphertext, &bob_private, &message_id).unwrap();

        // Signature verification should FAIL (Mallory signed, but `from` claims Alice)
        assert!(!decrypted.verify_signature(&message_id), "Forged signature should be invalid");
    }

    #[test]
    fn test_wrong_message_id_fails_decryption() {
        // This tests the AAD binding - tampering with message_id should fail
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        let alice = Identity::generate();

        let message_id = MessageID::new();
        let wrong_message_id = MessageID::new();

        let inner = create_signed_inner(&alice, &message_id, "Test message", 1234567890);

        // Encrypt with correct message_id
        let (ephemeral_pub, ciphertext) = encrypt_to_mik(&inner, &bob_public, &message_id).unwrap();

        // Try to decrypt with wrong message_id (should fail due to AAD mismatch)
        let result = decrypt_with_mik(&ephemeral_pub, &ciphertext, &bob_private, &wrong_message_id);
        assert!(result.is_err(), "Decryption with wrong message_id should fail");
        assert!(matches!(result.unwrap_err(), EncryptionError::DecryptionFailed));
    }

    #[test]
    fn test_low_order_point_rejected() {
        // Test that encryption to small-order (weak) public keys is rejected.
        // These keys produce predictable shared secrets, providing no confidentiality.
        let alice = Identity::generate();
        let message_id = MessageID::new();
        let inner = create_signed_inner(&alice, &message_id, "Test message", 1234567890);

        // Test zero point (order 1)
        let zero_mik = PublicID::from_bytes(&[0u8; 32]);
        let result = encrypt_to_mik(&inner, &zero_mik, &message_id);
        assert!(
            matches!(result, Err(EncryptionError::InvalidRecipientKey)),
            "Zero MIK should be rejected"
        );

        // Test order-2 point
        let mut order2 = [0u8; 32];
        order2[0] = 1;
        let order2_mik = PublicID::from_bytes(&order2);
        let result = encrypt_to_mik(&inner, &order2_mik, &message_id);
        assert!(
            matches!(result, Err(EncryptionError::InvalidRecipientKey)),
            "Order-2 point should be rejected"
        );
    }

    #[test]
    fn test_large_message_encryption() {
        // Test encryption of messages larger than typical sizes
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        let alice = Identity::generate();

        // Create a large message (~10KB)
        let large_body = "X".repeat(10 * 1024);
        let message_id = MessageID::new();
        let inner = create_signed_inner(&alice, &message_id, &large_body, 1234567890);

        // Encrypt
        let (ephemeral_pub, ciphertext) = encrypt_to_mik(&inner, &bob_public, &message_id)
            .expect("Large message encryption should succeed");

        // Ciphertext should be larger than plaintext (due to serialization + tag)
        assert!(ciphertext.len() > large_body.len(), "Ciphertext should include overhead");

        // Decrypt and verify
        let decrypted = decrypt_with_mik(&ephemeral_pub, &ciphertext, &bob_private, &message_id)
            .expect("Large message decryption should succeed");

        match decrypted.content {
            Content::Text(text) => {
                assert_eq!(text.body.len(), large_body.len(), "Decrypted body length should match");
                assert_eq!(text.body, large_body, "Decrypted body should match original");
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
        let charlie = Identity::generate();

        // Same message content and message_id, but different senders
        let message_id = MessageID::new();
        let inner_alice = create_signed_inner(&alice, &message_id, "Hello Bob!", 1234567890);
        let inner_charlie = create_signed_inner(&charlie, &message_id, "Hello Bob!", 1234567890);

        // Encrypt both
        let (ephemeral_alice, ciphertext_alice) = encrypt_to_mik(&inner_alice, &bob_public, &message_id).unwrap();
        let (ephemeral_charlie, ciphertext_charlie) = encrypt_to_mik(&inner_charlie, &bob_public, &message_id).unwrap();

        // Ephemeral keys should be different (random)
        assert_ne!(ephemeral_alice, ephemeral_charlie, "Ephemeral keys should differ");

        // Ciphertexts should be different (different ephemeral keys = different shared secrets)
        assert_ne!(ciphertext_alice, ciphertext_charlie, "Ciphertexts should differ");

        // Both should still decrypt correctly
        let bob_private = bob.to_bytes();
        let decrypted_alice = decrypt_with_mik(&ephemeral_alice, &ciphertext_alice, &bob_private, &message_id).unwrap();
        let decrypted_charlie = decrypt_with_mik(&ephemeral_charlie, &ciphertext_charlie, &bob_private, &message_id).unwrap();

        assert_eq!(decrypted_alice.from, *alice.public_id());
        assert_eq!(decrypted_charlie.from, *charlie.public_id());
    }

    #[test]
    fn test_same_sender_same_content_different_ciphertext() {
        // Even with same sender, recipient, and content, each encryption should produce
        // different ciphertext due to fresh ephemeral keys
        let bob = Identity::generate();
        let bob_public = *bob.public_id();

        let alice = Identity::generate();

        let message_id1 = MessageID::new();
        let message_id2 = MessageID::new();

        let inner1 = create_signed_inner(&alice, &message_id1, "Same content", 1234567890);
        let inner2 = create_signed_inner(&alice, &message_id2, "Same content", 1234567890);

        let (ephemeral1, ciphertext1) = encrypt_to_mik(&inner1, &bob_public, &message_id1).unwrap();
        let (ephemeral2, ciphertext2) = encrypt_to_mik(&inner2, &bob_public, &message_id2).unwrap();

        // Different ephemeral keys
        assert_ne!(ephemeral1, ephemeral2, "Ephemeral keys should differ");

        // Different ciphertexts (even with same content)
        assert_ne!(ciphertext1, ciphertext2, "Ciphertexts should differ even with same content");
    }

    #[test]
    fn test_empty_message_content() {
        // Test encryption of empty message body
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        let alice = Identity::generate();

        let message_id = MessageID::new();
        let inner = create_signed_inner(&alice, &message_id, "", 1234567890);

        // Encrypt empty message
        let (ephemeral_pub, ciphertext) = encrypt_to_mik(&inner, &bob_public, &message_id)
            .expect("Empty message encryption should succeed");

        // Decrypt and verify
        let decrypted = decrypt_with_mik(&ephemeral_pub, &ciphertext, &bob_private, &message_id)
            .expect("Empty message decryption should succeed");

        match decrypted.content {
            Content::Text(text) => assert_eq!(text.body, "", "Decrypted body should be empty"),
            _ => panic!("Expected text content"),
        }
    }
}
