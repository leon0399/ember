use chacha20poly1305::{
    aead::{Aead, KeyInit},
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
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::error::EncodeError),
    #[error("Deserialization error: {0}")]
    DeserializationError(#[from] bincode::error::DecodeError),
}

/// Encrypt an InnerEnvelope to a recipient's MIK (stateless encryption)
///
/// This implements Session V1-style sealed box encryption:
/// 1. Generates an ephemeral X25519 keypair (e, E)
/// 2. Computes shared_secret = X25519(e, recipient_MIK)
/// 3. Derives encryption key from shared_secret using blake3
/// 4. Encrypts the InnerEnvelope with ChaCha20Poly1305
///
/// Returns the ephemeral public key and ciphertext.
pub fn encrypt_to_mik(
    inner_envelope: &InnerEnvelope,
    recipient_mik: &PublicID,
    outer_message_id: &MessageID,
) -> Result<([u8; 32], Vec<u8>), EncryptionError> {
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

    // Derive nonce from message_id
    let nonce_bytes = derive_nonce_from_message_id(outer_message_id);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher and encrypt
    let cipher = ChaCha20Poly1305::new((&encryption_key).into());
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    Ok((ephemeral_public.to_bytes(), ciphertext))
}

/// Decrypt a message using MIK private key (stateless decryption)
///
/// This is the receiver side of MIK encryption:
/// 1. Computes shared_secret = X25519(mik_private, ephemeral_public)
/// 2. Derives encryption key from shared_secret + both public keys
/// 3. Decrypts the ciphertext with ChaCha20Poly1305
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

    // Derive nonce from message_id
    let nonce_bytes = derive_nonce_from_message_id(outer_message_id);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher and decrypt
    let cipher = ChaCha20Poly1305::new((&encryption_key).into());
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
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
/// Key = BLAKE3_KDF("reme-mik-encryption-key-v1", ephemeral_pub || recipient_pub || shared_secret)
fn derive_key_from_shared(
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
    shared_secret: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("reme-mik-encryption-key-v1");
    hasher.update(ephemeral_public);
    hasher.update(recipient_public);
    hasher.update(shared_secret);
    let hash = hasher.finalize();
    *hash.as_bytes()
}

/// Derive a 12-byte nonce from a MessageID
///
/// We use blake3 hash of the message_id bytes and take the first 12 bytes.
/// This ensures a deterministic but unique nonce for each message.
fn derive_nonce_from_message_id(message_id: &MessageID) -> [u8; 12] {
    // Serialize message_id to bytes
    let message_id_bytes = bincode::encode_to_vec(message_id, bincode::config::standard())
        .expect("MessageID serialization should never fail");

    // Hash the message_id bytes
    let hash = blake3::hash(&message_id_bytes);

    // Take first 12 bytes as nonce
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hash.as_bytes()[0..12]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_identity::Identity;
    use reme_message::{Content, TextContent, CURRENT_VERSION};

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Create recipient identity (Bob)
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        // Create sender identity (Alice)
        let alice = Identity::generate();

        // Create inner envelope
        let message_id = MessageID::new();
        let inner = InnerEnvelope {
            version: CURRENT_VERSION,
            from: *alice.public_id(),
            to: bob_public,
            created_at_ms: 1234567890,
            outer_message_id: message_id,
            content: Content::Text(TextContent {
                body: "Hello Bob via MIK!".to_string(),
            }),
        };

        // Alice encrypts to Bob's MIK
        let (ephemeral_pub, ciphertext) = encrypt_to_mik(&inner, &bob_public, &message_id).unwrap();

        // Bob decrypts with his MIK private key
        let decrypted = decrypt_with_mik(&ephemeral_pub, &ciphertext, &bob_private, &message_id).unwrap();

        assert_eq!(inner.from, decrypted.from);
        assert_eq!(inner.to, decrypted.to);
        assert_eq!(inner.created_at_ms, decrypted.created_at_ms);

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

        // Create inner envelope
        let message_id = MessageID::new();
        let inner = InnerEnvelope {
            version: CURRENT_VERSION,
            from: *alice.public_id(),
            to: bob_public,
            created_at_ms: 1234567890,
            outer_message_id: message_id,
            content: Content::Text(TextContent {
                body: "Secret message for Bob".to_string(),
            }),
        };

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

        // Create two different messages
        let message_id1 = MessageID::new();
        let inner1 = InnerEnvelope {
            version: CURRENT_VERSION,
            from: *alice.public_id(),
            to: bob_public,
            created_at_ms: 1234567890,
            outer_message_id: message_id1,
            content: Content::Text(TextContent { body: "Message 1".to_string() }),
        };

        let message_id2 = MessageID::new();
        let inner2 = InnerEnvelope {
            version: CURRENT_VERSION,
            from: *alice.public_id(),
            to: bob_public,
            created_at_ms: 1234567891,
            outer_message_id: message_id2,
            content: Content::Text(TextContent { body: "Message 2".to_string() }),
        };

        // Encrypt both
        let (ephemeral1, _) = encrypt_to_mik(&inner1, &bob_public, &message_id1).unwrap();
        let (ephemeral2, _) = encrypt_to_mik(&inner2, &bob_public, &message_id2).unwrap();

        // Each message should have a different ephemeral key
        assert_ne!(ephemeral1, ephemeral2);
    }
}
