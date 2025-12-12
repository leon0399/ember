use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use reme_message::{InnerEnvelope, MessageID};

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

/// Encrypt an InnerEnvelope using ChaCha20Poly1305 AEAD
///
/// The nonce is derived from the first 12 bytes of the outer message_id.
/// This ensures each message has a unique nonce without needing to transmit it separately.
pub fn encrypt_inner_envelope(
    inner_envelope: &InnerEnvelope,
    key: &[u8; 32],
    outer_message_id: &MessageID,
) -> Result<Vec<u8>, EncryptionError> {
    // Serialize the inner envelope
    let plaintext = bincode::encode_to_vec(inner_envelope, bincode::config::standard())?;

    // Derive nonce from message_id (first 12 bytes)
    let nonce_bytes = derive_nonce_from_message_id(outer_message_id);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher
    let cipher = ChaCha20Poly1305::new(key.into());

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    Ok(ciphertext)
}

/// Decrypt an InnerEnvelope from ciphertext using ChaCha20Poly1305 AEAD
pub fn decrypt_inner_envelope(
    ciphertext: &[u8],
    key: &[u8; 32],
    outer_message_id: &MessageID,
) -> Result<InnerEnvelope, EncryptionError> {
    // Derive nonce from message_id (first 12 bytes)
    let nonce_bytes = derive_nonce_from_message_id(outer_message_id);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher
    let cipher = ChaCha20Poly1305::new(key.into());

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    // Deserialize
    let (inner_envelope, _) = bincode::decode_from_slice(&plaintext, bincode::config::standard())?;

    Ok(inner_envelope)
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
    use reme_message::{Content, TextContent, CURRENT_VERSION};
    use reme_identity::Identity;

    fn create_test_inner_envelope() -> InnerEnvelope {
        let alice = Identity::generate();
        let bob = Identity::generate();

        InnerEnvelope {
            version: CURRENT_VERSION,
            from: *alice.public_id(),
            to: *bob.public_id(),
            created_at_ms: 1234567890,
            outer_message_id: create_test_message_id(),
            content: Content::Text(TextContent {
                body: "Hello, World!".to_string(),
            }),
        }
    }

    fn create_test_message_id() -> MessageID {
        // Create a deterministic message ID for testing
        use uuid::Uuid;
        MessageID::from(Uuid::nil())
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let inner = create_test_inner_envelope();
        let key = [42u8; 32];
        let message_id = create_test_message_id();

        let ciphertext = encrypt_inner_envelope(&inner, &key, &message_id).unwrap();
        let decrypted = decrypt_inner_envelope(&ciphertext, &key, &message_id).unwrap();

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
    fn test_wrong_key_fails() {
        let inner = create_test_inner_envelope();
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let message_id = create_test_message_id();

        let ciphertext = encrypt_inner_envelope(&inner, &key, &message_id).unwrap();
        let result = decrypt_inner_envelope(&ciphertext, &wrong_key, &message_id);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EncryptionError::DecryptionFailed));
    }

    #[test]
    fn test_wrong_message_id_fails() {
        let inner = create_test_inner_envelope();
        let key = [42u8; 32];
        let message_id = create_test_message_id();

        // Create a different message ID
        use uuid::Uuid;
        let different_message_id = MessageID::from(Uuid::new_v4());

        let ciphertext = encrypt_inner_envelope(&inner, &key, &message_id).unwrap();
        let result = decrypt_inner_envelope(&ciphertext, &key, &different_message_id);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EncryptionError::DecryptionFailed));
    }

    #[test]
    fn test_nonce_derivation_deterministic() {
        let message_id = create_test_message_id();

        let nonce1 = derive_nonce_from_message_id(&message_id);
        let nonce2 = derive_nonce_from_message_id(&message_id);

        assert_eq!(nonce1, nonce2);
    }

    #[test]
    fn test_different_message_ids_different_nonces() {
        use uuid::Uuid;

        let message_id1 = MessageID::from(Uuid::nil());
        let message_id2 = MessageID::from(Uuid::new_v4());

        let nonce1 = derive_nonce_from_message_id(&message_id1);
        let nonce2 = derive_nonce_from_message_id(&message_id2);

        assert_ne!(nonce1, nonce2);
    }
}
