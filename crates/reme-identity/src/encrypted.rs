//! Password-protected identity storage using Argon2id + ChaCha20-Poly1305.
//!
//! This module provides secure storage for identity private keys with optional
//! password protection. When a password is provided, the identity is encrypted
//! using Argon2id for key derivation and ChaCha20-Poly1305 for authenticated
//! encryption.
//!
//! ## File Format
//!
//! ### Encrypted Format (93 bytes)
//! ```text
//! MAGIC       (16 bytes): "reme-identity-v1"
//! VERSION     (1 byte):   0x01
//! SALT        (16 bytes): random salt for Argon2
//! NONCE       (12 bytes): random nonce for ChaCha20
//! CIPHERTEXT  (32 bytes): encrypted identity key
//! TAG         (16 bytes): Poly1305 auth tag
//! ```
//!
//! ### Plaintext Format (32 bytes)
//! Raw 32-byte identity private key (no encryption).
//!
//! ## Security Parameters (OWASP 2024)
//!
//! Argon2id parameters are hardcoded following OWASP recommendations:
//! - Memory: 46 MiB (47104 KiB)
//! - Iterations: 1
//! - Parallelism: 1
//!
//! To change parameters, bump VERSION and handle migration.

use crate::Identity;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

/// Magic bytes identifying an encrypted identity file
pub const MAGIC: &[u8; 16] = b"reme-identity-v1";

/// Current file format version
pub const VERSION: u8 = 0x01;

/// Size of the encrypted file format
pub const ENCRYPTED_FILE_SIZE: usize = 93;

/// Size of the plaintext file format (raw key)
pub const PLAINTEXT_FILE_SIZE: usize = 32;

// OWASP 2024 recommended Argon2id parameters (hardcoded)
const ARGON2_M: u32 = 47104; // 46 MiB
const ARGON2_T: u32 = 2;     // 2 iterations (OWASP minimum)
const ARGON2_P: u32 = 1;     // 1 parallelism

/// Errors that can occur during encrypted identity operations
#[derive(Debug, Error)]
pub enum EncryptedIdentityError {
    /// Invalid file size
    #[error("Invalid file size: expected {expected} bytes, got {actual}")]
    InvalidSize { expected: usize, actual: usize },

    /// Invalid magic header
    #[error("Invalid magic header: not a reme identity file")]
    InvalidMagic,

    /// Unsupported file format version
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),

    /// Decryption failed (wrong password or corrupted data)
    #[error("Decryption failed: wrong password or corrupted data")]
    DecryptionFailed,

    /// Password required for encrypted identity
    #[error("Password required: identity file is encrypted")]
    PasswordRequired,

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
}

/// Encrypted identity file representation
#[derive(Debug, Clone)]
pub struct EncryptedIdentity {
    /// Random salt for Argon2id (16 bytes)
    salt: [u8; 16],
    /// Random nonce for ChaCha20-Poly1305 (12 bytes)
    nonce: [u8; 12],
    /// Encrypted identity key + Poly1305 tag (48 bytes)
    ciphertext: [u8; 48],
}

impl EncryptedIdentity {
    /// Encrypt an identity with a password.
    ///
    /// Uses Argon2id for key derivation with OWASP 2024 recommended parameters,
    /// and ChaCha20-Poly1305 for authenticated encryption.
    pub fn encrypt(identity: &Identity, password: &[u8]) -> Result<Self, EncryptedIdentityError> {
        // Generate random salt and nonce
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        // Derive encryption key using Argon2id
        let argon2_params = Params::new(ARGON2_M, ARGON2_T, ARGON2_P, Some(32))
            .expect("hardcoded Argon2 parameters are invalid");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

        // Key is wrapped in Zeroizing to ensure it's cleared from memory on drop
        let mut key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password, &salt, key.as_mut())
            .map_err(|e| EncryptedIdentityError::EncryptionFailed(e.to_string()))?;

        // Encrypt identity key with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
            .expect("derived key has correct length");

        let plaintext = identity.to_bytes();
        let ciphertext_vec = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|e| EncryptedIdentityError::EncryptionFailed(e.to_string()))?;

        // Convert to fixed-size array (32 bytes ciphertext + 16 bytes tag = 48 bytes)
        let mut ciphertext = [0u8; 48];
        if ciphertext_vec.len() != 48 {
            return Err(EncryptedIdentityError::EncryptionFailed(format!(
                "unexpected ciphertext length: {}",
                ciphertext_vec.len()
            )));
        }
        ciphertext.copy_from_slice(&ciphertext_vec);

        Ok(Self {
            salt,
            nonce,
            ciphertext,
        })
    }

    /// Decrypt the identity using the provided password.
    pub fn decrypt(&self, password: &[u8]) -> Result<Identity, EncryptedIdentityError> {
        // Derive decryption key using Argon2id
        let argon2_params = Params::new(ARGON2_M, ARGON2_T, ARGON2_P, Some(32))
            .expect("hardcoded Argon2 parameters are invalid");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

        // Key is wrapped in Zeroizing to ensure it's cleared from memory on drop
        let mut key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password, &self.salt, key.as_mut())
            .map_err(|_| EncryptedIdentityError::DecryptionFailed)?;

        // Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
            .expect("derived key has correct length");

        let plaintext = Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref())
                .map_err(|_| EncryptedIdentityError::DecryptionFailed)?,
        );

        // Convert to identity
        if plaintext.len() != 32 {
            return Err(EncryptedIdentityError::DecryptionFailed);
        }

        let mut key_bytes = Zeroizing::new([0u8; 32]);
        key_bytes.copy_from_slice(&plaintext);
        Ok(Identity::from_bytes(&key_bytes))
    }

    /// Serialize to the binary file format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ENCRYPTED_FILE_SIZE);

        // Magic header
        buf.extend_from_slice(MAGIC);

        // Version
        buf.push(VERSION);

        // Salt
        buf.extend_from_slice(&self.salt);

        // Nonce
        buf.extend_from_slice(&self.nonce);

        // Ciphertext + tag
        buf.extend_from_slice(&self.ciphertext);

        buf
    }

    /// Parse from the binary file format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EncryptedIdentityError> {
        if data.len() != ENCRYPTED_FILE_SIZE {
            return Err(EncryptedIdentityError::InvalidSize {
                expected: ENCRYPTED_FILE_SIZE,
                actual: data.len(),
            });
        }

        // Verify magic header
        if &data[0..16] != MAGIC {
            return Err(EncryptedIdentityError::InvalidMagic);
        }

        // Check version
        let version = data[16];
        if version != VERSION {
            return Err(EncryptedIdentityError::UnsupportedVersion(version));
        }

        // Parse salt
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[17..33]);

        // Parse nonce
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[33..45]);

        // Parse ciphertext + tag
        let mut ciphertext = [0u8; 48];
        ciphertext.copy_from_slice(&data[45..93]);

        Ok(Self {
            salt,
            nonce,
            ciphertext,
        })
    }
}

/// Determines whether identity file data is encrypted or plaintext.
///
/// Returns `true` if the data appears to be in encrypted format,
/// `false` if it appears to be plaintext (raw 32-byte key).
pub fn is_encrypted(data: &[u8]) -> bool {
    data.len() == ENCRYPTED_FILE_SIZE && data.starts_with(MAGIC)
}

/// Load an identity from file data, handling both encrypted and plaintext formats.
///
/// - If `password` is `Some` and data is encrypted: decrypt with password
/// - If `password` is `Some` and data is plaintext: warn and load anyway
/// - If `password` is `None` and data is plaintext: load directly
/// - If `password` is `None` and data is encrypted: return error (password required)
pub fn load_identity(
    data: &[u8],
    password: Option<&[u8]>,
) -> Result<Identity, EncryptedIdentityError> {
    let encrypted = is_encrypted(data);

    match (encrypted, password) {
        (true, Some(pwd)) => {
            let enc = EncryptedIdentity::from_bytes(data)?;
            enc.decrypt(pwd)
        }
        (true, None) => Err(EncryptedIdentityError::PasswordRequired),
        (false, None) => {
            // Plaintext format: raw 32-byte key
            if data.len() != PLAINTEXT_FILE_SIZE {
                return Err(EncryptedIdentityError::InvalidSize {
                    expected: PLAINTEXT_FILE_SIZE,
                    actual: data.len(),
                });
            }
            // Wrap in Zeroizing to ensure key is cleared from memory on drop
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(data);
            Ok(Identity::from_bytes(&key))
        }
        (false, Some(_)) => {
            // User provided password but file is plaintext
            eprintln!(
                "Warning: Identity file is not encrypted. \
                Password provided but file is in plaintext format."
            );
            if data.len() != PLAINTEXT_FILE_SIZE {
                return Err(EncryptedIdentityError::InvalidSize {
                    expected: PLAINTEXT_FILE_SIZE,
                    actual: data.len(),
                });
            }
            // Wrap in Zeroizing to ensure key is cleared from memory on drop
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(data);
            Ok(Identity::from_bytes(&key))
        }
    }
}

/// Save an identity to bytes, optionally encrypting with a password.
///
/// - If `password` is `Some`: encrypt with Argon2id + ChaCha20-Poly1305
/// - If `password` is `None`: save as plaintext 32-byte key
pub fn save_identity(
    identity: &Identity,
    password: Option<&[u8]>,
) -> Result<Vec<u8>, EncryptedIdentityError> {
    match password {
        Some(pwd) if !pwd.is_empty() => {
            let enc = EncryptedIdentity::encrypt(identity, pwd)?;
            Ok(enc.to_bytes())
        }
        _ => {
            // No password or empty password: save as plaintext
            Ok(identity.to_bytes().to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let identity = Identity::generate();
        let password = b"test-password-123";

        let encrypted = EncryptedIdentity::encrypt(&identity, password).unwrap();
        let decrypted = encrypted.decrypt(password).unwrap();

        assert_eq!(identity.to_bytes(), decrypted.to_bytes());
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let identity = Identity::generate();
        let password = b"another-password";

        let encrypted = EncryptedIdentity::encrypt(&identity, password).unwrap();
        let bytes = encrypted.to_bytes();

        assert_eq!(bytes.len(), ENCRYPTED_FILE_SIZE);

        let parsed = EncryptedIdentity::from_bytes(&bytes).unwrap();
        let decrypted = parsed.decrypt(password).unwrap();

        assert_eq!(identity.to_bytes(), decrypted.to_bytes());
    }

    #[test]
    fn test_wrong_password_fails() {
        let identity = Identity::generate();
        let password = b"correct-password";
        let wrong_password = b"wrong-password";

        let encrypted = EncryptedIdentity::encrypt(&identity, password).unwrap();
        let result = encrypted.decrypt(wrong_password);

        assert!(matches!(
            result,
            Err(EncryptedIdentityError::DecryptionFailed)
        ));
    }

    #[test]
    fn test_corrupted_data_fails() {
        let identity = Identity::generate();
        let password = b"test-password";

        let encrypted = EncryptedIdentity::encrypt(&identity, password).unwrap();
        let mut bytes = encrypted.to_bytes();

        // Corrupt the ciphertext
        bytes[50] ^= 0xFF;

        let parsed = EncryptedIdentity::from_bytes(&bytes).unwrap();
        let result = parsed.decrypt(password);

        assert!(matches!(
            result,
            Err(EncryptedIdentityError::DecryptionFailed)
        ));
    }

    #[test]
    fn test_invalid_magic_fails() {
        let mut data = [0u8; ENCRYPTED_FILE_SIZE];
        data[0..16].copy_from_slice(b"wrong-magic-head");

        let result = EncryptedIdentity::from_bytes(&data);
        assert!(matches!(result, Err(EncryptedIdentityError::InvalidMagic)));
    }

    #[test]
    fn test_invalid_size_fails() {
        let data = [0u8; 50]; // Wrong size
        let result = EncryptedIdentity::from_bytes(&data);

        assert!(matches!(
            result,
            Err(EncryptedIdentityError::InvalidSize { .. })
        ));
    }

    #[test]
    fn test_unsupported_version_fails() {
        let mut data = [0u8; ENCRYPTED_FILE_SIZE];
        data[0..16].copy_from_slice(MAGIC);
        data[16] = 0x99; // Unsupported version

        let result = EncryptedIdentity::from_bytes(&data);
        assert!(matches!(
            result,
            Err(EncryptedIdentityError::UnsupportedVersion(0x99))
        ));
    }

    #[test]
    fn test_is_encrypted_detection() {
        let identity = Identity::generate();
        let password = b"test";

        // Encrypted format
        let encrypted = EncryptedIdentity::encrypt(&identity, password).unwrap();
        let encrypted_bytes = encrypted.to_bytes();
        assert!(is_encrypted(&encrypted_bytes));

        // Plaintext format
        let plaintext_bytes = identity.to_bytes();
        assert!(!is_encrypted(&plaintext_bytes));
    }

    #[test]
    fn test_load_save_identity_with_password() {
        let identity = Identity::generate();
        let password = b"my-secure-password";

        let saved = save_identity(&identity, Some(password)).unwrap();
        let loaded = load_identity(&saved, Some(password)).unwrap();

        assert_eq!(identity.to_bytes(), loaded.to_bytes());
    }

    #[test]
    fn test_load_save_identity_without_password() {
        let identity = Identity::generate();

        let saved = save_identity(&identity, None).unwrap();
        assert_eq!(saved.len(), PLAINTEXT_FILE_SIZE);

        let loaded = load_identity(&saved, None).unwrap();
        assert_eq!(identity.to_bytes(), loaded.to_bytes());
    }

    #[test]
    fn test_load_plaintext_with_password_provided() {
        // When user has password configured but file is legacy plaintext,
        // we should still load it (allows migration)
        let identity = Identity::generate();
        let plaintext = identity.to_bytes().to_vec();

        let loaded = load_identity(&plaintext, Some(b"some-password")).unwrap();
        assert_eq!(identity.to_bytes(), loaded.to_bytes());
    }

    #[test]
    fn test_empty_password_saves_plaintext() {
        let identity = Identity::generate();

        let saved = save_identity(&identity, Some(b"")).unwrap();
        assert_eq!(saved.len(), PLAINTEXT_FILE_SIZE);
        assert!(!is_encrypted(&saved));
    }
}
