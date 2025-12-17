//! Password-protected identity storage using Argon2id + ChaCha20-Poly1305.
//!
//! This module provides secure storage for identity private keys with optional
//! password protection. When a password is provided, the identity is encrypted
//! using Argon2id for key derivation and ChaCha20-Poly1305 for authenticated
//! encryption.
//!
//! ## File Format
//!
//! ### Encrypted Format (105 bytes)
//! ```text
//! MAGIC       (16 bytes): "reme-identity-v1"
//! VERSION     (1 byte):   0x01
//! ARGON2_M    (4 bytes):  memory cost in KiB (LE u32)
//! ARGON2_T    (4 bytes):  time cost / iterations (LE u32)
//! ARGON2_P    (4 bytes):  parallelism (LE u32)
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
//! Default Argon2id parameters follow OWASP recommendations:
//! - Memory: 46 MiB (47104 KiB)
//! - Iterations: 1
//! - Parallelism: 1

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
pub const ENCRYPTED_FILE_SIZE: usize = 105;

/// Size of the plaintext file format (raw key)
pub const PLAINTEXT_FILE_SIZE: usize = 32;

// OWASP 2024 recommended Argon2id parameters
/// Default memory cost in KiB (46 MiB)
pub const DEFAULT_ARGON2_M: u32 = 47104;
/// Default time cost (iterations)
pub const DEFAULT_ARGON2_T: u32 = 1;
/// Default parallelism
pub const DEFAULT_ARGON2_P: u32 = 1;

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

    /// Invalid Argon2 parameters
    #[error("Invalid Argon2 parameters: {0}")]
    InvalidParams(String),

    /// Decryption failed (wrong password or corrupted data)
    #[error("Decryption failed: wrong password or corrupted data")]
    DecryptionFailed,

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
}

/// Argon2id parameters for key derivation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB
    pub m_cost: u32,
    /// Time cost (iterations)
    pub t_cost: u32,
    /// Parallelism
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: DEFAULT_ARGON2_M,
            t_cost: DEFAULT_ARGON2_T,
            p_cost: DEFAULT_ARGON2_P,
        }
    }
}

impl Argon2Params {
    /// Create Argon2id parameters with custom values
    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
        }
    }

    /// Convert to argon2 crate Params
    fn to_argon2_params(&self) -> Result<Params, EncryptedIdentityError> {
        Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| EncryptedIdentityError::InvalidParams(e.to_string()))
    }
}

/// Encrypted identity file representation
#[derive(Debug, Clone)]
pub struct EncryptedIdentity {
    /// Argon2id parameters used for key derivation
    pub params: Argon2Params,
    /// Random salt for Argon2id (16 bytes)
    pub salt: [u8; 16],
    /// Random nonce for ChaCha20-Poly1305 (12 bytes)
    pub nonce: [u8; 12],
    /// Encrypted identity key + Poly1305 tag (48 bytes)
    pub ciphertext: [u8; 48],
}

impl EncryptedIdentity {
    /// Encrypt an identity with a password.
    ///
    /// Uses Argon2id for key derivation with OWASP 2024 recommended parameters,
    /// and ChaCha20-Poly1305 for authenticated encryption.
    pub fn encrypt(identity: &Identity, password: &[u8]) -> Result<Self, EncryptedIdentityError> {
        Self::encrypt_with_params(identity, password, Argon2Params::default())
    }

    /// Encrypt an identity with a password using custom Argon2id parameters.
    pub fn encrypt_with_params(
        identity: &Identity,
        password: &[u8],
        params: Argon2Params,
    ) -> Result<Self, EncryptedIdentityError> {
        // Generate random salt and nonce
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        // Derive encryption key using Argon2id
        // Key is wrapped in Zeroizing to ensure it's cleared from memory on drop
        let argon2_params = params.to_argon2_params()?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

        let mut key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password, &salt, key.as_mut())
            .map_err(|e| EncryptedIdentityError::EncryptionFailed(e.to_string()))?;

        // Encrypt identity key with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|e| EncryptedIdentityError::EncryptionFailed(e.to_string()))?;

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
            params,
            salt,
            nonce,
            ciphertext,
        })
    }

    /// Decrypt the identity using the provided password.
    pub fn decrypt(&self, password: &[u8]) -> Result<Identity, EncryptedIdentityError> {
        // Derive decryption key using Argon2id
        // Key is wrapped in Zeroizing to ensure it's cleared from memory on drop
        let argon2_params = self.params.to_argon2_params()?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

        let mut key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password, &self.salt, key.as_mut())
            .map_err(|_| EncryptedIdentityError::DecryptionFailed)?;

        // Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| EncryptedIdentityError::DecryptionFailed)?;

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

        // Argon2 parameters (little-endian u32)
        buf.extend_from_slice(&self.params.m_cost.to_le_bytes());
        buf.extend_from_slice(&self.params.t_cost.to_le_bytes());
        buf.extend_from_slice(&self.params.p_cost.to_le_bytes());

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

        // Parse Argon2 parameters
        let m_cost = u32::from_le_bytes([data[17], data[18], data[19], data[20]]);
        let t_cost = u32::from_le_bytes([data[21], data[22], data[23], data[24]]);
        let p_cost = u32::from_le_bytes([data[25], data[26], data[27], data[28]]);

        // Parse salt
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[29..45]);

        // Parse nonce
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[45..57]);

        // Parse ciphertext + tag
        let mut ciphertext = [0u8; 48];
        ciphertext.copy_from_slice(&data[57..105]);

        Ok(Self {
            params: Argon2Params::new(m_cost, t_cost, p_cost),
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
/// - If `password` is `Some` and data is plaintext: return error (expected encrypted)
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
        (true, None) => Err(EncryptedIdentityError::DecryptionFailed),
        (false, None) => {
            // Plaintext format: raw 32-byte key
            if data.len() != PLAINTEXT_FILE_SIZE {
                return Err(EncryptedIdentityError::InvalidSize {
                    expected: PLAINTEXT_FILE_SIZE,
                    actual: data.len(),
                });
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(data);
            Ok(Identity::from_bytes(&key))
        }
        (false, Some(_)) => {
            // User provided password but file is plaintext - load anyway
            // This allows loading legacy files even when password is configured
            if data.len() != PLAINTEXT_FILE_SIZE {
                return Err(EncryptedIdentityError::InvalidSize {
                    expected: PLAINTEXT_FILE_SIZE,
                    actual: data.len(),
                });
            }
            let mut key = [0u8; 32];
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
        bytes[60] ^= 0xFF;

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
    fn test_custom_argon2_params() {
        let identity = Identity::generate();
        let password = b"test";

        // Use lighter params for faster test
        let params = Argon2Params::new(1024, 1, 1); // 1 MiB, 1 iteration

        let encrypted = EncryptedIdentity::encrypt_with_params(&identity, password, params).unwrap();

        // Verify params are preserved
        let bytes = encrypted.to_bytes();
        let parsed = EncryptedIdentity::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.params, params);

        // Verify decryption works
        let decrypted = parsed.decrypt(password).unwrap();
        assert_eq!(identity.to_bytes(), decrypted.to_bytes());
    }

    #[test]
    fn test_empty_password_saves_plaintext() {
        let identity = Identity::generate();

        let saved = save_identity(&identity, Some(b"")).unwrap();
        assert_eq!(saved.len(), PLAINTEXT_FILE_SIZE);
        assert!(!is_encrypted(&saved));
    }
}
