//! Node Identity Management
//!
//! Handles loading, generating, and storing the node's cryptographic identity.
//! The node identity is an X25519 keypair used for:
//! - XEdDSA signatures on HTTP headers (proving message origin)
//! - Cryptographic loop prevention (identifying self by public key)

use reme_identity::{Identity, InvalidPublicKey, PublicID};
use std::fs;
use std::io;
use std::path::Path;

/// Errors that can occur during node identity operations.
#[derive(Debug, thiserror::Error)]
pub enum NodeIdentityError {
    #[error("Failed to read identity file: {0}")]
    ReadError(#[source] io::Error),

    #[error("Failed to write identity file: {0}")]
    WriteError(#[source] io::Error),

    #[error("Failed to create identity directory: {0}")]
    CreateDirError(#[source] io::Error),

    #[error("Invalid identity file: expected 32 bytes, got {0}")]
    InvalidLength(usize),

    #[error("Invalid identity key: derived public key is a low-order point")]
    InvalidKey(#[from] InvalidPublicKey),
}

/// Load an existing identity or generate a new one.
///
/// If the identity file exists, loads and validates it.
/// If it doesn't exist, generates a new identity and saves it atomically.
///
/// # Arguments
/// * `path` - Path to the identity file (32 bytes raw X25519 secret key)
///
/// # Errors
/// Returns an error if the file exists but is invalid, or if file I/O fails.
pub fn load_or_generate_identity(path: &Path) -> Result<Identity, NodeIdentityError> {
    if path.exists() {
        load_identity(path)
    } else {
        generate_and_save_identity(path)
    }
}

/// Load an identity from a file.
///
/// The file must contain exactly 32 bytes (raw X25519 secret key).
fn load_identity(path: &Path) -> Result<Identity, NodeIdentityError> {
    let data = fs::read(path).map_err(NodeIdentityError::ReadError)?;

    if data.len() != 32 {
        return Err(NodeIdentityError::InvalidLength(data.len()));
    }

    let bytes: [u8; 32] = data
        .try_into()
        .expect("length already validated");

    Identity::try_from_bytes(&bytes).map_err(NodeIdentityError::InvalidKey)
}

/// Generate a new identity and save it atomically.
///
/// Uses temp-file-then-rename pattern to prevent race conditions
/// and ensure atomic writes.
fn generate_and_save_identity(path: &Path) -> Result<Identity, NodeIdentityError> {
    let identity = Identity::generate();

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(NodeIdentityError::CreateDirError)?;
        }
    }

    // Write to temp file first, then rename for atomicity
    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, identity.to_bytes()).map_err(NodeIdentityError::WriteError)?;
    fs::rename(&temp_path, path).map_err(NodeIdentityError::WriteError)?;

    tracing::info!(
        "Generated new node identity: {}",
        node_id_hex(identity.public_id())
    );

    Ok(identity)
}

/// Derive the node ID from a public identity.
///
/// Returns the hex-encoded routing key (32 hex characters).
/// This is consistent with the message routing scheme used elsewhere.
pub fn node_id_hex(public_id: &PublicID) -> String {
    hex::encode(public_id.routing_key().as_bytes())
}

/// Wrapper around Identity providing node-specific functionality.
pub struct NodeIdentity {
    identity: Identity,
    /// Pre-computed hex-encoded node ID for header use
    node_id: String,
}

impl NodeIdentity {
    /// Create a NodeIdentity from an Identity.
    pub fn new(identity: Identity) -> Self {
        let node_id = node_id_hex(identity.public_id());
        Self { identity, node_id }
    }

    /// Load or generate a node identity from the given path.
    pub fn load_or_generate(path: &Path) -> Result<Self, NodeIdentityError> {
        let identity = load_or_generate_identity(path)?;
        Ok(Self::new(identity))
    }

    /// Get the underlying Identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Get the public identity.
    pub fn public_id(&self) -> &PublicID {
        self.identity.public_id()
    }

    /// Get the hex-encoded node ID (32 hex chars).
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Sign a message using XEdDSA.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.identity.sign_xeddsa(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_generate_and_load_identity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");

        // Generate new identity
        let identity1 = load_or_generate_identity(&path).unwrap();
        assert!(path.exists());

        // Load existing identity
        let identity2 = load_or_generate_identity(&path).unwrap();

        // Should be the same identity
        assert_eq!(
            identity1.public_id().to_bytes(),
            identity2.public_id().to_bytes()
        );
    }

    #[test]
    fn test_node_id_consistency() {
        let identity = Identity::generate();
        let node_id1 = node_id_hex(identity.public_id());
        let node_id2 = node_id_hex(identity.public_id());

        // Should be deterministic
        assert_eq!(node_id1, node_id2);
        // Should be 32 hex chars (16 bytes)
        assert_eq!(node_id1.len(), 32);
    }

    #[test]
    fn test_invalid_identity_file_length() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("invalid.key");

        // Write invalid data (not 32 bytes)
        fs::write(&path, b"too short").unwrap();

        let result = load_or_generate_identity(&path);
        assert!(matches!(result, Err(NodeIdentityError::InvalidLength(9))));
    }

    #[test]
    fn test_node_identity_wrapper() {
        let identity = Identity::generate();
        let node_identity = NodeIdentity::new(identity);

        // Test node_id
        assert_eq!(node_identity.node_id().len(), 32);

        // Test signing
        let message = b"test message";
        let signature = node_identity.sign(message);
        assert_eq!(signature.len(), 64);

        // Verify signature
        assert!(node_identity
            .public_id()
            .verify_xeddsa(message, &signature));
    }

    #[test]
    fn test_creates_parent_directories() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("dir").join("identity.key");

        let identity = load_or_generate_identity(&path).unwrap();
        assert!(path.exists());
        assert_eq!(fs::read(&path).unwrap().len(), 32);

        // Verify we can reload it
        let loaded = load_or_generate_identity(&path).unwrap();
        assert_eq!(
            identity.public_id().to_bytes(),
            loaded.public_id().to_bytes()
        );
    }
}
