use std::fmt::Debug;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ed25519_dalek::ed25519::Error;
use getset::Getters;
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use bincode::{Encode, Decode};
use bincode::enc::Encoder;
use bincode::de::Decoder;
use bincode::error::{EncodeError, DecodeError};

/// PublicID is a 64-byte address for a user identity.
///
/// **Structure**: 32 bytes Ed25519 public key + 32 bytes X25519 public key
/// **Serialization**: Both keys are serialized (64 bytes total)
///
/// This design provides full functionality:
/// - Ed25519 for signature verification
/// - X25519 for encryption and key exchange
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicID {
  pub(crate) verifying_key: VerifyingKey,
  pub(crate) x25519_public: X25519PublicKey,
}

impl PublicID {
  /// Create a new PublicID from both keys
  pub fn new(verifying_key: VerifyingKey, x25519_public: X25519PublicKey) -> Self {
    Self {
      verifying_key,
      x25519_public,
    }
  }

  /// Serialize to 64 bytes (32 Ed25519 + 32 X25519)
  pub fn to_bytes(&self) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    bytes[0..32].copy_from_slice(self.verifying_key.as_bytes());
    bytes[32..64].copy_from_slice(self.x25519_public.as_bytes());
    bytes
  }

  /// Deserialize from 64 bytes (32 Ed25519 + 32 X25519)
  pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, ed25519_dalek::SignatureError> {
    let ed25519_bytes: [u8; 32] = bytes[0..32].try_into().expect("slice is exactly 32 bytes");
    let x25519_bytes: [u8; 32] = bytes[32..64].try_into().expect("slice is exactly 32 bytes");

    let verifying_key = VerifyingKey::from_bytes(&ed25519_bytes)?;
    let x25519_public = X25519PublicKey::from(x25519_bytes);

    Ok(Self {
      verifying_key,
      x25519_public,
    })
  }

  /// Get Ed25519 VerifyingKey for signature verification
  pub fn verifying_key(&self) -> &VerifyingKey {
    &self.verifying_key
  }

  /// Get X25519 public key for encryption/DH
  pub fn x25519_public(&self) -> &X25519PublicKey {
    &self.x25519_public
  }

  /// Calculate fingerprint hash of the public ID
  pub fn fingerprint(&self) -> String {
    let hash = blake3::hash(&self.to_bytes());
    hex::encode(hash.as_bytes())
  }
}

impl AsRef<X25519PublicKey> for PublicID {
  fn as_ref(&self) -> &X25519PublicKey {
    &self.x25519_public
  }
}

// Implement bincode Encode/Decode for PublicID (64 bytes on wire)
// Serializes both Ed25519 and X25519 public keys
impl Encode for PublicID {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.to_bytes().encode(encoder)
    }
}

impl<Context> Decode<Context> for PublicID {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let bytes: [u8; 64] = Decode::decode(decoder)?;
        Self::from_bytes(&bytes)
            .map_err(|_| DecodeError::Other("Invalid Ed25519 public key"))
    }
}

impl<'de, Context> bincode::BorrowDecode<'de, Context> for PublicID {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        let bytes: [u8; 64] = bincode::BorrowDecode::borrow_decode(decoder)?;
        Self::from_bytes(&bytes)
            .map_err(|_| DecodeError::Other("Invalid Ed25519 public key"))
    }
}

#[derive(Getters)]
pub struct Identity {
  #[get = "pub"]
  pub(crate) public_id: PublicID,
  pub(crate) master_seed: [u8; 32],
  pub(crate) signing_key: SigningKey,
  pub(crate) x25519_secret: X25519Secret,
}

impl Debug for Identity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Identity")
      .field("public_id", &self.public_id)
      .field("master_seed", &"[REDACTED]")
      .field("signing_key", &"[REDACTED]")
      .field("x25519_secret", &"[REDACTED]")
      .finish()
  }
}

impl Identity {
  pub fn x25519_secret(&self) -> &X25519Secret {
    &self.x25519_secret
  }

  /// Generate a new identity from a random 32-byte seed
  pub fn generate() -> Self {
    let mut seed = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut seed);
    Self::from_seed(&seed)
  }

  /// Derive identity from a 32-byte master seed using HKDF-SHA256
  ///
  /// Derives both Ed25519 (signing) and X25519 (encryption) keys independently
  /// using HKDF with domain separation. Both public keys are stored in PublicID.
  pub fn from_seed(seed: &[u8; 32]) -> Self {
    // Derive Ed25519 signing key from HKDF
    let hkdf_ed25519 = Hkdf::<Sha256>::new(None, seed);
    let mut ed25519_seed = [0u8; 32];
    hkdf_ed25519
      .expand(b"reme-ed25519-identity-v1", &mut ed25519_seed)
      .expect("HKDF expand should never fail for 32 bytes");

    let signing_key = SigningKey::from_bytes(&ed25519_seed);
    let verifying_key = signing_key.verifying_key();

    // Derive X25519 key separately from HKDF
    let hkdf_x25519 = Hkdf::<Sha256>::new(None, seed);
    let mut x25519_seed = [0u8; 32];
    hkdf_x25519
      .expand(b"reme-x25519-identity-v1", &mut x25519_seed)
      .expect("HKDF expand should never fail for 32 bytes");

    let x25519_secret = X25519Secret::from(x25519_seed);
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    // Store both keys in PublicID (64 bytes)
    let public_id = PublicID::new(verifying_key, x25519_public);

    Self {
      public_id,
      master_seed: *seed,
      signing_key,
      x25519_secret,
    }
  }

  /// Return the 32-byte master seed
  ///
  /// IMPORTANT: This is the secret that backs up the entire identity.
  /// Encrypt this before writing to disk.
  pub fn to_seed(&self) -> &[u8; 32] {
    &self.master_seed
  }

  /// Create Identity from 32-byte seed (new format)
  pub fn from_bytes(bytes: &[u8; 32]) -> Self {
    Self::from_seed(bytes)
  }

  /// Return the 32-byte master seed (new format)
  ///
  /// IMPORTANT: Encrypt this before writing to disk.
  pub fn to_bytes(&self) -> [u8; 32] {
    self.master_seed
  }
}

impl Signer<Signature> for Identity {
  fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
    self.signing_key.try_sign(msg)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sign_and_verify() {
    let id = Identity::generate();
    let msg = b"hello world";
    let sig = id.sign(msg);

    // Get VerifyingKey from PublicID
    let verifying_key = id.public_id().verifying_key();

    verifying_key.verify_strict(msg, &sig).unwrap();
  }

  #[test]
  fn deterministic_derivation() {
    let seed = [42u8; 32];

    let id1 = Identity::from_seed(&seed);
    let id2 = Identity::from_seed(&seed);

    // Same seed should produce identical identities
    assert_eq!(id1.public_id(), id2.public_id());
    assert_eq!(id1.to_seed(), id2.to_seed());
    assert_eq!(id1.signing_key.to_bytes(), id2.signing_key.to_bytes());
    assert_eq!(id1.x25519_secret.to_bytes(), id2.x25519_secret.to_bytes());
  }

  #[test]
  fn seed_roundtrip() {
    let id1 = Identity::generate();
    let seed = id1.to_seed();

    // Recreate from seed
    let id2 = Identity::from_seed(seed);

    // Should have identical keys
    assert_eq!(id1.public_id(), id2.public_id());
  }

  #[test]
  fn bytes_compatibility() {
    let id1 = Identity::generate();

    // to_bytes/from_bytes should work with 32-byte seed
    let bytes = id1.to_bytes();
    let id2 = Identity::from_bytes(&bytes);

    assert_eq!(id1.public_id(), id2.public_id());
    assert_eq!(bytes.len(), 32);
  }

  #[test]
  fn public_id_is_64_bytes() {
    let id = Identity::generate();
    let public_id_bytes = id.public_id().to_bytes();

    assert_eq!(public_id_bytes.len(), 64);
  }

  #[test]
  fn public_id_has_both_keys() {
    let id = Identity::generate();

    // PublicID should have both keys
    let verifying_key = id.public_id().verifying_key();
    let x25519_key = id.public_id().x25519_public();

    // Sign and verify should work
    let msg = b"test message";
    let sig = id.sign(msg);
    verifying_key.verify_strict(msg, &sig).unwrap();

    // X25519 key should work for DH
    assert_eq!(x25519_key.as_bytes().len(), 32);
  }

  #[test]
  fn public_id_from_bytes_roundtrip() {
    let id = Identity::generate();
    let public_id = id.public_id();

    // Serialize to bytes
    let bytes = public_id.to_bytes();
    assert_eq!(bytes.len(), 64);

    // Deserialize from bytes
    let restored = PublicID::from_bytes(&bytes).unwrap();

    // Should be fully equal (both keys)
    assert_eq!(public_id, &restored);
    assert_eq!(public_id.verifying_key(), restored.verifying_key());
    assert_eq!(public_id.x25519_public(), restored.x25519_public());

    // Both encryption and signature verification should work
    let msg = b"test message";
    let sig = id.sign(msg);
    restored.verifying_key().verify_strict(msg, &sig).unwrap();
  }
}