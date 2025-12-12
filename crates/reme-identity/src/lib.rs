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

/// PublicID is a 32-byte address for a user identity.
///
/// **Serialization**: Only the X25519 public key is serialized (32 bytes)
/// **In-memory**: Stores both X25519 (encryption) and Ed25519 (signing) keys
///
/// This design achieves 32-byte wire format while supporting both encryption
/// and signature verification. The Ed25519 key can be reconstructed from the
/// master seed when deserializing.
///
/// **Equality**: Only compares X25519 keys (since Ed25519 may be placeholder after deserialization)
#[derive(Clone, Copy, Debug)]
pub struct PublicID {
  pub(crate) x25519_public: X25519PublicKey,
  pub(crate) verifying_key: VerifyingKey,
}

impl PartialEq for PublicID {
  fn eq(&self, other: &Self) -> bool {
    self.x25519_public == other.x25519_public
  }
}

impl Eq for PublicID {}

impl std::hash::Hash for PublicID {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    self.x25519_public.as_bytes().hash(state);
  }
}

impl PublicID {
  /// Create a new PublicID from both keys
  pub fn new(x25519_public: X25519PublicKey, verifying_key: VerifyingKey) -> Self {
    Self {
      x25519_public,
      verifying_key,
    }
  }

  /// Get the raw 32-byte X25519 public key (what gets serialized)
  pub fn to_bytes(&self) -> [u8; 32] {
    self.x25519_public.to_bytes()
  }

  /// Get X25519 public key for encryption/DH
  pub fn x25519_public(&self) -> &X25519PublicKey {
    &self.x25519_public
  }

  /// Get Ed25519 VerifyingKey for signature verification
  pub fn verifying_key(&self) -> &VerifyingKey {
    &self.verifying_key
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

// Implement bincode Encode/Decode for PublicID (32 bytes on wire)
// Note: Only X25519 key is serialized. Ed25519 key must be reconstructed from seed.
impl Encode for PublicID {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.to_bytes().encode(encoder)
    }
}

impl<Context> Decode<Context> for PublicID {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let x25519_bytes: [u8; 32] = Decode::decode(decoder)?;
        let x25519_public = X25519PublicKey::from(x25519_bytes);

        // IMPORTANT: We cannot reconstruct the Ed25519 key from X25519 alone.
        // This decode is only valid when reconstructing from a full Identity seed.
        // For now, we'll use a placeholder that will cause errors if used incorrectly.
        // The proper way is to always reconstruct PublicID through Identity::from_seed().
        let verifying_key = VerifyingKey::from_bytes(&[0u8; 32])
            .map_err(|_| DecodeError::Other("PublicID decode requires full identity context"))?;

        Ok(PublicID {
            x25519_public,
            verifying_key,
        })
    }
}

impl<'de, Context> bincode::BorrowDecode<'de, Context> for PublicID {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        let x25519_bytes: [u8; 32] = bincode::BorrowDecode::borrow_decode(decoder)?;
        let x25519_public = X25519PublicKey::from(x25519_bytes);

        let verifying_key = VerifyingKey::from_bytes(&[0u8; 32])
            .map_err(|_| DecodeError::Other("PublicID decode requires full identity context"))?;

        Ok(PublicID {
            x25519_public,
            verifying_key,
        })
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
  /// Strategy: Generate keys and store the X25519 public key as PublicID.
  /// For signature verification, we store the Ed25519 VerifyingKey internally
  /// and expose it through PublicID's verifying_key() method.
  ///
  /// This achieves 32-byte serialization (X25519 only) while maintaining both
  /// encryption and signature capabilities.
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

    // Store both Ed25519 verifying key and X25519 public in PublicID
    let public_id = PublicID::new(x25519_public, verifying_key);

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
  fn public_id_is_32_bytes() {
    let id = Identity::generate();
    let public_id_bytes = id.public_id().to_bytes();

    assert_eq!(public_id_bytes.len(), 32);
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
}