use std::fmt::Debug;
use getset::Getters;
use rand_core::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use xeddsa::{xed25519, Sign, Verify};
use bincode::{Encode, Decode};
use bincode::enc::Encoder;
use bincode::de::Decoder;
use bincode::error::{EncodeError, DecodeError};

/// PublicID is a 32-byte address for a user identity using XEdDSA.
///
/// **Structure**: Single 32-byte X25519 public key (Curve25519 Montgomery form)
/// **Serialization**: 32 bytes on wire
///
/// Uses XEdDSA protocol:
/// - X25519 for encryption and key exchange (direct usage)
/// - XEdDSA signatures for authentication (via birational map to Ed25519)
/// - Sign bit convention: Always 0 (enforced during key generation)
///
/// This achieves 32-byte compact addresses while supporting both encryption
/// and signature verification through the birational equivalence between
/// Curve25519 (Montgomery) and Ed25519 (Twisted Edwards) forms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicID {
  pub(crate) x25519_public: X25519PublicKey,
}

impl PublicID {
  /// Create a new PublicID from X25519 public key
  pub fn new(x25519_public: X25519PublicKey) -> Self {
    Self { x25519_public }
  }

  /// Serialize to 32 bytes (X25519 public key)
  pub fn to_bytes(&self) -> [u8; 32] {
    self.x25519_public.to_bytes()
  }

  /// Deserialize from 32 bytes (X25519 public key)
  pub fn from_bytes(bytes: &[u8; 32]) -> Self {
    Self {
      x25519_public: X25519PublicKey::from(*bytes),
    }
  }

  /// Get X25519 public key for encryption/DH
  pub fn x25519_public(&self) -> &X25519PublicKey {
    &self.x25519_public
  }

  /// Verify an XEdDSA signature
  ///
  /// This converts the X25519 public key to Ed25519 form (with sign bit = 0)
  /// and verifies the signature using XEdDSA.
  pub fn verify_xeddsa(&self, message: &[u8], signature: &[u8; 64]) -> bool {
    // Convert to xeddsa PublicKey type
    let xed_public = xed25519::PublicKey(self.x25519_public.to_bytes());
    // Verify using XEdDSA
    xed_public.verify(message, signature).is_ok()
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
// Serializes only the X25519 public key
impl Encode for PublicID {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.to_bytes().encode(encoder)
    }
}

impl<Context> Decode<Context> for PublicID {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let bytes: [u8; 32] = Decode::decode(decoder)?;
        Ok(Self::from_bytes(&bytes))
    }
}

impl<'de, Context> bincode::BorrowDecode<'de, Context> for PublicID {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        let bytes: [u8; 32] = bincode::BorrowDecode::borrow_decode(decoder)?;
        Ok(Self::from_bytes(&bytes))
    }
}

#[derive(Getters)]
pub struct Identity {
  #[get = "pub"]
  pub(crate) public_id: PublicID,
  pub(crate) master_seed: [u8; 32],
  pub(crate) x25519_secret: X25519Secret,
}

impl Debug for Identity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Identity")
      .field("public_id", &self.public_id)
      .field("master_seed", &"[REDACTED]")
      .field("x25519_secret", &"[REDACTED]")
      .finish()
  }
}

impl Identity {
  /// Get the X25519 secret key for DH operations
  pub fn x25519_secret(&self) -> &X25519Secret {
    &self.x25519_secret
  }

  /// Sign a message using XEdDSA
  ///
  /// This uses the XEdDSA signing algorithm which produces Ed25519-compatible
  /// signatures from X25519 keys via the birational map.
  pub fn sign_xeddsa(&self, message: &[u8]) -> [u8; 64] {
    // Convert to xeddsa PrivateKey type
    let xed_private = xed25519::PrivateKey(self.x25519_secret.to_bytes());
    // Sign using XEdDSA with OsRng
    xed_private.sign(message, OsRng)
  }

  /// Generate a new identity from a random 32-byte seed
  pub fn generate() -> Self {
    let mut seed = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut seed);
    Self::from_seed(&seed)
  }

  /// Derive identity from a 32-byte master seed
  ///
  /// Derives a single X25519 key that will be used for both:
  /// - X25519 DH operations (direct usage)
  /// - XEdDSA signatures (via birational map to Ed25519)
  ///
  /// The XEdDSA signing implementation automatically enforces sign bit = 0
  /// convention, ensuring unique Ed25519 representation.
  pub fn from_seed(seed: &[u8; 32]) -> Self {
    // Use seed directly as X25519 private key
    // XEdDSA signing/verification will handle sign bit normalization
    let x25519_secret = X25519Secret::from(*seed);
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    // PublicID stores only the 32-byte X25519 public key
    let public_id = PublicID::new(x25519_public);

    Self {
      public_id,
      master_seed: *seed,
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sign_and_verify_xeddsa() {
    let id = Identity::generate();
    let msg = b"hello world";
    let sig = id.sign_xeddsa(msg);

    // Verify XEdDSA signature using PublicID
    assert!(id.public_id().verify_xeddsa(msg, &sig));
  }

  #[test]
  fn deterministic_derivation() {
    let seed = [42u8; 32];

    let id1 = Identity::from_seed(&seed);
    let id2 = Identity::from_seed(&seed);

    // Same seed should produce identical identities
    assert_eq!(id1.public_id(), id2.public_id());
    assert_eq!(id1.to_seed(), id2.to_seed());
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
  fn public_id_xeddsa_signature() {
    let id = Identity::generate();
    let x25519_key = id.public_id().x25519_public();

    // Sign and verify should work with XEdDSA
    let msg = b"test message";
    let sig = id.sign_xeddsa(msg);
    assert!(id.public_id().verify_xeddsa(msg, &sig));

    // X25519 key should be 32 bytes
    assert_eq!(x25519_key.as_bytes().len(), 32);
  }

  #[test]
  fn public_id_from_bytes_roundtrip() {
    let id = Identity::generate();
    let public_id = id.public_id();

    // Serialize to bytes
    let bytes = public_id.to_bytes();
    assert_eq!(bytes.len(), 32);

    // Deserialize from bytes
    let restored = PublicID::from_bytes(&bytes);

    // Should be equal
    assert_eq!(public_id, &restored);
    assert_eq!(public_id.x25519_public(), restored.x25519_public());

    // XEdDSA signature verification should work
    let msg = b"test message";
    let sig = id.sign_xeddsa(msg);
    assert!(restored.verify_xeddsa(msg, &sig));
  }
}