use std::fmt::{self, Debug, Display};
use getset::Getters;
use rand_core::OsRng;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use xeddsa::{xed25519, Sign, Verify};
use bincode::{Encode, Decode, impl_borrow_decode};
use bincode::enc::Encoder;
use bincode::de::Decoder;
use bincode::error::{EncodeError, DecodeError};

pub mod encrypted;
pub use encrypted::{
    Argon2Params, EncryptedIdentity, EncryptedIdentityError,
    is_encrypted, load_identity, save_identity,
};

/// Error returned when a public key is invalid (e.g., low-order point)
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("Invalid public key: low-order point on Curve25519")]
pub struct InvalidPublicKey;

/// Check if a public key is a small-order (weak) point on Curve25519.
///
/// Curve25519 has a cofactor of 8, meaning there are points of small order
/// that produce predictable shared secrets when used in ECDH.
///
/// Source: libsodium's x25519_ref10.c blocklist
/// <https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c>
pub fn is_low_order_point(public_key: &[u8; 32]) -> bool {
    const LOW_ORDER_POINTS: [[u8; 32]; 7] = [
        // 0 (order 4)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        // 1 (order 1)
        [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
        [0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
         0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00],
        // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
        [0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
         0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],
        // p-1 (order 2)
        [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
        // p (order 4) - equivalent to 0 mod p
        [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
        // p+1 (order 1) - equivalent to 1 mod p
        [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    ];

    LOW_ORDER_POINTS.iter().any(|p| p == public_key)
}

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
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicID {
  pub(crate) x25519_public: X25519PublicKey,
}

impl Display for PublicID {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", hex::encode(self.to_bytes()))
  }
}

impl Debug for PublicID {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "PublicID({})", hex::encode(self.to_bytes()))
  }
}

impl PublicID {
  /// Serialize to 32 bytes (X25519 public key)
  pub fn to_bytes(&self) -> [u8; 32] {
    self.x25519_public.to_bytes()
  }

  /// Deserialize from 32 bytes with validation.
  ///
  /// Returns an error if the bytes represent a low-order point on Curve25519,
  /// which would produce predictable shared secrets in ECDH.
  ///
  /// Use this for untrusted input (network, storage, user input).
  pub fn try_from_bytes(bytes: &[u8; 32]) -> Result<Self, InvalidPublicKey> {
    if is_low_order_point(bytes) {
      return Err(InvalidPublicKey);
    }
    Ok(Self {
      x25519_public: X25519PublicKey::from(*bytes),
    })
  }

  /// Deserialize from 32 bytes without validation.
  ///
  /// # Safety (Cryptographic)
  ///
  /// This does not check for low-order points, which produce predictable
  /// shared secrets in ECDH. Use [`try_from_bytes`] for untrusted input.
  ///
  /// This method exists only for test code that intentionally uses invalid keys.
  /// Production code should always use [`try_from_bytes`].
  ///
  /// [`try_from_bytes`]: Self::try_from_bytes
  #[doc(hidden)]
  pub fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self {
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

  /// Calculate routing key for mailbox addressing
  ///
  /// Returns a 16-byte key derived from the public ID hash.
  /// This is used to address messages in the mailbox system
  /// without revealing the full public key.
  pub fn routing_key(&self) -> RoutingKey {
    let hash = blake3::hash(&self.to_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.as_bytes()[0..16]);
    RoutingKey(bytes)
  }
}

/// Routing key for mailbox addressing (16 bytes).
///
/// Derived from the first 16 bytes of a BLAKE3 hash of a PublicID.
/// Used to address messages without revealing the full public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
pub struct RoutingKey(pub [u8; 16]);

impl RoutingKey {
    /// Create a new RoutingKey from raw bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Display for RoutingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Debug for RoutingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RoutingKey({})", hex::encode(self.0))
    }
}

impl AsRef<[u8; 16]> for RoutingKey {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl AsRef<[u8]> for RoutingKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 16]> for RoutingKey {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl From<RoutingKey> for [u8; 16] {
    fn from(key: RoutingKey) -> Self {
        key.0
    }
}

impl std::ops::Deref for RoutingKey {
    type Target = [u8; 16];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RoutingKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<X25519PublicKey> for PublicID {
  fn as_ref(&self) -> &X25519PublicKey {
    &self.x25519_public
  }
}

// Implement bincode Encode/Decode for PublicID (32 bytes on wire)
// Serializes only the X25519 public key
// Note: Decode validates against low-order points (rejects invalid keys)
impl Encode for PublicID {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.to_bytes().encode(encoder)
    }
}

impl<Context> Decode<Context> for PublicID {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let bytes: [u8; 32] = Decode::decode(decoder)?;
        Self::try_from_bytes(&bytes).map_err(|_| {
            DecodeError::OtherString("Invalid public key: low-order point".into())
        })
    }
}

impl_borrow_decode!(PublicID);

#[derive(Getters)]
pub struct Identity {
  #[get = "pub"]
  pub(crate) public_id: PublicID,
  pub(crate) x25519_secret: X25519Secret,
}

impl Debug for Identity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Identity")
      .field("public_id", &self.public_id)
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

  /// Generate a new identity from random bytes
  pub fn generate() -> Self {
    let mut bytes = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    Self::from_bytes(&bytes)
  }

  /// Create Identity from 32-byte secret key with validation.
  ///
  /// Derives a single X25519 key that will be used for both:
  /// - X25519 DH operations (direct usage)
  /// - XEdDSA signatures (via birational map to Ed25519)
  ///
  /// Returns an error if the derived public key is a low-order point
  /// (mathematically impossible with proper clamping, but checked for defense-in-depth).
  pub fn try_from_bytes(bytes: &[u8; 32]) -> Result<Self, InvalidPublicKey> {
    let x25519_secret = X25519Secret::from(*bytes);
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    // Defense-in-depth: verify derived public key isn't low-order
    // This should be mathematically impossible with X25519 clamping
    if is_low_order_point(x25519_public.as_bytes()) {
      return Err(InvalidPublicKey);
    }

    let public_id = PublicID { x25519_public };

    Ok(Self {
      public_id,
      x25519_secret,
    })
  }

  /// Create Identity from 32-byte secret key.
  ///
  /// # Panics
  ///
  /// Panics if the derived public key is a low-order point (mathematically
  /// impossible with proper X25519 clamping - indicates a bug in crypto library).
  pub fn from_bytes(bytes: &[u8; 32]) -> Self {
    Self::try_from_bytes(bytes).expect("derived public key is low-order (crypto library bug)")
  }

  /// Return the 32-byte secret key for backup/serialization
  ///
  /// IMPORTANT: This is the secret that backs up the entire identity.
  /// Encrypt this before writing to disk.
  pub fn to_bytes(&self) -> [u8; 32] {
    self.x25519_secret.to_bytes()
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
    let bytes = [42u8; 32];

    let id1 = Identity::from_bytes(&bytes);
    let id2 = Identity::from_bytes(&bytes);

    // Same bytes should produce identical identities
    assert_eq!(id1.public_id(), id2.public_id());
    assert_eq!(id1.to_bytes(), id2.to_bytes());
    assert_eq!(id1.x25519_secret.to_bytes(), id2.x25519_secret.to_bytes());
  }

  #[test]
  fn bytes_roundtrip() {
    let id1 = Identity::generate();
    let bytes = id1.to_bytes();

    // Recreate from bytes
    let id2 = Identity::from_bytes(&bytes);

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

    // Deserialize from bytes (valid key, so unwrap is safe)
    let restored = PublicID::try_from_bytes(&bytes).unwrap();

    // Should be equal
    assert_eq!(public_id, &restored);
    assert_eq!(public_id.x25519_public(), restored.x25519_public());

    // XEdDSA signature verification should work
    let msg = b"test message";
    let sig = id.sign_xeddsa(msg);
    assert!(restored.verify_xeddsa(msg, &sig));
  }

  #[test]
  fn try_from_bytes_rejects_low_order_points() {
    use super::InvalidPublicKey;

    // Zero point (low-order)
    let zero = [0u8; 32];
    assert_eq!(PublicID::try_from_bytes(&zero), Err(InvalidPublicKey));

    // Identity point (low-order)
    let mut one = [0u8; 32];
    one[0] = 1;
    assert_eq!(PublicID::try_from_bytes(&one), Err(InvalidPublicKey));

    // Valid random key should succeed
    let id = Identity::generate();
    let valid_bytes = id.public_id().to_bytes();
    assert!(PublicID::try_from_bytes(&valid_bytes).is_ok());
  }
}