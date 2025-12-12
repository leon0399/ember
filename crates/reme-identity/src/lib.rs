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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Getters)]
pub struct PublicID {
  #[get = "pub"]
  pub(crate) verifying_key: VerifyingKey,
  #[get = "pub"]
  pub(crate) x25519_public: X25519PublicKey,
}

impl PublicID {
  pub fn to_bytes(&self) -> [u8; 32] {
    self.verifying_key.to_bytes()
  }

  pub fn x25519_to_bytes(&self) -> [u8; 32] {
    self.x25519_public.to_bytes()
  }

  pub fn fingerprint(&self) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&self.to_bytes());
    hasher.update(&self.x25519_to_bytes());
    let hash = hasher.finalize(); // 32 bytes

    hex::encode(hash.as_bytes())
  }
}

impl From<(VerifyingKey, X25519PublicKey)> for PublicID {
  fn from((verifying_key, x25519_public): (VerifyingKey, X25519PublicKey)) -> Self {
    Self {
      verifying_key,
      x25519_public,
    }
  }
}

impl From<&PublicID> for VerifyingKey {
  fn from(value: &PublicID) -> Self {
    value.verifying_key.clone()
  }
}

impl AsRef<VerifyingKey> for PublicID {
  fn as_ref(&self) -> &VerifyingKey {
    &self.verifying_key
  }
}

// Implement bincode Encode/Decode for PublicID
impl Encode for PublicID {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        // Encode Ed25519 public key (32 bytes)
        self.to_bytes().encode(encoder)?;
        // Encode X25519 public key (32 bytes)
        self.x25519_to_bytes().encode(encoder)?;
        Ok(())
    }
}

impl<Context> Decode<Context> for PublicID {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let ed25519_bytes: [u8; 32] = Decode::decode(decoder)?;
        let x25519_bytes: [u8; 32] = Decode::decode(decoder)?;

        let verifying_key = VerifyingKey::from_bytes(&ed25519_bytes)
            .map_err(|_| DecodeError::Other("Invalid Ed25519 public key"))?;
        let x25519_public = X25519PublicKey::from(x25519_bytes);

        Ok(PublicID::from((verifying_key, x25519_public)))
    }
}

impl<'de, Context> bincode::BorrowDecode<'de, Context> for PublicID {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        let ed25519_bytes: [u8; 32] = bincode::BorrowDecode::borrow_decode(decoder)?;
        let x25519_bytes: [u8; 32] = bincode::BorrowDecode::borrow_decode(decoder)?;

        let verifying_key = VerifyingKey::from_bytes(&ed25519_bytes)
            .map_err(|_| DecodeError::Other("Invalid Ed25519 public key"))?;
        let x25519_public = X25519PublicKey::from(x25519_bytes);

        Ok(PublicID::from((verifying_key, x25519_public)))
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
  /// This follows Signal Protocol's approach with domain separation:
  /// - Ed25519 seed: HKDF(seed, info="reme-ed25519-identity-v1")
  /// - X25519 seed: HKDF(seed, info="reme-x25519-identity-v1")
  pub fn from_seed(seed: &[u8; 32]) -> Self {
    // Derive Ed25519 signing key
    let hkdf_ed25519 = Hkdf::<Sha256>::new(None, seed);
    let mut ed25519_seed = [0u8; 32];
    hkdf_ed25519
      .expand(b"reme-ed25519-identity-v1", &mut ed25519_seed)
      .expect("HKDF expand should never fail for 32 bytes");

    let signing_key = SigningKey::from_bytes(&ed25519_seed);
    let verifying_key = signing_key.verifying_key();

    // Derive X25519 encryption key
    let hkdf_x25519 = Hkdf::<Sha256>::new(None, seed);
    let mut x25519_seed = [0u8; 32];
    hkdf_x25519
      .expand(b"reme-x25519-identity-v1", &mut x25519_seed)
      .expect("HKDF expand should never fail for 32 bytes");

    let x25519_secret = X25519Secret::from(x25519_seed);
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    let public_id = PublicID::from((verifying_key, x25519_public));

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

    // verify via public id
    id.public_id()
      .verifying_key()
      .verify_strict(msg, &sig)
      .unwrap();
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
}