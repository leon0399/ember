use std::fmt::Debug;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ed25519_dalek::ed25519::Error;
use getset::Getters;
use rand_core::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

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

#[derive(Getters)]
pub struct Identity {
  #[get = "pub"]
  pub(crate) public_id: PublicID,
  pub(crate) signing_key: SigningKey,
  pub(crate) x25519_secret: X25519Secret,
}

impl Debug for Identity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Identity")
      .field("public_id", &self.public_id)
      .field("signing_key", &"[REDACTED]")
      .field("x25519_secret", &"[REDACTED]")
      .finish()
  }
}

impl Identity {
  pub fn x25519_secret(&self) -> &X25519Secret {
    &self.x25519_secret
  }
}

impl Identity {
  pub fn generate() -> Self {
    // Use the OS randomness source directly; OsRng implements RngCore + CryptoRng
    let mut rng = OsRng;

    // Generate Ed25519 keypair for signing
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    // Generate X25519 keypair for encryption (DH key agreement)
    let x25519_secret = X25519Secret::random_from_rng(&mut rng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    let public_id = PublicID::from((verifying_key, x25519_public));

    Self {
      public_id,
      signing_key,
      x25519_secret,
    }
  }

  /// Create Identity from 64 bytes: first 32 for Ed25519, last 32 for X25519
  pub fn from_bytes(bytes: &[u8; 64]) -> Self {
    let (ed25519_bytes, x25519_bytes) = bytes.split_at(32);

    let signing_key = SigningKey::from_bytes(ed25519_bytes.try_into().expect("slice with incorrect length"));
    let verifying_key = signing_key.verifying_key();

    let x25519_secret = X25519Secret::from(*<&[u8; 32]>::try_from(x25519_bytes).expect("slice with incorrect length"));
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    let public_id = PublicID::from((verifying_key, x25519_public));

    Self {
      public_id,
      signing_key,
      x25519_secret,
    }
  }

  /// Return raw secret key bytes (64 bytes: first 32 for Ed25519, last 32 for X25519).
  ///
  /// IMPORTANT: you should encrypt these before writing to disk.
  pub fn to_bytes(&self) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    bytes[0..32].copy_from_slice(&self.signing_key.to_bytes());
    bytes[32..64].copy_from_slice(&self.x25519_secret.to_bytes());
    bytes
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
}