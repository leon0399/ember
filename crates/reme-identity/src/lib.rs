use std::fmt::Debug;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use getset::Getters;
use rand_core::OsRng;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Getters)]
pub struct PublicID {
  #[get = "pub(crate)"]
  pub(crate) verifying_key: VerifyingKey,
}

impl PublicID {
  pub fn to_bytes(&self) -> [u8; 32] {
    self.verifying_key.to_bytes()
  }

  pub fn fingerprint(&self) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&self.to_bytes());
    let hash = hasher.finalize(); // 32 bytes

    hex::encode(hash.as_bytes())
  }
}

impl From<VerifyingKey> for PublicID {
  fn from(value: VerifyingKey) -> Self {
    Self {
      verifying_key: value,
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
  #[get(public)]
  pub(crate) public_id: PublicID,
  pub(crate) signing_key: SigningKey,
}

impl Debug for Identity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Identity")
      .field("public_id", &self.public_id)
      .field("private_key", &"[REDACTED]")
      .finish()
  }
}

impl Identity {
  pub fn generate() -> Self {
    // Use the OS randomness source directly; OsRng implements RngCore + CryptoRng
    let mut rng = OsRng;

    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let public_id = PublicID::from(verifying_key);

    Self {
      public_id,
      signing_key,
    }
  }

  /// Sign arbitrary data with this identity's private key.
  ///
  /// Sign prekeys, config, etc.
  pub fn sign(&self, msg: &[u8]) -> ed25519_dalek::Signature {
    self.signing_key.sign(msg)
  }

  pub fn from_bytes(bytes: &[u8; 32]) -> Self {
    let signing_key = SigningKey::from_bytes(bytes);
    let verifying_key = signing_key.verifying_key();
    let public_id = PublicID::from(verifying_key);

    Self {
      public_id,
      signing_key,
    }
  }

  /// Return raw secret key bytes (for storage/backup).
  ///
  /// IMPORTANT: you should encrypt these before writing to disk.
  pub fn to_bytes(&self) -> [u8; 32] {
    self.signing_key.to_bytes()
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