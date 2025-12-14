use bincode::enc::Encoder;
use bincode::error::EncodeError;
use bincode::{Decode, Encode, impl_borrow_decode};
use rand_core::OsRng;
use reme_identity::{Identity, PublicID};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(transparent)]
pub struct SignedPrekeyID(uuid::Uuid);

impl SignedPrekeyID {
    /// Get the ID as bytes
    pub fn to_bytes(&self) -> [u8; 16] {
        *self.0.as_bytes()
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        SignedPrekeyID(uuid::Uuid::from_bytes(bytes))
    }
}

impl bincode::Encode for SignedPrekeyID {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.0.as_bytes().encode(encoder)
    }
}

impl<C> bincode::Decode<C> for SignedPrekeyID {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let bytes: [u8; 16] = Decode::decode(decoder)?;
        let uuid = uuid::Uuid::from_bytes(bytes);
        Ok(SignedPrekeyID(uuid))
    }
}

impl_borrow_decode!(SignedPrekeyID);

#[derive(Encode, Decode)]
pub struct LocalPrekeySecrets {
    signed_prekey_id: SignedPrekeyID,
    #[bincode(with_serde)]
    signed_prekey_secret: X25519Secret,
    #[bincode(with_serde)]
    one_time_prekeys: Vec<(SignedPrekeyID, X25519Secret)>,
}

impl LocalPrekeySecrets {
    pub fn signed_prekey_id(&self) -> SignedPrekeyID {
        self.signed_prekey_id
    }

    pub fn signed_prekey_secret(&self) -> &X25519Secret {
        &self.signed_prekey_secret
    }

    pub fn find_one_time_prekey(&self, id: SignedPrekeyID) -> Option<&X25519Secret> {
        self.one_time_prekeys.iter()
            .find(|(ot_id, _)| ot_id.0 == id.0)
            .map(|(_, secret)| secret)
    }
}

#[derive(Clone, Encode, Decode)]
pub struct PrekeyBundle {
    id_pub: [u8; 32],

    signed_prekey_id: SignedPrekeyID,

    signed_prekey_pub: [u8; 32],
    signed_prekey_sig: Vec<u8>,

    one_time_prekeys: Vec<(SignedPrekeyID, [u8; 32])>,
}

pub fn generate_prekey_bundle(
    identity: &Identity,
    num_one_time_keys: usize,
) -> (LocalPrekeySecrets, SignedPrekeyBundle) {
    let mut rng = OsRng;

    let signed_prekey_id = SignedPrekeyID(uuid::Uuid::new_v4());
    let signed_prekey_sk = X25519Secret::random_from_rng(&mut rng);
    let signed_prekey_pk = X25519PublicKey::from(&signed_prekey_sk);

    let mut ot_secret_vec = Vec::with_capacity(num_one_time_keys);
    let mut ot_public_vec = Vec::with_capacity(num_one_time_keys);

    for _i in 0..num_one_time_keys {
        let ot_id = SignedPrekeyID(uuid::Uuid::new_v4());
        let ot_sk = X25519Secret::random_from_rng(&mut rng);
        let ot_pk = X25519PublicKey::from(&ot_sk);

        ot_secret_vec.push((ot_id, ot_sk));
        ot_public_vec.push((ot_id, ot_pk.to_bytes()));
    }

    let bundle = PrekeyBundle {
        id_pub: identity.public_id().to_bytes(),
        signed_prekey_id,
        signed_prekey_pub: signed_prekey_pk.to_bytes(),
        signed_prekey_sig: identity
            .sign_xeddsa(&signed_prekey_pk.to_bytes())
            .to_vec(),
        one_time_prekeys: ot_public_vec,
    };

    let local_secrets = LocalPrekeySecrets {
        signed_prekey_id,
        signed_prekey_secret: signed_prekey_sk,
        one_time_prekeys: ot_secret_vec,
    };

    (local_secrets, bundle.try_sign(identity).unwrap())
}

impl PrekeyBundle {
    pub fn bundle(&self) -> Vec<u8> {
        bincode::encode_to_vec(
            &(
                &self.id_pub,
                &self.signed_prekey_id.0.as_fields(),
                &self.signed_prekey_pub,
                &self.signed_prekey_sig,
                &self
                    .one_time_prekeys
                    .iter()
                    .map(|(id, pk)| (id.0.as_fields(), pk))
                    .collect::<Vec<_>>(),
            ),
            bincode::config::standard(),
        )
        .unwrap()
    }

    pub fn try_sign(
        self: Self,
        signer: &Identity,
    ) -> Result<SignedPrekeyBundle, ()> {
        let payload = self.bundle();
        let signature = signer.sign_xeddsa(&payload);

        Ok(SignedPrekeyBundle(self, signature.to_vec()))
    }
}

#[derive(Clone, Encode, Decode)]
pub struct SignedPrekeyBundle(PrekeyBundle, Vec<u8>);

impl SignedPrekeyBundle {
    pub fn id_pub(&self) -> &[u8; 32] {
        &self.0.id_pub
    }

    pub fn signed_prekey_id(&self) -> SignedPrekeyID {
        self.0.signed_prekey_id
    }

    pub fn signed_prekey_pub(&self) -> &[u8; 32] {
        &self.0.signed_prekey_pub
    }

    pub fn one_time_prekeys(&self) -> &[(SignedPrekeyID, [u8; 32])] {
        &self.0.one_time_prekeys
    }

    pub fn signature(&self) -> &[u8] {
        &self.1
    }

    /// Verify the bundle signatures
    ///
    /// This verifies:
    /// 1. The outer bundle signature (self.1) against the bundle payload
    /// 2. The inner signed_prekey_sig against signed_prekey_pub
    ///
    /// Both signatures must be valid for the bundle to be considered authentic.
    /// This prevents:
    /// - Bundle tampering (outer signature)
    /// - Signed prekey substitution attacks (inner signature)
    pub fn verify(&self) -> bool {
        // Get the public ID from the bundle
        let public_id = PublicID::from_bytes(&self.0.id_pub);

        // Verify outer bundle signature (must be exactly 64 bytes)
        if self.1.len() != 64 {
            return false;
        }
        let outer_sig: [u8; 64] = match self.1[..64].try_into() {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        if !public_id.verify_xeddsa(&self.0.bundle(), &outer_sig) {
            return false;
        }

        // Verify inner signed prekey signature (must be exactly 64 bytes)
        if self.0.signed_prekey_sig.len() != 64 {
            return false;
        }
        let inner_sig: [u8; 64] = match self.0.signed_prekey_sig[..64].try_into() {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        public_id.verify_xeddsa(&self.0.signed_prekey_pub, &inner_sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let id = Identity::generate();

        let bundle = generate_prekey_bundle(&id, 5).1;

        // Verify XEdDSA signature
        let sig: [u8; 64] = bundle.1[..64].try_into().unwrap();
        assert!(id.public_id().verify_xeddsa(&bundle.0.bundle(), &sig));
    }

    #[test]
    fn verify_bundle_method() {
        let id = Identity::generate();
        let bundle = generate_prekey_bundle(&id, 5).1;

        // Valid bundle should verify
        assert!(bundle.verify(), "Valid bundle should verify");
    }

    #[test]
    fn verify_bundle_without_one_time_prekeys() {
        let id = Identity::generate();
        let bundle = generate_prekey_bundle(&id, 0).1;

        // Bundle without one-time prekeys should still verify
        assert!(bundle.verify(), "Bundle without OTPs should verify");
    }

    #[test]
    fn verify_bundle_rejects_tampered_outer_signature() {
        let id = Identity::generate();
        let (_, bundle) = generate_prekey_bundle(&id, 5);

        // Tamper with outer signature
        let mut tampered_sig = bundle.1.clone();
        tampered_sig[0] ^= 0xFF; // Flip bits

        let tampered_bundle = SignedPrekeyBundle(bundle.0, tampered_sig);
        assert!(!tampered_bundle.verify(), "Tampered outer signature should fail");
    }

    #[test]
    fn verify_bundle_rejects_wrong_identity_signature() {
        let alice = Identity::generate();
        let mallory = Identity::generate();

        // Generate bundle with Alice's identity
        let (_, bundle) = generate_prekey_bundle(&alice, 3);

        // Re-sign with Mallory's identity (outer signature only)
        let mallory_sig = mallory.sign_xeddsa(&bundle.0.bundle());

        let forged_bundle = SignedPrekeyBundle(bundle.0, mallory_sig.to_vec());

        // Should fail because id_pub is Alice's but outer sig is Mallory's
        assert!(!forged_bundle.verify(), "Wrong identity signature should fail");
    }

    #[test]
    fn verify_bundle_rejects_truncated_signature() {
        let id = Identity::generate();
        let (_, bundle) = generate_prekey_bundle(&id, 5);

        // Truncate outer signature
        let truncated_sig = bundle.1[..32].to_vec();

        let truncated_bundle = SignedPrekeyBundle(bundle.0, truncated_sig);
        assert!(!truncated_bundle.verify(), "Truncated signature should fail");
    }

    #[test]
    fn verify_bundle_rejects_empty_signature() {
        let id = Identity::generate();
        let (_, bundle) = generate_prekey_bundle(&id, 5);

        let empty_bundle = SignedPrekeyBundle(bundle.0, vec![]);
        assert!(!empty_bundle.verify(), "Empty signature should fail");
    }

    #[test]
    fn verify_prevents_signed_prekey_substitution() {
        // This test verifies that an attacker cannot substitute
        // a different signed prekey into a valid bundle
        let alice = Identity::generate();
        let mallory = Identity::generate();

        // Generate bundles for both
        let (_, alice_bundle) = generate_prekey_bundle(&alice, 3);
        let (_, mallory_bundle) = generate_prekey_bundle(&mallory, 3);

        // Try to substitute Mallory's signed prekey into Alice's bundle
        // This would require forging the inner signature which is bound to id_pub
        let substituted = PrekeyBundle {
            id_pub: alice_bundle.0.id_pub, // Keep Alice's identity
            signed_prekey_id: mallory_bundle.0.signed_prekey_id,
            signed_prekey_pub: mallory_bundle.0.signed_prekey_pub, // Mallory's prekey
            signed_prekey_sig: mallory_bundle.0.signed_prekey_sig.clone(), // Mallory's sig
            one_time_prekeys: alice_bundle.0.one_time_prekeys.clone(),
        };

        // Re-sign the outer bundle with Alice's key (attacker would need to do this)
        // But the inner sig is still wrong (signed by Mallory, not Alice)
        let outer_sig = alice.sign_xeddsa(&substituted.bundle());
        let forged_bundle = SignedPrekeyBundle(substituted, outer_sig.to_vec());

        // Should fail because inner signed_prekey_sig was made by Mallory, not Alice
        assert!(!forged_bundle.verify(), "Substituted signed prekey should fail");
    }
}
