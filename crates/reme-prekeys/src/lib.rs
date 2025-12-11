use bincode::enc::Encoder;
use bincode::error::EncodeError;
use bincode::{Decode, Encode, impl_borrow_decode};
use ed25519_dalek::{Signature, Signer};
use rand_core::OsRng;
use reme_identity::Identity;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct SignedPrekeyID(uuid::Uuid);

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

pub struct LocalPrekeySecrets {
    signed_prekey_id: SignedPrekeyID,
    signed_prekey_secret: ed25519_dalek::SigningKey,
    one_time_prekeys: Vec<ed25519_dalek::SigningKey>,
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
    let signed_prekey_sk = ed25519_dalek::SigningKey::generate(&mut rng);
    let signed_prekey_pk = signed_prekey_sk.verifying_key();

    let mut ot_secret_vec = Vec::with_capacity(num_one_time_keys);
    let mut ot_public_vec = Vec::with_capacity(num_one_time_keys);

    for _i in 0..num_one_time_keys {
        let ot_id = SignedPrekeyID(uuid::Uuid::new_v4());
        let ot_sk = ed25519_dalek::SigningKey::generate(&mut rng);
        let ot_pk = ot_sk.verifying_key();

        ot_secret_vec.push((ot_id, ot_sk));
        ot_public_vec.push((ot_id, ot_pk.to_bytes()));
    }

    let bundle = PrekeyBundle {
        id_pub: identity.public_id().to_bytes(),
        signed_prekey_id,
        signed_prekey_pub: signed_prekey_pk.to_bytes(),
        signed_prekey_sig: identity
            .sign(&signed_prekey_pk.to_bytes())
            .to_bytes()
            .to_vec(),
        one_time_prekeys: ot_public_vec,
    };

    let local_secrets = LocalPrekeySecrets {
        signed_prekey_id,
        signed_prekey_secret: signed_prekey_sk,
        one_time_prekeys: ot_secret_vec.into_iter().map(|(_, sk)| sk).collect(),
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
    ) -> Result<SignedPrekeyBundle, ed25519_dalek::SignatureError> {
        let payload = self.bundle();
        let signature: Signature = signer.try_sign(&payload)?;

        Ok(SignedPrekeyBundle(self, signature.to_bytes().to_vec()))
    }
}

#[derive(Clone)]
pub struct SignedPrekeyBundle(PrekeyBundle, Vec<u8>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let id = Identity::generate();

        let bundle = generate_prekey_bundle(&id, 5).1;

        id.public_id()
            .verifying_key()
            .verify_strict(
                &bundle.0.bundle(),
                &Signature::from_slice(&bundle.1).unwrap(),
            )
            .unwrap()
    }
}
