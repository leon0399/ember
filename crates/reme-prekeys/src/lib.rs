use bincode::enc::Encoder;
use bincode::error::EncodeError;
use bincode::{Decode, Encode, impl_borrow_decode};
use rand_core::OsRng;
use reme_identity::Identity;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

#[derive(Debug, Clone, Copy)]
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
    signed_prekey_secret: X25519Secret,
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

#[derive(Clone)]
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
}
