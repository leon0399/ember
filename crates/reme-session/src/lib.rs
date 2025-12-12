use hkdf::Hkdf;
use reme_identity::{Identity, PublicID};
use reme_prekeys::{LocalPrekeySecrets, SignedPrekeyBundle, SignedPrekeyID};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

/// A symmetric session derived from X3DH key exchange
#[derive(Debug, Clone)]
pub struct Session {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    ephemeral_public: X25519PublicKey,
    used_one_time_prekey_id: Option<SignedPrekeyID>,
    /// Whether this session has been confirmed (first message sent/received)
    confirmed: bool,
}

impl Session {
    /// Create a session from raw keys (for storage reconstruction)
    pub fn from_keys(
        send_key: [u8; 32],
        recv_key: [u8; 32],
        ephemeral_public: [u8; 32],
        used_one_time_prekey_id: Option<SignedPrekeyID>,
    ) -> Self {
        Self {
            send_key,
            recv_key,
            ephemeral_public: X25519PublicKey::from(ephemeral_public),
            used_one_time_prekey_id,
            confirmed: true, // Reconstructed sessions are already confirmed
        }
    }

    pub fn send_key(&self) -> &[u8; 32] {
        &self.send_key
    }

    pub fn recv_key(&self) -> &[u8; 32] {
        &self.recv_key
    }

    pub fn ephemeral_public(&self) -> &X25519PublicKey {
        &self.ephemeral_public
    }

    pub fn used_one_time_prekey_id(&self) -> Option<SignedPrekeyID> {
        self.used_one_time_prekey_id
    }

    /// Check if this session has been confirmed (first message exchanged)
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// Mark this session as confirmed
    pub fn set_confirmed(&mut self) {
        self.confirmed = true;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Invalid prekey bundle")]
    InvalidBundle,
    #[error("One-time prekey not found")]
    OneTimePrekeyNotFound,
}

/// Initiator side: Alice creates a session with Bob's prekey bundle
pub fn derive_session_as_initiator(
    alice_identity: &Identity,
    bob_bundle: &SignedPrekeyBundle,
    use_one_time_prekey: bool,
) -> Result<Session, SessionError> {
    let mut rng = rand_core::OsRng;

    // Alice generates ephemeral key
    let ephemeral_secret = X25519Secret::random_from_rng(&mut rng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // Extract Bob's public keys
    // id_pub is now just 32 bytes (X25519 key directly)
    let bob_id_pub = X25519PublicKey::from(*bob_bundle.id_pub());
    let bob_signed_prekey = X25519PublicKey::from(*bob_bundle.signed_prekey_pub());

    // Perform DH operations
    // DH1 = id_A × sp_B
    let dh1 = alice_identity.x25519_secret().diffie_hellman(&bob_signed_prekey);

    // DH2 = eph_A × id_B
    let dh2 = ephemeral_secret.diffie_hellman(&bob_id_pub);

    // DH3 = eph_A × sp_B
    let dh3 = ephemeral_secret.diffie_hellman(&bob_signed_prekey);

    // DH4 = eph_A × otp_B (optional)
    let (dh4, used_otp_id) = if use_one_time_prekey {
        let one_time_prekeys = bob_bundle.one_time_prekeys();
        if let Some((otp_id, otp_pub_bytes)) = one_time_prekeys.first() {
            let otp_pub = X25519PublicKey::from(*otp_pub_bytes);
            let dh4 = ephemeral_secret.diffie_hellman(&otp_pub);
            (Some(dh4.to_bytes()), Some(*otp_id))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    // Concatenate DH outputs
    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());
    if let Some(dh4_bytes) = dh4 {
        dh_concat.extend_from_slice(&dh4_bytes);
    }

    // Derive keys using HKDF
    let hkdf = Hkdf::<Sha256>::new(None, &dh_concat);
    let mut okm = [0u8; 64];
    hkdf.expand(b"ResilientMessenger-X3DH-v0.1", &mut okm)
        .map_err(|_| SessionError::InvalidBundle)?;

    let send_key: [u8; 32] = okm[0..32].try_into().unwrap();
    let recv_key: [u8; 32] = okm[32..64].try_into().unwrap();

    Ok(Session {
        send_key,
        recv_key,
        ephemeral_public,
        used_one_time_prekey_id: used_otp_id,
        confirmed: false, // Not confirmed until first message is sent
    })
}

/// Responder side: Bob derives session from Alice's ephemeral key and his local secrets
pub fn derive_session_as_responder(
    bob_identity: &Identity,
    bob_secrets: &LocalPrekeySecrets,
    alice_id: &PublicID,
    alice_ephemeral: &X25519PublicKey,
    used_one_time_prekey_id: Option<SignedPrekeyID>,
) -> Result<Session, SessionError> {
    // Perform DH operations (reverse of initiator)
    // DH1 = sp_B × id_A
    let alice_id_pub = alice_id.x25519_public();
    let dh1 = bob_secrets.signed_prekey_secret().diffie_hellman(&alice_id_pub);

    // DH2 = id_B × eph_A
    let dh2 = bob_identity.x25519_secret().diffie_hellman(alice_ephemeral);

    // DH3 = sp_B × eph_A
    let dh3 = bob_secrets.signed_prekey_secret().diffie_hellman(alice_ephemeral);

    // DH4 = otp_B × eph_A (if one-time prekey was used)
    let dh4 = if let Some(otp_id) = used_one_time_prekey_id {
        let otp_secret = bob_secrets.find_one_time_prekey(otp_id)
            .ok_or(SessionError::OneTimePrekeyNotFound)?;
        Some(otp_secret.diffie_hellman(alice_ephemeral).to_bytes())
    } else {
        None
    };

    // Concatenate DH outputs
    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());
    if let Some(dh4_bytes) = dh4 {
        dh_concat.extend_from_slice(&dh4_bytes);
    }

    // Derive keys using HKDF
    let hkdf = Hkdf::<Sha256>::new(None, &dh_concat);
    let mut okm = [0u8; 64];
    hkdf.expand(b"ResilientMessenger-X3DH-v0.1", &mut okm)
        .map_err(|_| SessionError::InvalidBundle)?;

    // Note: Keys are swapped for responder (send/recv reversed)
    let recv_key: [u8; 32] = okm[0..32].try_into().unwrap();
    let send_key: [u8; 32] = okm[32..64].try_into().unwrap();

    Ok(Session {
        send_key,
        recv_key,
        ephemeral_public: *alice_ephemeral,
        used_one_time_prekey_id,
        confirmed: true, // Responder session is confirmed when first message is received
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_prekeys::generate_prekey_bundle;

    #[test]
    fn test_x3dh_session_derivation() {
        // Generate identities
        let alice = Identity::generate();
        let bob = Identity::generate();

        // Bob generates prekey bundle
        let (bob_secrets, bob_bundle) = generate_prekey_bundle(&bob, 5);

        // Alice initiates session
        let alice_session = derive_session_as_initiator(&alice, &bob_bundle, true).unwrap();

        // Bob derives session
        let bob_session = derive_session_as_responder(
            &bob,
            &bob_secrets,
            alice.public_id(),
            alice_session.ephemeral_public(),
            alice_session.used_one_time_prekey_id(),
        ).unwrap();

        // Verify keys match (Alice's send = Bob's recv, Alice's recv = Bob's send)
        assert_eq!(alice_session.send_key(), bob_session.recv_key());
        assert_eq!(alice_session.recv_key(), bob_session.send_key());
    }

    #[test]
    fn test_x3dh_without_one_time_prekey() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let (bob_secrets, bob_bundle) = generate_prekey_bundle(&bob, 0);

        let alice_session = derive_session_as_initiator(&alice, &bob_bundle, false).unwrap();

        let bob_session = derive_session_as_responder(
            &bob,
            &bob_secrets,
            alice.public_id(),
            alice_session.ephemeral_public(),
            None,
        ).unwrap();

        assert_eq!(alice_session.send_key(), bob_session.recv_key());
        assert_eq!(alice_session.recv_key(), bob_session.send_key());
        assert!(alice_session.used_one_time_prekey_id().is_none());
    }
}
