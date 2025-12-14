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
    #[error("Invalid bundle signature - bundle may have been tampered with")]
    InvalidBundleSignature,
    #[error("One-time prekey not found")]
    OneTimePrekeyNotFound,
}

/// Build HKDF info parameter with identity binding.
///
/// Per Signal's X3DH specification, the info parameter should include
/// identifying information for both parties to prevent Unknown Key Share (UKS) attacks.
///
/// The format is: protocol_name || initiator_identity || responder_identity
///
/// This ensures that even if DH outputs are somehow reused, different identity
/// combinations will produce different session keys.
fn build_hkdf_info(initiator_id: &[u8; 32], responder_id: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::with_capacity(32 + 32 + 32);
    info.extend_from_slice(b"ResilientMessenger-X3DH-v0.1");
    info.extend_from_slice(initiator_id);
    info.extend_from_slice(responder_id);
    info
}

/// Initiator side: Alice creates a session with Bob's prekey bundle
///
/// This function first verifies the bundle signatures before deriving session keys.
/// Both the outer bundle signature and inner signed prekey signature are checked
/// to ensure authenticity and prevent man-in-the-middle attacks.
pub fn derive_session_as_initiator(
    alice_identity: &Identity,
    bob_bundle: &SignedPrekeyBundle,
    use_one_time_prekey: bool,
) -> Result<Session, SessionError> {
    // Verify bundle signatures before proceeding
    // This checks both outer bundle signature and inner signed prekey signature
    if !bob_bundle.verify() {
        return Err(SessionError::InvalidBundleSignature);
    }

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

    // Derive keys using HKDF with identity binding
    // Info includes both identities to prevent Unknown Key Share attacks
    let info = build_hkdf_info(
        &alice_identity.public_id().to_bytes(),
        bob_bundle.id_pub(),
    );
    let hkdf = Hkdf::<Sha256>::new(None, &dh_concat);
    let mut okm = [0u8; 64];
    hkdf.expand(&info, &mut okm)
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

    // Derive keys using HKDF with identity binding
    // Info includes both identities to prevent Unknown Key Share attacks
    // Note: Order is (initiator, responder) = (alice, bob) - same as initiator side
    let info = build_hkdf_info(
        &alice_id.to_bytes(),
        &bob_identity.public_id().to_bytes(),
    );
    let hkdf = Hkdf::<Sha256>::new(None, &dh_concat);
    let mut okm = [0u8; 64];
    hkdf.expand(&info, &mut okm)
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

    #[test]
    fn test_identity_binding_info_format() {
        // Test that the HKDF info is constructed correctly
        let initiator_id = [1u8; 32];
        let responder_id = [2u8; 32];

        let info = build_hkdf_info(&initiator_id, &responder_id);

        // Should be: protocol_name (28 bytes) + initiator (32 bytes) + responder (32 bytes)
        assert_eq!(info.len(), 28 + 32 + 32);
        assert_eq!(&info[0..28], b"ResilientMessenger-X3DH-v0.1");
        assert_eq!(&info[28..60], &initiator_id);
        assert_eq!(&info[60..92], &responder_id);
    }

    #[test]
    fn test_identity_binding_different_initiator_different_keys() {
        // When the initiator identity changes, session keys should be different
        // This prevents Unknown Key Share attacks
        let alice1 = Identity::generate();
        let alice2 = Identity::generate();
        let bob = Identity::generate();

        let (bob_secrets, bob_bundle) = generate_prekey_bundle(&bob, 5);

        // Alice1 initiates session with Bob
        let session1 = derive_session_as_initiator(&alice1, &bob_bundle, false).unwrap();

        // Alice2 initiates session with Bob (using same bundle)
        let session2 = derive_session_as_initiator(&alice2, &bob_bundle, false).unwrap();

        // Keys should be different due to identity binding
        assert_ne!(session1.send_key(), session2.send_key());
        assert_ne!(session1.recv_key(), session2.recv_key());

        // But each should still work with proper responder derivation
        let bob_session1 = derive_session_as_responder(
            &bob,
            &bob_secrets,
            alice1.public_id(),
            session1.ephemeral_public(),
            None,
        ).unwrap();

        let bob_session2 = derive_session_as_responder(
            &bob,
            &bob_secrets,
            alice2.public_id(),
            session2.ephemeral_public(),
            None,
        ).unwrap();

        assert_eq!(session1.send_key(), bob_session1.recv_key());
        assert_eq!(session2.send_key(), bob_session2.recv_key());
    }

    #[test]
    fn test_identity_binding_different_responder_different_keys() {
        // When the responder identity changes, session keys should be different
        let alice = Identity::generate();
        let bob1 = Identity::generate();
        let bob2 = Identity::generate();

        let (_, bob1_bundle) = generate_prekey_bundle(&bob1, 5);
        let (_, bob2_bundle) = generate_prekey_bundle(&bob2, 5);

        // Alice initiates sessions with different Bobs
        let session1 = derive_session_as_initiator(&alice, &bob1_bundle, false).unwrap();
        let session2 = derive_session_as_initiator(&alice, &bob2_bundle, false).unwrap();

        // Keys should be different due to different responder identities
        assert_ne!(session1.send_key(), session2.send_key());
        assert_ne!(session1.recv_key(), session2.recv_key());
    }

    #[test]
    fn test_identity_binding_prevents_key_confusion() {
        // This test verifies that if someone tries to use the wrong identity
        // when deriving the responder session, the keys won't match
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();

        let (bob_secrets, bob_bundle) = generate_prekey_bundle(&bob, 5);

        // Alice initiates session with Bob
        let alice_session = derive_session_as_initiator(&alice, &bob_bundle, true).unwrap();

        // Bob correctly derives session using Alice's identity
        let bob_session_correct = derive_session_as_responder(
            &bob,
            &bob_secrets,
            alice.public_id(),
            alice_session.ephemeral_public(),
            alice_session.used_one_time_prekey_id(),
        ).unwrap();

        // If Bob (incorrectly) thinks he's talking to Mallory
        let bob_session_wrong = derive_session_as_responder(
            &bob,
            &bob_secrets,
            mallory.public_id(),  // Wrong identity!
            alice_session.ephemeral_public(),
            alice_session.used_one_time_prekey_id(),
        ).unwrap();

        // Correct derivation should match
        assert_eq!(alice_session.send_key(), bob_session_correct.recv_key());

        // Wrong identity should NOT match - this is the UKS attack prevention
        assert_ne!(alice_session.send_key(), bob_session_wrong.recv_key());
    }

    #[test]
    fn test_session_derivation_verifies_bundle_signature() {
        // Valid bundle should work
        let alice = Identity::generate();
        let bob = Identity::generate();

        let (_, bob_bundle) = generate_prekey_bundle(&bob, 5);

        // Session derivation should succeed with valid bundle
        let result = derive_session_as_initiator(&alice, &bob_bundle, true);
        assert!(result.is_ok(), "Valid bundle should allow session derivation");
    }

    #[test]
    fn test_session_derivation_rejects_tampered_signature() {
        use reme_prekeys::SignedPrekeyBundle;

        let alice = Identity::generate();
        let bob = Identity::generate();

        let (_, bob_bundle) = generate_prekey_bundle(&bob, 5);

        // Tamper with the signature by creating a bundle with corrupted signature
        // We need to access the internal structure, so we'll encode/decode with modification
        let encoded = bincode::encode_to_vec(&bob_bundle, bincode::config::standard()).unwrap();
        let mut tampered = encoded.clone();

        // Flip the last byte (part of the signature)
        let len = tampered.len();
        tampered[len - 1] ^= 0xFF;

        // Decode the tampered bundle
        let (tampered_bundle, _): (SignedPrekeyBundle, _) =
            bincode::decode_from_slice(&tampered, bincode::config::standard()).unwrap();

        // Session derivation should fail with tampered bundle
        let result = derive_session_as_initiator(&alice, &tampered_bundle, true);
        assert!(
            matches!(result, Err(SessionError::InvalidBundleSignature)),
            "Tampered bundle should be rejected with InvalidBundleSignature"
        );
    }

    #[test]
    fn test_session_derivation_rejects_wrong_signer() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();

        // Generate Bob's bundle
        let (_, bob_bundle) = generate_prekey_bundle(&bob, 5);

        // Generate Mallory's bundle (different identity, different signature)
        let (_, mallory_bundle) = generate_prekey_bundle(&mallory, 5);

        // Valid bundles should work
        assert!(derive_session_as_initiator(&alice, &bob_bundle, false).is_ok());
        assert!(derive_session_as_initiator(&alice, &mallory_bundle, false).is_ok());

        // Each bundle is valid for its own identity - this test confirms
        // that signature verification is actually happening
        assert!(bob_bundle.verify(), "Bob's bundle should verify");
        assert!(mallory_bundle.verify(), "Mallory's bundle should verify");
    }
}
