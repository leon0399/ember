use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand_core::OsRng;
use reme_identity::{is_low_order_point, PublicID};
use reme_message::{bincode_config, InnerEnvelope, MessageID};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use xeddsa::{xed25519, Sign, Verify};

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid recipient public key (low-order point)")]
    InvalidRecipientKey,
    #[error("Invalid sender signature: message may be forged or tampered")]
    InvalidSenderSignature,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::error::EncodeError),
    #[error("Deserialization error: {0}")]
    DeserializationError(#[from] bincode::error::DecodeError),
}

/// Check if a shared secret is all zeros (indicates small-order input).
///
/// Per RFC 7748, implementations should check for all-zero output after
/// scalar multiplication as defense-in-depth against small-order points.
fn is_zero_shared_secret(shared_secret: &[u8; 32]) -> bool {
    shared_secret == &[0u8; 32]
}

/// Sign data with XEdDSA using an X25519 private key.
///
/// XEdDSA allows signing with X25519 keys by converting them to Ed25519-compatible
/// format internally. This enables using a single keypair for both DH and signatures.
fn xeddsa_sign(private_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let key = xed25519::PrivateKey(*private_key);
    key.sign(message, OsRng)
}

/// Verify an XEdDSA signature using an X25519 public key.
///
/// Returns true if the signature is valid, false otherwise.
fn xeddsa_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let key = xed25519::PublicKey(*public_key);
    key.verify(message, signature).is_ok()
}

// ============================================================================
// Public Outer Signature Functions
// ============================================================================

/// Sign outer envelope data with a commitment private key.
///
/// This creates an XEdDSA signature over the outer_signable_bytes that can
/// be verified by any node using the commitment_pub from the OuterEnvelope.
///
/// # Arguments
/// * `commitment_private` - 32-byte commitment private key from EncryptionOutput
/// * `outer_signable` - Bytes from OuterEnvelope::outer_signable_bytes()
///
/// # Returns
/// 64-byte XEdDSA signature
pub fn sign_outer_envelope(commitment_private: &[u8; 32], outer_signable: &[u8]) -> [u8; 64] {
    xeddsa_sign(commitment_private, outer_signable)
}

/// Verify an outer envelope signature using the commitment public key.
///
/// This allows relay nodes to verify outer envelope integrity without
/// knowing the sender's identity. The commitment_pub is anonymous -
/// it's derived from VRF output and is unlinkable to sender's identity.
///
/// # Arguments
/// * `commitment_pub` - 32-byte commitment public key from OuterEnvelope
/// * `outer_signable` - Bytes from OuterEnvelope::outer_signable_bytes()
/// * `signature` - 64-byte signature from OuterEnvelope.outer_signature
///
/// # Returns
/// true if signature is valid, false otherwise
pub fn verify_outer_envelope(
    commitment_pub: &[u8; 32],
    outer_signable: &[u8],
    signature: &[u8; 64],
) -> bool {
    xeddsa_verify(commitment_pub, outer_signable, signature)
}

// ============================================================================
// VXEdDSA Functions (for anonymous outer envelope verification)
// ============================================================================

/// Sign data with VXEdDSA, producing a signature and deterministic VRF output.
///
/// VXEdDSA extends XEdDSA with Verifiable Random Function (VRF) properties:
/// - Same (key, message) always produces the same VRF output
/// - Anyone with the public key can verify and recover the VRF output
/// - The VRF output looks random but is deterministically derived
///
/// Note: The underlying VXEdDSA implementation requires a 32-byte message.
/// Variable-length input is hashed to 32 bytes using BLAKE3 before signing.
///
/// Returns (signature: 96 bytes, vrf_output: 32 bytes)
fn vxeddsa_sign(private_key: &[u8; 32], message: &[u8]) -> ([u8; 96], [u8; 32]) {
    use libsignal_dezire::vxeddsa::vxeddsa_sign as ffi_sign;

    // Hash message to 32 bytes (VXEdDSA requires fixed-size message)
    let message_hash: [u8; 32] = *blake3::hash(message).as_bytes();

    // VXEdDSA sign - may panic if scalar is zero (extremely unlikely)
    let output = ffi_sign(private_key, &message_hash);

    (output.signature, output.vrf)
}

/// Verify a VXEdDSA signature and recover the VRF output.
///
/// If verification succeeds, returns Some(vrf_output) where vrf_output is the
/// deterministic 32-byte VRF value for this (public_key, message) pair.
///
/// If verification fails, returns None.
///
/// Note: The message is hashed to 32 bytes using BLAKE3 (same as during signing).
fn vxeddsa_verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 96],
) -> Option<[u8; 32]> {
    use libsignal_dezire::vxeddsa::vxeddsa_verify as ffi_verify;

    // Hash message to 32 bytes (same as during signing)
    let message_hash: [u8; 32] = *blake3::hash(message).as_bytes();

    let mut vrf_output = [0u8; 32];

    // VXEdDSA verify - writes VRF output to pointer if valid
    let valid = ffi_verify(public_key, &message_hash, signature, &mut vrf_output);

    if valid {
        Some(vrf_output)
    } else {
        None
    }
}

/// Derive a commitment keypair from a VRF output.
///
/// This derives a deterministic X25519 keypair from the VRF output, which can be
/// used for anonymous outer envelope signing. The commitment key is:
/// - Unlinkable to the sender's identity (derived from VRF output)
/// - Deterministic for the same (sender, message_id) pair
/// - Verifiable by recipient (who can recover VRF output via VXEdDSA verification)
///
/// Returns (commitment_private: 32 bytes, commitment_public: 32 bytes)
fn derive_commitment_key(vrf_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Derive private key from VRF output using domain-separated KDF
    let commitment_private = blake3::derive_key("reme-commitment-v1", vrf_output);

    // Derive public key from private key
    let secret = StaticSecret::from(commitment_private);
    let public = X25519PublicKey::from(&secret);

    (commitment_private, *public.as_bytes())
}

/// Output from encrypt_to_mik containing all encryption artifacts.
///
/// The commitment data (when present) enables anonymous outer envelope
/// verification by relay nodes.
#[derive(Debug)]
pub struct EncryptionOutput {
    /// Ephemeral X25519 public key for this message
    pub ephemeral_public: [u8; 32],
    /// Encrypted inner envelope (includes inner signature + derivation proof)
    pub ciphertext: Vec<u8>,
    /// Commitment private key for signing outer envelope (None if VXEdDSA disabled)
    pub commitment_private: Option<[u8; 32]>,
    /// Commitment public key for outer signature verification (None if VXEdDSA disabled)
    pub commitment_public: Option<[u8; 32]>,
}

/// Output from decrypt_with_mik containing decrypted envelope and optional derivation proof.
#[derive(Debug)]
pub struct DecryptionOutput {
    /// The decrypted inner envelope
    pub inner_envelope: InnerEnvelope,
    /// VXEdDSA derivation signature (96 bytes) proving commitment_pub was derived by sender.
    /// Present only when commitment_pub was provided during decryption.
    /// Use verify_commitment_binding() to verify this proof.
    pub derivation_sig: Option<[u8; 96]>,
}

/// Encrypt an InnerEnvelope to a recipient's MIK (stateless encryption)
///
/// This implements Session V1-style sealed box encryption with triple binding:
/// 1. Generates an ephemeral X25519 keypair (e, E)
/// 2. Computes shared_secret = X25519(e, recipient_MIK)
/// 3. Derives encryption key from shared_secret using blake3
/// 4. Signs the serialized envelope || message_id || commitment_pub with XEdDSA
/// 5. Encrypts (serialized_envelope || signature || derivation_sig) with ChaCha20Poly1305
///
/// Triple binding (message_id bound via):
/// - Nonce derivation: nonce = BLAKE3(context, message_id || recipient_pk)
/// - AAD: message_id passed as additional authenticated data
/// - Signature: message_id included in signed data
///
/// ## Anonymous Outer Verification (VXEdDSA)
///
/// When enabled (default), also generates commitment key via VXEdDSA:
/// 1. Generate VXEdDSA(sender_priv, message_id) → (derivation_sig, vrf_output)
/// 2. Derive commitment keypair from vrf_output
/// 3. Include commitment_pub in inner signature (recipient can verify commitment binding)
/// 4. Include derivation_sig (96 bytes) in encrypted payload (proof for recipient)
/// 5. Return commitment_priv/pub for caller to sign outer envelope
///
/// Returns EncryptionOutput containing all artifacts needed for OuterEnvelope creation.
pub fn encrypt_to_mik(
    inner_envelope: &InnerEnvelope,
    recipient_mik: &PublicID,
    outer_message_id: &MessageID,
    sender_private: &[u8; 32],
) -> Result<EncryptionOutput, EncryptionError> {
    encrypt_to_mik_impl(inner_envelope, recipient_mik, outer_message_id, sender_private, true)
}

/// Encrypt without VXEdDSA outer signature support.
///
/// Use this for constrained transports (LoRa, BLE) where the +192 byte overhead
/// of VXEdDSA is prohibitive. Messages encrypted this way cannot have their
/// outer envelope verified by relay nodes.
pub fn encrypt_to_mik_unsigned(
    inner_envelope: &InnerEnvelope,
    recipient_mik: &PublicID,
    outer_message_id: &MessageID,
    sender_private: &[u8; 32],
) -> Result<EncryptionOutput, EncryptionError> {
    encrypt_to_mik_impl(inner_envelope, recipient_mik, outer_message_id, sender_private, false)
}

/// Internal implementation of encrypt_to_mik with optional VXEdDSA support.
fn encrypt_to_mik_impl(
    inner_envelope: &InnerEnvelope,
    recipient_mik: &PublicID,
    outer_message_id: &MessageID,
    sender_private: &[u8; 32],
    enable_outer_signature: bool,
) -> Result<EncryptionOutput, EncryptionError> {
    // Reject small-order (weak) public keys that would produce predictable shared secrets
    if is_low_order_point(&recipient_mik.to_bytes()) {
        return Err(EncryptionError::InvalidRecipientKey);
    }

    // Generate ephemeral keypair
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // Recipient's MIK as X25519 public key
    let recipient_x25519 = X25519PublicKey::from(recipient_mik.to_bytes());

    // Compute shared secret via ECDH
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_x25519);

    // Defense-in-depth: reject all-zero shared secrets (indicates small-order input)
    // Per RFC 7748, implementations should check for all-zero output after scalar multiplication
    if is_zero_shared_secret(shared_secret.as_bytes()) {
        return Err(EncryptionError::InvalidRecipientKey);
    }

    // Derive encryption key binding both public keys (prevents key confusion attacks)
    let encryption_key = derive_key_from_shared(
        ephemeral_public.as_bytes(),
        &recipient_mik.to_bytes(),
        shared_secret.as_bytes(),
    );

    // ===== VXEdDSA Commitment Key Derivation (for anonymous outer signing) =====
    let (commitment_priv, commitment_pub, derivation_sig) = if enable_outer_signature {
        // Generate VXEdDSA derivation signature on message_id
        let (derivation_sig, vrf_output) = vxeddsa_sign(sender_private, outer_message_id.as_bytes());
        // Derive commitment keypair from VRF output
        let (priv_key, pub_key) = derive_commitment_key(&vrf_output);
        (Some(priv_key), Some(pub_key), Some(derivation_sig))
    } else {
        (None, None, None)
    };

    // Serialize the inner envelope into a reusable buffer
    let mut buffer = bincode::encode_to_vec(inner_envelope, bincode_config())?;
    let inner_bytes_len = buffer.len();

    // Sign: inner_bytes || outer_message_id || [commitment_pub]
    // Including commitment_pub in signature binds the inner message to the outer commitment.
    // This allows recipient to verify that the commitment_pub in OuterEnvelope was
    // derived by the sender (via VXEdDSA verification).
    buffer.extend_from_slice(outer_message_id.as_bytes());
    if let Some(ref pub_key) = commitment_pub {
        buffer.extend_from_slice(pub_key);
    }
    let inner_signature = xeddsa_sign(sender_private, &buffer);

    // Prepare plaintext for encryption: inner_bytes || inner_signature || [derivation_sig]
    // Truncate to remove message_id and commitment_pub, then append signatures
    buffer.truncate(inner_bytes_len);
    buffer.extend_from_slice(&inner_signature);
    if let Some(ref sig) = derivation_sig {
        buffer.extend_from_slice(sig);
    }
    let plaintext = buffer;

    // Derive nonce from message_id AND recipient_pk (recipient binding)
    let nonce_bytes = derive_nonce(outer_message_id, &recipient_mik.to_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher and encrypt with AAD (message_id binding)
    // Note: AEAD errors are intentionally discarded to prevent oracle attacks
    let cipher = ChaCha20Poly1305::new((&encryption_key).into());
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: outer_message_id.as_bytes(), // AAD binding
            },
        )
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    Ok(EncryptionOutput {
        ephemeral_public: ephemeral_public.to_bytes(),
        ciphertext,
        commitment_private: commitment_priv,
        commitment_public: commitment_pub,
    })
}

/// Decrypt a message using MIK private key (stateless decryption)
///
/// This is the receiver side of MIK encryption:
/// 1. Computes shared_secret = X25519(mik_private, ephemeral_public)
/// 2. Derives encryption key from shared_secret + both public keys
/// 3. Decrypts the ciphertext with ChaCha20Poly1305 (with AAD verification)
/// 4. Splits signature (and optional derivation_sig) from decrypted data
/// 5. Verifies XEdDSA signature against sender's public key from InnerEnvelope
///
/// The outer_message_id is used for:
/// - Nonce derivation (with recipient_pk)
/// - AAD verification (tampering with message_id causes decryption failure)
/// - Signature verification (message_id is part of signed data)
///
/// # Commitment Binding (VXEdDSA)
///
/// If `commitment_pub` is provided:
/// - Expects plaintext format: inner_bytes || signature (64 bytes) || derivation_sig (96 bytes)
/// - Verifies signature over: inner_bytes || message_id || commitment_pub
/// - Returns derivation_sig for caller to verify commitment binding
///
/// If `commitment_pub` is None:
/// - Expects plaintext format: inner_bytes || signature (64 bytes)
/// - Verifies signature over: inner_bytes || message_id
///
/// # Breaking Change (v0.1)
///
/// This function expects the sign-all-bytes format where the signature is
/// appended to serialized InnerEnvelope bytes before encryption. Messages
/// encrypted with the previous format (signature inside InnerEnvelope) are
/// not compatible. This is intentional for the PoC stage - no migration path
/// is provided.
pub fn decrypt_with_mik(
    ephemeral_public: &[u8; 32],
    ciphertext: &[u8],
    mik_private: &[u8; 32],
    outer_message_id: &MessageID,
    commitment_pub: Option<&[u8; 32]>,
) -> Result<DecryptionOutput, EncryptionError> {
    // Reject small-order ephemeral keys (attacker could send malicious keys)
    if is_low_order_point(ephemeral_public) {
        return Err(EncryptionError::DecryptionFailed);
    }

    // Parse ephemeral public key
    let ephemeral_x25519 = X25519PublicKey::from(*ephemeral_public);

    // Our MIK private key as StaticSecret
    let mik_secret = StaticSecret::from(*mik_private);

    // Derive our public key from private key
    let mik_public = X25519PublicKey::from(&mik_secret);

    // Compute shared secret via ECDH
    let shared_secret = mik_secret.diffie_hellman(&ephemeral_x25519);

    // Defense-in-depth: reject all-zero shared secrets (indicates small-order input)
    if is_zero_shared_secret(shared_secret.as_bytes()) {
        return Err(EncryptionError::DecryptionFailed);
    }

    // Derive encryption key binding both public keys (prevents key confusion attacks)
    let encryption_key = derive_key_from_shared(
        ephemeral_public,
        mik_public.as_bytes(),
        shared_secret.as_bytes(),
    );

    // Derive nonce from message_id AND recipient_pk (recipient binding)
    let nonce_bytes = derive_nonce(outer_message_id, mik_public.as_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher and decrypt with AAD verification
    // Note: AEAD errors are intentionally discarded to prevent oracle attacks
    let cipher = ChaCha20Poly1305::new((&encryption_key).into());
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: outer_message_id.as_bytes(), // AAD verification
            },
        )
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    // Determine expected suffix length and extract components
    let (inner_bytes, signature, derivation_sig) = if commitment_pub.is_some() {
        // VXEdDSA format: inner_bytes || signature (64) || derivation_sig (96)
        let suffix_len = 64 + 96;
        if plaintext.len() < suffix_len {
            return Err(EncryptionError::DecryptionFailed);
        }
        let (inner_bytes, suffix) = plaintext.split_at(plaintext.len() - suffix_len);
        let (sig_bytes, deriv_bytes) = suffix.split_at(64);
        let signature: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| EncryptionError::DecryptionFailed)?;
        let derivation_sig: [u8; 96] = deriv_bytes
            .try_into()
            .map_err(|_| EncryptionError::DecryptionFailed)?;
        (inner_bytes, signature, Some(derivation_sig))
    } else {
        // Legacy format: inner_bytes || signature (64)
        if plaintext.len() < 64 {
            return Err(EncryptionError::DecryptionFailed);
        }
        let (inner_bytes, sig_bytes) = plaintext.split_at(plaintext.len() - 64);
        let signature: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| EncryptionError::DecryptionFailed)?;
        (inner_bytes, signature, None)
    };

    // Deserialize the inner envelope (bincode v2 decode_from_slice handles trailing bytes)
    let (inner_envelope, _): (InnerEnvelope, _) =
        bincode::decode_from_slice(inner_bytes, bincode_config())?;

    // Build signable data: inner_bytes || message_id || [commitment_pub]
    let mut signable = inner_bytes.to_vec();
    signable.extend_from_slice(outer_message_id.as_bytes());
    if let Some(cpub) = commitment_pub {
        signable.extend_from_slice(cpub);
    }

    // Verify inner signature
    let sender_pub = inner_envelope.from.to_bytes();
    if !xeddsa_verify(&sender_pub, &signable, &signature) {
        return Err(EncryptionError::InvalidSenderSignature);
    }

    Ok(DecryptionOutput {
        inner_envelope,
        derivation_sig,
    })
}

/// Verify that commitment_pub was correctly derived by the sender.
///
/// This proves the commitment key used for outer envelope signing was derived
/// from the sender's identity key using VXEdDSA. A malicious relay node that
/// forged a new commitment_pub would fail this verification.
///
/// # Arguments
/// * `sender_pub` - 32-byte sender's public key (from InnerEnvelope.from)
/// * `message_id` - The outer message_id used as VRF input
/// * `derivation_sig` - 96-byte VXEdDSA signature from DecryptionOutput
/// * `commitment_pub` - 32-byte commitment public key from OuterEnvelope
///
/// # Returns
/// true if commitment_pub was derived by sender, false if forged/invalid
pub fn verify_commitment_binding(
    sender_pub: &[u8; 32],
    message_id: &MessageID,
    derivation_sig: &[u8; 96],
    commitment_pub: &[u8; 32],
) -> bool {
    // Verify VXEdDSA signature and recover VRF output
    let vrf_output = match vxeddsa_verify(sender_pub, message_id.as_bytes(), derivation_sig) {
        Some(vrf) => vrf,
        None => return false,
    };

    // Derive expected commitment_pub from VRF output
    let (_, expected_pub) = derive_commitment_key(&vrf_output);

    // Compare with provided commitment_pub using constant-time comparison
    // to prevent timing attacks that could leak information about the expected key
    use subtle::ConstantTimeEq;
    expected_pub.ct_eq(commitment_pub).into()
}

/// Derive a 32-byte encryption key from ECDH shared secret and both public keys
///
/// Binding both public keys prevents key confusion attacks where an attacker
/// might try to claim a ciphertext was intended for a different recipient.
/// This construction is inspired by the principles of NaCl's crypto_box_seal,
/// but uses BLAKE3 KDF and does not follow the exact same nonce derivation.
///
/// Key = BLAKE3_KDF("reme-encryption-key-v0", ephemeral_pub || recipient_pub || shared_secret)
fn derive_key_from_shared(
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
    shared_secret: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("reme-encryption-key-v0");
    hasher.update(ephemeral_public);
    hasher.update(recipient_public);
    hasher.update(shared_secret);
    let hash = hasher.finalize();
    *hash.as_bytes()
}

/// Derive a 12-byte nonce from MessageID and recipient public key
///
/// Including recipient_pk in nonce derivation provides:
/// - Domain separation: same message_id to different recipients produces different nonces
/// - Recipient binding: prevents message forwarding attacks
///
/// Nonce = BLAKE3_KDF("reme-nonce-v0", message_id || recipient_pk)[0..12]
fn derive_nonce(message_id: &MessageID, recipient_pk: &[u8; 32]) -> [u8; 12] {
    let mut hasher = blake3::Hasher::new_derive_key("reme-nonce-v0");
    hasher.update(message_id.as_bytes());
    hasher.update(recipient_pk);
    let hash = hasher.finalize();

    // Take first 12 bytes as nonce
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hash.as_bytes()[0..12]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_identity::Identity;
    use reme_message::{Content, TextContent};

    /// Helper to create an InnerEnvelope (no signature field - signing happens during encryption)
    fn create_inner(sender: &Identity, body: &str, created_at_ms: u64) -> InnerEnvelope {
        InnerEnvelope {
            from: *sender.public_id(),
            created_at_ms,
            content: Content::Text(TextContent {
                body: body.to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Create recipient identity (Bob)
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        // Create sender identity (Alice)
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        // Create inner envelope (signature added during encryption)
        let message_id = MessageID::new();
        let inner = create_inner(&alice, "Hello Bob via MIK!", 1234567890);

        // Alice encrypts to Bob's MIK (signing happens inside encrypt_to_mik)
        let enc_output = encrypt_to_mik(&inner, &bob_public, &message_id, &alice_private).unwrap();

        // Bob decrypts with his MIK private key (signature verification happens inside)
        let dec_output = decrypt_with_mik(
            &enc_output.ephemeral_public,
            &enc_output.ciphertext,
            &bob_private,
            &message_id,
            enc_output.commitment_public.as_ref(),
        )
        .unwrap();

        assert_eq!(inner.from, dec_output.inner_envelope.from);
        assert_eq!(inner.created_at_ms, dec_output.inner_envelope.created_at_ms);

        // Signature was already verified during decryption - if we got here, it's valid
        // VXEdDSA derivation_sig should be present when commitment was used
        assert!(dec_output.derivation_sig.is_some(), "Should have derivation_sig when commitment_pub is provided");

        match (inner.content, dec_output.inner_envelope.content) {
            (Content::Text(orig), Content::Text(dec)) => {
                assert_eq!(orig.body, dec.body);
            }
            _ => panic!("Content type mismatch"),
        }
    }

    #[test]
    fn test_wrong_recipient_fails() {
        // Create two recipients
        let bob = Identity::generate();
        let bob_public = *bob.public_id();

        let eve = Identity::generate();
        let eve_private = eve.to_bytes();

        // Create sender
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        // Create inner envelope
        let message_id = MessageID::new();
        let inner = create_inner(&alice, "Secret message for Bob", 1234567890);

        // Alice encrypts to Bob's MIK
        let enc_output = encrypt_to_mik(&inner, &bob_public, &message_id, &alice_private).unwrap();

        // Eve tries to decrypt with her private key (should fail)
        let result = decrypt_with_mik(
            &enc_output.ephemeral_public,
            &enc_output.ciphertext,
            &eve_private,
            &message_id,
            enc_output.commitment_public.as_ref(),
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::DecryptionFailed
        ));
    }

    #[test]
    fn test_different_messages_different_ephemeral() {
        let bob = Identity::generate();
        let bob_public = *bob.public_id();

        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        // Create two different messages
        let message_id1 = MessageID::new();
        let inner1 = create_inner(&alice, "Message 1", 1234567890);

        let message_id2 = MessageID::new();
        let inner2 = create_inner(&alice, "Message 2", 1234567891);

        // Encrypt both
        let enc1 = encrypt_to_mik(&inner1, &bob_public, &message_id1, &alice_private).unwrap();
        let enc2 = encrypt_to_mik(&inner2, &bob_public, &message_id2, &alice_private).unwrap();

        // Each message should have a different ephemeral key
        assert_ne!(enc1.ephemeral_public, enc2.ephemeral_public);
    }

    #[test]
    fn test_invalid_sender_signature_detected() {
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        let alice = Identity::generate();
        let mallory = Identity::generate();
        let mallory_private = mallory.to_bytes();

        // Mallory creates a message claiming to be from Alice
        let message_id = MessageID::new();
        let inner = InnerEnvelope {
            from: *alice.public_id(), // Claims to be Alice
            created_at_ms: 1234567890,
            content: Content::Text(TextContent {
                body: "Fake message from Alice".to_string(),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        };

        // Mallory encrypts with HER private key (not Alice's)
        // The signature will be made with Mallory's key, but `from` claims Alice
        let enc_output =
            encrypt_to_mik(&inner, &bob_public, &message_id, &mallory_private).unwrap();

        // Bob decrypts - signature verification should FAIL
        // (decrypt_with_mik verifies using `from` field = Alice's pubkey, but signed with Mallory's key)
        let result = decrypt_with_mik(
            &enc_output.ephemeral_public,
            &enc_output.ciphertext,
            &bob_private,
            &message_id,
            enc_output.commitment_public.as_ref(),
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::InvalidSenderSignature
        ));
    }

    #[test]
    fn test_wrong_message_id_fails_decryption() {
        // This tests the AAD binding - tampering with message_id should fail
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        let message_id = MessageID::new();
        let wrong_message_id = MessageID::new();

        let inner = create_inner(&alice, "Test message", 1234567890);

        // Encrypt with correct message_id
        let enc_output =
            encrypt_to_mik(&inner, &bob_public, &message_id, &alice_private).unwrap();

        // Try to decrypt with wrong message_id (should fail due to AAD mismatch)
        let result = decrypt_with_mik(
            &enc_output.ephemeral_public,
            &enc_output.ciphertext,
            &bob_private,
            &wrong_message_id,
            enc_output.commitment_public.as_ref(),
        );
        assert!(
            result.is_err(),
            "Decryption with wrong message_id should fail"
        );
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::DecryptionFailed
        ));
    }

    #[test]
    fn test_low_order_point_rejected() {
        // Test that encryption to small-order (weak) public keys is rejected.
        // These keys produce predictable shared secrets, providing no confidentiality.
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();
        let message_id = MessageID::new();
        let inner = create_inner(&alice, "Test message", 1234567890);

        // Test zero point (order 1)
        let zero_mik = PublicID::from_bytes_unchecked(&[0u8; 32]);
        let result = encrypt_to_mik(&inner, &zero_mik, &message_id, &alice_private);
        assert!(
            matches!(result, Err(EncryptionError::InvalidRecipientKey)),
            "Zero MIK should be rejected"
        );

        // Test order-2 point
        let mut order2 = [0u8; 32];
        order2[0] = 1;
        let order2_mik = PublicID::from_bytes_unchecked(&order2);
        let result = encrypt_to_mik(&inner, &order2_mik, &message_id, &alice_private);
        assert!(
            matches!(result, Err(EncryptionError::InvalidRecipientKey)),
            "Order-2 point should be rejected"
        );
    }

    #[test]
    fn test_malicious_ephemeral_key_rejected() {
        // Test that decryption rejects small-order ephemeral keys
        // An attacker could craft a message with a malicious ephemeral key
        let bob = Identity::generate();
        let bob_private = bob.to_bytes();
        let message_id = MessageID::new();

        // Fake ciphertext (doesn't matter, should reject before decryption attempt)
        let fake_ciphertext = vec![0u8; 64];

        // Test zero ephemeral key
        let zero_ephemeral = [0u8; 32];
        let result = decrypt_with_mik(&zero_ephemeral, &fake_ciphertext, &bob_private, &message_id, None);
        assert!(
            matches!(result, Err(EncryptionError::DecryptionFailed)),
            "Zero ephemeral key should be rejected"
        );

        // Test order-1 ephemeral key (identity point)
        let mut order1_ephemeral = [0u8; 32];
        order1_ephemeral[0] = 1;
        let result = decrypt_with_mik(&order1_ephemeral, &fake_ciphertext, &bob_private, &message_id, None);
        assert!(
            matches!(result, Err(EncryptionError::DecryptionFailed)),
            "Order-1 ephemeral key should be rejected"
        );
    }

    #[test]
    fn test_large_message_encryption() {
        // Test encryption of messages larger than typical sizes
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        // Create a large message (~10KB)
        let large_body = "X".repeat(10 * 1024);
        let message_id = MessageID::new();
        let inner = create_inner(&alice, &large_body, 1234567890);

        // Encrypt
        let enc_output = encrypt_to_mik(&inner, &bob_public, &message_id, &alice_private)
            .expect("Large message encryption should succeed");

        // Ciphertext should be larger than plaintext (due to serialization + tag + signature)
        assert!(
            enc_output.ciphertext.len() > large_body.len(),
            "Ciphertext should include overhead"
        );

        // Decrypt and verify
        let dec_output = decrypt_with_mik(
            &enc_output.ephemeral_public,
            &enc_output.ciphertext,
            &bob_private,
            &message_id,
            enc_output.commitment_public.as_ref(),
        )
        .expect("Large message decryption should succeed");

        match dec_output.inner_envelope.content {
            Content::Text(text) => {
                assert_eq!(
                    text.body.len(),
                    large_body.len(),
                    "Decrypted body length should match"
                );
                assert_eq!(text.body, large_body, "Decrypted body should match original");
            }
            _ => panic!("Expected text content"),
        }
    }

    #[test]
    fn test_different_senders_same_recipient_different_ciphertext() {
        // Verify that different senders to the same recipient produce different ciphertexts
        // This ensures proper key isolation between senders
        let bob = Identity::generate();
        let bob_public = *bob.public_id();

        let alice = Identity::generate();
        let alice_private = alice.to_bytes();
        let charlie = Identity::generate();
        let charlie_private = charlie.to_bytes();

        // Same message content and message_id, but different senders
        let message_id = MessageID::new();
        let inner_alice = create_inner(&alice, "Hello Bob!", 1234567890);
        let inner_charlie = create_inner(&charlie, "Hello Bob!", 1234567890);

        // Encrypt both
        let enc_alice =
            encrypt_to_mik(&inner_alice, &bob_public, &message_id, &alice_private).unwrap();
        let enc_charlie =
            encrypt_to_mik(&inner_charlie, &bob_public, &message_id, &charlie_private).unwrap();

        // Ephemeral keys should be different (random)
        assert_ne!(
            enc_alice.ephemeral_public, enc_charlie.ephemeral_public,
            "Ephemeral keys should differ"
        );

        // Ciphertexts should be different (different ephemeral keys = different shared secrets)
        assert_ne!(
            enc_alice.ciphertext, enc_charlie.ciphertext,
            "Ciphertexts should differ"
        );

        // Both should still decrypt correctly
        let bob_private = bob.to_bytes();
        let dec_alice = decrypt_with_mik(
            &enc_alice.ephemeral_public,
            &enc_alice.ciphertext,
            &bob_private,
            &message_id,
            enc_alice.commitment_public.as_ref(),
        )
        .unwrap();
        let dec_charlie = decrypt_with_mik(
            &enc_charlie.ephemeral_public,
            &enc_charlie.ciphertext,
            &bob_private,
            &message_id,
            enc_charlie.commitment_public.as_ref(),
        )
        .unwrap();

        assert_eq!(dec_alice.inner_envelope.from, *alice.public_id());
        assert_eq!(dec_charlie.inner_envelope.from, *charlie.public_id());
    }

    #[test]
    fn test_same_sender_same_content_different_ciphertext() {
        // Even with same sender, recipient, and content, each encryption should produce
        // different ciphertext due to fresh ephemeral keys
        let bob = Identity::generate();
        let bob_public = *bob.public_id();

        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        let message_id1 = MessageID::new();
        let message_id2 = MessageID::new();

        let inner1 = create_inner(&alice, "Same content", 1234567890);
        let inner2 = create_inner(&alice, "Same content", 1234567890);

        let enc1 = encrypt_to_mik(&inner1, &bob_public, &message_id1, &alice_private).unwrap();
        let enc2 = encrypt_to_mik(&inner2, &bob_public, &message_id2, &alice_private).unwrap();

        // Different ephemeral keys
        assert_ne!(enc1.ephemeral_public, enc2.ephemeral_public, "Ephemeral keys should differ");

        // Different ciphertexts (even with same content)
        assert_ne!(
            enc1.ciphertext, enc2.ciphertext,
            "Ciphertexts should differ even with same content"
        );
    }

    #[test]
    fn test_empty_message_content() {
        // Test encryption of empty message body
        let bob = Identity::generate();
        let bob_public = *bob.public_id();
        let bob_private = bob.to_bytes();

        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        let message_id = MessageID::new();
        let inner = create_inner(&alice, "", 1234567890);

        // Encrypt empty message
        let enc_output = encrypt_to_mik(&inner, &bob_public, &message_id, &alice_private)
            .expect("Empty message encryption should succeed");

        // Decrypt and verify
        let dec_output = decrypt_with_mik(
            &enc_output.ephemeral_public,
            &enc_output.ciphertext,
            &bob_private,
            &message_id,
            enc_output.commitment_public.as_ref(),
        )
        .expect("Empty message decryption should succeed");

        match dec_output.inner_envelope.content {
            Content::Text(text) => assert_eq!(text.body, "", "Decrypted body should be empty"),
            _ => panic!("Expected text content"),
        }
    }

    #[test]
    fn test_is_zero_shared_secret() {
        // Test that zero shared secret is detected
        let zero_secret = [0u8; 32];
        assert!(is_zero_shared_secret(&zero_secret), "All-zero secret should be detected as zero");

        // Test that non-zero shared secrets are not flagged as zero
        let mut non_zero_secret = [0u8; 32];
        non_zero_secret[0] = 1;
        assert!(!is_zero_shared_secret(&non_zero_secret), "Non-zero secret should not be detected as zero");

        // Test with random non-zero secret
        let mut random_secret = [0u8; 32];
        random_secret[15] = 255;
        random_secret[31] = 128;
        assert!(!is_zero_shared_secret(&random_secret), "Random non-zero secret should not be detected as zero");

        // Test with secret that's all 0xFF (maximum non-zero)
        let max_secret = [0xFFu8; 32];
        assert!(!is_zero_shared_secret(&max_secret), "All-max secret should not be detected as zero");
    }

    // ============================================================================
    // VXEdDSA Tests
    // ============================================================================

    #[test]
    fn test_vxeddsa_sign_verify_roundtrip() {
        // Generate a keypair
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();
        let alice_public = alice.public_id().to_bytes();

        // Sign a message
        let message = b"test message for vxeddsa";
        let (signature, vrf_output) = vxeddsa_sign(&alice_private, message);

        // Verify the signature
        let verified_vrf = vxeddsa_verify(&alice_public, message, &signature);
        assert!(verified_vrf.is_some(), "VXEdDSA verification should succeed");
        assert_eq!(verified_vrf.unwrap(), vrf_output, "VRF output should match");
    }

    #[test]
    fn test_vxeddsa_deterministic_vrf() {
        // Same (key, message) should produce same VRF output
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        let message = b"deterministic vrf test";

        // Sign twice
        let (_, vrf1) = vxeddsa_sign(&alice_private, message);
        let (_, vrf2) = vxeddsa_sign(&alice_private, message);

        // VRF outputs should be identical (deterministic)
        assert_eq!(vrf1, vrf2, "VRF output should be deterministic for same key+message");
    }

    #[test]
    fn test_vxeddsa_different_messages_different_vrf() {
        // Different messages should produce different VRF outputs
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        let message1 = b"message one";
        let message2 = b"message two";

        let (_, vrf1) = vxeddsa_sign(&alice_private, message1);
        let (_, vrf2) = vxeddsa_sign(&alice_private, message2);

        assert_ne!(vrf1, vrf2, "Different messages should produce different VRF outputs");
    }

    #[test]
    fn test_vxeddsa_wrong_public_key_fails() {
        // Verification with wrong public key should fail
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        let bob = Identity::generate();
        let bob_public = bob.public_id().to_bytes();

        let message = b"wrong key test";
        let (signature, _) = vxeddsa_sign(&alice_private, message);

        // Verify with Bob's key should fail
        let result = vxeddsa_verify(&bob_public, message, &signature);
        assert!(result.is_none(), "VXEdDSA verification with wrong key should fail");
    }

    #[test]
    fn test_vxeddsa_wrong_message_fails() {
        // Verification with wrong message should fail
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();
        let alice_public = alice.public_id().to_bytes();

        let message = b"original message";
        let wrong_message = b"tampered message";

        let (signature, _) = vxeddsa_sign(&alice_private, message);

        // Verify with wrong message should fail
        let result = vxeddsa_verify(&alice_public, wrong_message, &signature);
        assert!(result.is_none(), "VXEdDSA verification with wrong message should fail");
    }

    #[test]
    fn test_derive_commitment_key_deterministic() {
        // Same VRF output should produce same commitment key
        let vrf_output = [42u8; 32];

        let (priv1, pub1) = derive_commitment_key(&vrf_output);
        let (priv2, pub2) = derive_commitment_key(&vrf_output);

        assert_eq!(priv1, priv2, "Commitment private key should be deterministic");
        assert_eq!(pub1, pub2, "Commitment public key should be deterministic");
    }

    #[test]
    fn test_derive_commitment_key_different_inputs() {
        // Different VRF outputs should produce different commitment keys
        let vrf1 = [1u8; 32];
        let vrf2 = [2u8; 32];

        let (_, pub1) = derive_commitment_key(&vrf1);
        let (_, pub2) = derive_commitment_key(&vrf2);

        assert_ne!(pub1, pub2, "Different VRF outputs should produce different commitment keys");
    }

    #[test]
    fn test_commitment_key_can_sign_with_xeddsa() {
        // Commitment key should be usable for XEdDSA signing
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        // Derive commitment key from VXEdDSA
        let message_id = b"test-message-id";
        let (_, vrf_output) = vxeddsa_sign(&alice_private, message_id);
        let (commitment_priv, commitment_pub) = derive_commitment_key(&vrf_output);

        // Sign with commitment key using XEdDSA
        let outer_data = b"outer envelope data";
        let signature = xeddsa_sign(&commitment_priv, outer_data);

        // Verify with commitment public key
        assert!(
            xeddsa_verify(&commitment_pub, outer_data, &signature),
            "Commitment key should work for XEdDSA signing"
        );
    }

    // ============================================================================
    // verify_commitment_binding Tests
    // ============================================================================

    #[test]
    fn test_verify_commitment_binding_valid() {
        // Valid commitment binding should verify
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();
        let alice_public = alice.public_id().to_bytes();

        let message_id = MessageID::new();

        // Derive commitment key via VXEdDSA (same as in encryption)
        let (derivation_sig, vrf_output) = vxeddsa_sign(&alice_private, message_id.as_bytes());
        let (_, commitment_pub) = derive_commitment_key(&vrf_output);

        // Verify binding
        assert!(
            verify_commitment_binding(&alice_public, &message_id, &derivation_sig, &commitment_pub),
            "Valid commitment binding should verify"
        );
    }

    #[test]
    fn test_verify_commitment_binding_wrong_sender() {
        // Verification with wrong sender public key should fail
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();

        let bob = Identity::generate();
        let bob_public = bob.public_id().to_bytes();

        let message_id = MessageID::new();

        // Alice creates commitment
        let (derivation_sig, vrf_output) = vxeddsa_sign(&alice_private, message_id.as_bytes());
        let (_, commitment_pub) = derive_commitment_key(&vrf_output);

        // Verify with Bob's key should fail
        assert!(
            !verify_commitment_binding(&bob_public, &message_id, &derivation_sig, &commitment_pub),
            "Wrong sender should fail verification"
        );
    }

    #[test]
    fn test_verify_commitment_binding_wrong_message_id() {
        // Verification with wrong message_id should fail
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();
        let alice_public = alice.public_id().to_bytes();

        let message_id = MessageID::new();
        let wrong_message_id = MessageID::new();

        // Create commitment for original message_id
        let (derivation_sig, vrf_output) = vxeddsa_sign(&alice_private, message_id.as_bytes());
        let (_, commitment_pub) = derive_commitment_key(&vrf_output);

        // Verify with wrong message_id should fail
        assert!(
            !verify_commitment_binding(&alice_public, &wrong_message_id, &derivation_sig, &commitment_pub),
            "Wrong message_id should fail verification"
        );
    }

    #[test]
    fn test_verify_commitment_binding_forged_commitment() {
        // Verification with forged commitment_pub should fail
        // This simulates a malicious relay node replacing commitment_pub
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();
        let alice_public = alice.public_id().to_bytes();

        let message_id = MessageID::new();

        // Alice creates legitimate commitment
        let (derivation_sig, _) = vxeddsa_sign(&alice_private, message_id.as_bytes());

        // Attacker creates their own commitment_pub
        let attacker = Identity::generate();
        let attacker_private = attacker.to_bytes();
        let (_, forged_vrf) = vxeddsa_sign(&attacker_private, message_id.as_bytes());
        let (_, forged_commitment_pub) = derive_commitment_key(&forged_vrf);

        // Verify should fail - derivation_sig proves Alice's commitment, not attacker's
        assert!(
            !verify_commitment_binding(&alice_public, &message_id, &derivation_sig, &forged_commitment_pub),
            "Forged commitment_pub should fail verification"
        );
    }

    #[test]
    fn test_verify_commitment_binding_tampered_signature() {
        // Verification with tampered derivation_sig should fail
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();
        let alice_public = alice.public_id().to_bytes();

        let message_id = MessageID::new();

        // Create valid commitment
        let (mut derivation_sig, vrf_output) = vxeddsa_sign(&alice_private, message_id.as_bytes());
        let (_, commitment_pub) = derive_commitment_key(&vrf_output);

        // Tamper with signature
        derivation_sig[0] ^= 0xFF;
        derivation_sig[50] ^= 0x01;

        // Verify should fail
        assert!(
            !verify_commitment_binding(&alice_public, &message_id, &derivation_sig, &commitment_pub),
            "Tampered derivation_sig should fail verification"
        );
    }

    #[test]
    fn test_verify_commitment_binding_constant_time() {
        // Test that the same binding verifies consistently (sanity check for constant-time path)
        let alice = Identity::generate();
        let alice_private = alice.to_bytes();
        let alice_public = alice.public_id().to_bytes();

        let message_id = MessageID::new();
        let (derivation_sig, vrf_output) = vxeddsa_sign(&alice_private, message_id.as_bytes());
        let (_, commitment_pub) = derive_commitment_key(&vrf_output);

        // Verify multiple times - should always succeed
        for _ in 0..10 {
            assert!(
                verify_commitment_binding(&alice_public, &message_id, &derivation_sig, &commitment_pub),
                "Valid binding should verify consistently"
            );
        }
    }
}
