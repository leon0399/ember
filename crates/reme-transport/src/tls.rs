//! TLS certificate pinning for secure node connections.
//!
//! Supports two pin formats:
//! - `spki//sha256/<base64>` - Subject Public Key Info hash (recommended)
//! - `cert//sha256/<base64>` - Full certificate hash
//!
//! SPKI pinning is generally preferred as it survives certificate renewal
//! when the public key remains the same.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

/// Certificate pin type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertPin {
    /// SPKI (Subject Public Key Info) SHA256 hash
    Spki { sha256: [u8; 32] },
    /// Full certificate SHA256 hash
    Cert { sha256: [u8; 32] },
}

/// Error parsing a certificate pin string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinParseError {
    /// Invalid pin format (must be spki//sha256/... or cert//sha256/...)
    InvalidFormat,
    /// Invalid base64 encoding
    InvalidBase64,
    /// Hash is not exactly 32 bytes (SHA256)
    InvalidHashLength { expected: usize, actual: usize },
}

impl fmt::Display for PinParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PinParseError::InvalidFormat => write!(
                f,
                "Invalid pin format, expected 'spki//sha256/<base64>' or 'cert//sha256/<base64>'"
            ),
            PinParseError::InvalidBase64 => write!(f, "Invalid base64 encoding"),
            PinParseError::InvalidHashLength { expected, actual } => {
                write!(f, "Invalid hash length: expected {} bytes, got {}", expected, actual)
            }
        }
    }
}

impl std::error::Error for PinParseError {}

impl CertPin {
    /// Parse a certificate pin from string format.
    ///
    /// # Formats
    /// - `spki//sha256/<base64>` - SPKI hash (recommended)
    /// - `cert//sha256/<base64>` - Full certificate hash
    ///
    /// # Example
    /// ```
    /// use reme_transport::tls::CertPin;
    ///
    /// let pin = CertPin::parse("spki//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
    /// ```
    pub fn parse(pin_str: &str) -> Result<Self, PinParseError> {
        if let Some(hash_b64) = pin_str.strip_prefix("spki//sha256/") {
            let bytes = decode_hash(hash_b64)?;
            Ok(CertPin::Spki { sha256: bytes })
        } else if let Some(hash_b64) = pin_str.strip_prefix("cert//sha256/") {
            let bytes = decode_hash(hash_b64)?;
            Ok(CertPin::Cert { sha256: bytes })
        } else {
            Err(PinParseError::InvalidFormat)
        }
    }

    /// Format the pin as a string.
    pub fn to_pin_string(&self) -> String {
        match self {
            CertPin::Spki { sha256 } => format!("spki//sha256/{}", BASE64_STANDARD.encode(sha256)),
            CertPin::Cert { sha256 } => format!("cert//sha256/{}", BASE64_STANDARD.encode(sha256)),
        }
    }

    /// Verify that a certificate matches this pin.
    pub fn verify(&self, cert: &CertificateDer<'_>) -> bool {
        match self {
            CertPin::Spki { sha256 } => {
                let actual = compute_spki_hash(cert);
                actual.as_ref() == Some(sha256)
            }
            CertPin::Cert { sha256 } => {
                let actual = compute_cert_hash(cert);
                &actual == sha256
            }
        }
    }
}

/// Decode base64 hash and validate length.
fn decode_hash(hash_b64: &str) -> Result<[u8; 32], PinParseError> {
    let bytes = BASE64_STANDARD
        .decode(hash_b64)
        .map_err(|_| PinParseError::InvalidBase64)?;

    if bytes.len() != 32 {
        return Err(PinParseError::InvalidHashLength {
            expected: 32,
            actual: bytes.len(),
        });
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

/// Compute SHA256 hash of full certificate.
fn compute_cert_hash(cert: &CertificateDer<'_>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(cert.as_ref());
    hasher.finalize().into()
}

/// Compute SHA256 hash of certificate's SPKI (Subject Public Key Info).
///
/// Uses the x509-parser crate for safe and robust ASN.1/DER parsing.
/// Returns None if the certificate cannot be parsed.
fn compute_spki_hash(cert: &CertificateDer<'_>) -> Option<[u8; 32]> {
    // Use x509-parser for safe X.509 certificate parsing
    let (_, x509) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;

    // Get the raw DER bytes of the SubjectPublicKeyInfo
    let spki_bytes = x509.public_key().raw;

    let mut hasher = Sha256::new();
    hasher.update(spki_bytes);
    Some(hasher.finalize().into())
}

/// Certificate verifier that checks pins after normal verification.
#[derive(Debug)]
pub struct PinningVerifier {
    /// Hostname -> Pin mapping
    pins: HashMap<String, CertPin>,
    /// Inner verifier for standard certificate chain validation
    inner: Arc<dyn ServerCertVerifier>,
}

impl PinningVerifier {
    /// Create a new pinning verifier with the given pins.
    ///
    /// Pins are keyed by hostname (without port).
    pub fn new(pins: HashMap<String, CertPin>) -> Self {
        // Use ring as the crypto provider explicitly
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        // Use platform verifier with webpki roots
        let root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        );
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(root_store),
            provider,
        )
        .build()
        .expect("valid root store");
        Self { pins, inner }
    }

    /// Create a pinning verifier without any pins (just standard verification).
    pub fn without_pins() -> Self {
        Self::new(HashMap::new())
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // First, perform standard verification
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // Then check pin if configured for this host
        if let ServerName::DnsName(dns_name) = server_name {
            let hostname = dns_name.as_ref().to_string();
            if let Some(pin) = self.pins.get(&hostname) {
                if !pin.verify(end_entity) {
                    return Err(TlsError::General(format!(
                        "Certificate pin mismatch for {}: expected {}",
                        hostname,
                        pin.to_pin_string()
                    )));
                }
            }
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_spki_pin() {
        let pin_str = "spki//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pin = CertPin::parse(pin_str).unwrap();
        assert!(matches!(pin, CertPin::Spki { .. }));

        if let CertPin::Spki { sha256 } = pin {
            assert_eq!(sha256, [0u8; 32]);
        }
    }

    #[test]
    fn test_parse_cert_pin() {
        let pin_str = "cert//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pin = CertPin::parse(pin_str).unwrap();
        assert!(matches!(pin, CertPin::Cert { .. }));

        if let CertPin::Cert { sha256 } = pin {
            assert_eq!(sha256, [0u8; 32]);
        }
    }

    #[test]
    fn test_parse_invalid_format() {
        assert_eq!(
            CertPin::parse("invalid"),
            Err(PinParseError::InvalidFormat)
        );
        assert_eq!(
            CertPin::parse("sha256/AAAA"),
            Err(PinParseError::InvalidFormat)
        );
    }

    #[test]
    fn test_parse_invalid_base64() {
        assert_eq!(
            CertPin::parse("spki//sha256/!!!invalid!!!"),
            Err(PinParseError::InvalidBase64)
        );
    }

    #[test]
    fn test_parse_invalid_length() {
        // Too short (only 16 bytes)
        assert_eq!(
            CertPin::parse("spki//sha256/AAAAAAAAAAAAAAAAAAAAAA=="),
            Err(PinParseError::InvalidHashLength {
                expected: 32,
                actual: 16
            })
        );
    }

    #[test]
    fn test_roundtrip() {
        let original = "spki//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pin = CertPin::parse(original).unwrap();
        assert_eq!(pin.to_pin_string(), original);

        let original = "cert//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pin = CertPin::parse(original).unwrap();
        assert_eq!(pin.to_pin_string(), original);
    }

    #[test]
    fn test_verify_cert_hash() {
        // Create a simple test certificate hash
        let test_cert = b"test certificate data";
        let mut hasher = Sha256::new();
        hasher.update(test_cert);
        let expected_hash: [u8; 32] = hasher.finalize().into();

        let pin = CertPin::Cert { sha256: expected_hash };
        let cert = CertificateDer::from(test_cert.to_vec());
        assert!(pin.verify(&cert));

        // Wrong hash should fail
        let wrong_pin = CertPin::Cert { sha256: [0u8; 32] };
        assert!(!wrong_pin.verify(&cert));
    }
}
