//! Security primitives for configuration.
//!
//! This module handles parsing and validation of security-related configuration fields:
//! - Certificate pins (SPKI SHA-256 format)
//! - Node public keys (base64-encoded `PublicID`)
//! - Credential extraction from URLs

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use percent_encoding::percent_decode_str;
use reme_identity::PublicID;
use thiserror::Error;
use url::Url;

/// Error types for security primitive parsing.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SecurityError {
    /// Certificate pin has an invalid format (expected "spki//sha256/BASE64...")
    #[error("Invalid certificate pin format: {0}")]
    InvalidCertPinFormat(String),

    /// Base64 decoding failed
    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(String),

    /// Invalid public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid URL format
    #[error("Invalid URL format: {0}")]
    InvalidUrl(String),
}

/// Certificate pin for TLS certificate validation.
///
/// Certificate pinning mitigates MITM attacks by validating that the server's
/// certificate matches a known public key hash, even if a trusted CA has been
/// compromised or coerced into issuing fraudulent certificates.
///
/// # Formats
///
/// Supports two pin types:
/// - `spki//sha256/BASE64_HASH` - Subject Public Key Info hash (recommended)
/// - `cert//sha256/BASE64_HASH` - Full certificate hash
///
/// SPKI pinning is generally preferred as it survives certificate renewal
/// when the public key remains the same.
///
/// # Examples
///
/// ```
/// use reme_config::CertPin;
///
/// // Parse SPKI pin (recommended)
/// let spki_pin = CertPin::parse("spki//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")?;
///
/// // Parse full certificate pin
/// let cert_pin = CertPin::parse("cert//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")?;
///
/// // Access the hash bytes
/// let hash = spki_pin.hash();
/// assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes
/// # Ok::<(), reme_config::SecurityError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertPin {
    /// SPKI (Subject Public Key Info) SHA256 hash
    Spki { sha256: [u8; 32] },
    /// Full certificate SHA256 hash
    Cert { sha256: [u8; 32] },
}

impl CertPin {
    /// Parse a certificate pin string.
    ///
    /// # Formats
    ///
    /// - `spki//sha256/BASE64_HASH` - SPKI hash (recommended)
    /// - `cert//sha256/BASE64_HASH` - Full certificate hash
    ///
    /// # Errors
    ///
    /// Returns [`SecurityError::InvalidCertPinFormat`] if:
    /// - The string doesn't start with `spki//sha256/` or `cert//sha256/`
    /// - The format is malformed
    ///
    /// Returns [`SecurityError::InvalidBase64`] if:
    /// - The base64 decoding fails
    /// - The decoded hash is not exactly 32 bytes (SHA-256 requirement)
    ///
    /// # Examples
    ///
    /// ```
    /// use reme_config::CertPin;
    ///
    /// // Valid SPKI pin
    /// let spki = CertPin::parse("spki//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")?;
    ///
    /// // Valid cert pin
    /// let cert = CertPin::parse("cert//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")?;
    ///
    /// // Invalid format
    /// assert!(CertPin::parse("sha256/AAAAAA").is_err());
    ///
    /// // Invalid base64
    /// assert!(CertPin::parse("spki//sha256/!!!invalid!!!").is_err());
    /// # Ok::<(), reme_config::SecurityError>(())
    /// ```
    pub fn parse(s: &str) -> Result<Self, SecurityError> {
        // Try SPKI format first
        if let Some(hash_b64) = s.strip_prefix("spki//sha256/") {
            let sha256 = decode_hash(hash_b64)?;
            return Ok(Self::Spki { sha256 });
        }

        // Try cert format
        if let Some(hash_b64) = s.strip_prefix("cert//sha256/") {
            let sha256 = decode_hash(hash_b64)?;
            return Ok(Self::Cert { sha256 });
        }

        // Neither format matched
        Err(SecurityError::InvalidCertPinFormat(format!(
            "expected format 'spki//sha256/BASE64...' or 'cert//sha256/BASE64...', got '{s}'"
        )))
    }

    /// Get the type prefix and hash.
    ///
    /// Returns the pin type ("spki" or "cert") and the decoded hash bytes.
    const fn parts(&self) -> (&'static str, &[u8; 32]) {
        match self {
            Self::Spki { sha256 } => ("spki", sha256),
            Self::Cert { sha256 } => ("cert", sha256),
        }
    }

    /// Get the decoded hash bytes (SHA-256, 32 bytes).
    ///
    /// Returns the hash regardless of pin type (SPKI or cert).
    pub const fn hash(&self) -> &[u8; 32] {
        self.parts().1
    }

    /// Format the pin as a string for display or serialization.
    ///
    /// Returns the canonical pin format that can be parsed with [`CertPin::parse`].
    ///
    /// # Examples
    ///
    /// ```
    /// use reme_config::CertPin;
    ///
    /// let pin = CertPin::parse("spki//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")?;
    /// assert_eq!(pin.to_pin_string(), "spki//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    ///
    /// let pin = CertPin::parse("cert//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")?;
    /// assert_eq!(pin.to_pin_string(), "cert//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    /// # Ok::<(), reme_config::SecurityError>(())
    /// ```
    pub fn to_pin_string(&self) -> String {
        let (prefix, sha256) = self.parts();
        format!("{prefix}//sha256/{}", BASE64_STANDARD.encode(sha256))
    }
}

/// Decode base64 hash and validate length.
fn decode_hash(hash_b64: &str) -> Result<[u8; 32], SecurityError> {
    if hash_b64.is_empty() {
        return Err(SecurityError::InvalidCertPinFormat(
            "missing base64-encoded hash".to_string(),
        ));
    }

    // Decode base64
    let bytes = BASE64_STANDARD
        .decode(hash_b64)
        .map_err(|e| SecurityError::InvalidBase64(format!("failed to decode base64: {e}")))?;

    // SHA-256 produces 32 bytes
    bytes.try_into().map_err(|v: Vec<u8>| {
        SecurityError::InvalidBase64(format!(
            "expected 32-byte SHA-256 hash, got {} bytes",
            v.len()
        ))
    })
}

/// Parse a base64-encoded `PublicID` from a configuration string.
///
/// Node public keys are stored as base64-encoded 32-byte X25519 public keys
/// in configuration files. This function handles the decoding and validation.
///
/// # Errors
///
/// Returns [`SecurityError::InvalidBase64`] if:
/// - The base64 decoding fails
/// - The decoded data is not exactly 32 bytes
///
/// Returns [`SecurityError::InvalidPublicKey`] if:
/// - The public key is a low-order point on Curve25519
///
/// # Examples
///
/// ```
/// use reme_config::parse_node_pubkey;
/// use reme_identity::Identity;
///
/// // Generate a test identity
/// let identity = Identity::generate();
/// let pubkey_bytes = identity.public_id().to_bytes();
///
/// // Encode as base64
/// let base64_str = base64::encode(&pubkey_bytes);
///
/// // Parse back
/// let parsed = parse_node_pubkey(&base64_str)?;
/// assert_eq!(parsed, *identity.public_id());
/// # Ok::<(), reme_config::SecurityError>(())
/// ```
pub fn parse_node_pubkey(s: &str) -> Result<PublicID, SecurityError> {
    // Decode base64 and convert to 32-byte array
    let key_bytes: [u8; 32] = BASE64_STANDARD
        .decode(s)
        .map_err(|e| SecurityError::InvalidBase64(format!("{e}")))?
        .try_into()
        .map_err(|v: Vec<u8>| {
            SecurityError::InvalidBase64(format!(
                "expected 32-byte public key, got {} bytes",
                v.len()
            ))
        })?;

    // Validate against low-order points
    PublicID::try_from_bytes(&key_bytes)
        .map_err(|e| SecurityError::InvalidPublicKey(format!("{e}")))
}

/// Extract username and password from a URL.
///
/// This helper supports backward compatibility with URLs that embed credentials:
/// `https://user:pass@host:port`
///
/// Explicit username/password config fields take precedence over URL-embedded
/// credentials, but this function can be used to extract them when needed.
///
/// # Returns
///
/// - `Some((username, password))` if credentials are embedded in the URL
/// - `None` if no credentials are present or the URL is invalid
///
/// # Examples
///
/// ```
/// use reme_config::extract_url_credentials;
///
/// // URL with credentials
/// let url = "https://alice:secret123@example.com:23003/api";
/// let (user, pass) = extract_url_credentials(url).unwrap();
/// assert_eq!(user, "alice");
/// assert_eq!(pass, "secret123");
///
/// // URL without credentials
/// let url = "https://example.com:23003/api";
/// assert!(extract_url_credentials(url).is_none());
///
/// // Invalid URL
/// let url = "not a url";
/// assert!(extract_url_credentials(url).is_none());
/// ```
pub fn extract_url_credentials(url_str: &str) -> Option<(String, String)> {
    // Use the standard url crate for WHATWG-compliant URL parsing
    // This handles all edge cases correctly and supports percent-encoding
    let url = Url::parse(url_str).ok()?;

    // Check if URL has credentials (username OR password)
    // URLs like "http://:pass@host" have empty username but still have credentials
    let has_credentials = !url.username().is_empty() || url.password().is_some();

    if !has_credentials {
        return None;
    }

    // URL crate returns percent-encoded credentials; decode them for use with HTTP clients
    // Example: "p%40ss:word" becomes "p@ss:word"
    let username = percent_decode_str(url.username())
        .decode_utf8_lossy()
        .into_owned();

    let password = url
        .password()
        .map(|p| percent_decode_str(p).decode_utf8_lossy().into_owned())
        .unwrap_or_default();

    Some((username, password))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_identity::Identity;

    #[test]
    fn cert_pin_valid_spki_format() {
        let pin_str = "spki//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pin = CertPin::parse(pin_str).unwrap();

        assert!(matches!(pin, CertPin::Spki { .. }));
        assert_eq!(pin.hash().len(), 32);
        assert_eq!(*pin.hash(), [0u8; 32]);
    }

    #[test]
    fn cert_pin_valid_cert_format() {
        let pin_str = "cert//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pin = CertPin::parse(pin_str).unwrap();

        assert!(matches!(pin, CertPin::Cert { .. }));
        assert_eq!(pin.hash().len(), 32);
        assert_eq!(*pin.hash(), [0u8; 32]);
    }

    #[test]
    fn cert_pin_invalid_prefix() {
        let pin_str = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let err = CertPin::parse(pin_str).unwrap_err();

        assert!(matches!(err, SecurityError::InvalidCertPinFormat(_)));
    }

    #[test]
    fn cert_pin_missing_hash() {
        let pin_str = "spki//sha256/";
        let err = CertPin::parse(pin_str).unwrap_err();

        assert!(matches!(err, SecurityError::InvalidCertPinFormat(_)));
    }

    #[test]
    fn cert_pin_invalid_base64() {
        let pin_str = "spki//sha256/!!!invalid!!!";
        let err = CertPin::parse(pin_str).unwrap_err();

        assert!(matches!(err, SecurityError::InvalidBase64(_)));
    }

    #[test]
    fn cert_pin_wrong_hash_length() {
        // 16 bytes instead of 32
        let short_hash = BASE64_STANDARD.encode([0u8; 16]);
        let pin_str = format!("spki//sha256/{short_hash}");
        let err = CertPin::parse(&pin_str).unwrap_err();

        assert!(matches!(err, SecurityError::InvalidBase64(_)));
    }

    #[test]
    fn cert_pin_roundtrip_spki() {
        let original = "spki//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pin = CertPin::parse(original).unwrap();
        assert_eq!(pin.to_pin_string(), original);
    }

    #[test]
    fn cert_pin_roundtrip_cert() {
        let original = "cert//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pin = CertPin::parse(original).unwrap();
        assert_eq!(pin.to_pin_string(), original);
    }

    #[test]
    fn parse_node_pubkey_valid() {
        let identity = Identity::generate();
        let pubkey_bytes = identity.public_id().to_bytes();
        let base64_str = BASE64_STANDARD.encode(pubkey_bytes);

        let parsed = parse_node_pubkey(&base64_str).unwrap();
        assert_eq!(parsed, *identity.public_id());
    }

    #[test]
    fn parse_node_pubkey_invalid_base64() {
        let err = parse_node_pubkey("!!!invalid!!!").unwrap_err();
        assert!(matches!(err, SecurityError::InvalidBase64(_)));
    }

    #[test]
    fn parse_node_pubkey_wrong_length() {
        let short_bytes = BASE64_STANDARD.encode([0u8; 16]);
        let err = parse_node_pubkey(&short_bytes).unwrap_err();
        assert!(matches!(err, SecurityError::InvalidBase64(_)));
    }

    #[test]
    fn parse_node_pubkey_low_order_point() {
        // Zero point (low-order)
        let zero_point = BASE64_STANDARD.encode([0u8; 32]);
        let err = parse_node_pubkey(&zero_point).unwrap_err();
        assert!(matches!(err, SecurityError::InvalidPublicKey(_)));
    }

    #[test]
    fn extract_url_credentials_with_auth() {
        let url = "https://alice:secret123@example.com:23003/api";
        let (user, pass) = extract_url_credentials(url).unwrap();

        assert_eq!(user, "alice");
        assert_eq!(pass, "secret123");
    }

    #[test]
    fn extract_url_credentials_without_auth() {
        let url = "https://example.com:23003/api";
        assert!(extract_url_credentials(url).is_none());
    }

    #[test]
    fn extract_url_credentials_without_path() {
        let url = "https://alice:secret123@example.com:23003";
        let (user, pass) = extract_url_credentials(url).unwrap();

        assert_eq!(user, "alice");
        assert_eq!(pass, "secret123");
    }

    #[test]
    fn extract_url_credentials_invalid_url() {
        assert!(extract_url_credentials("not a url").is_none());
        assert!(extract_url_credentials("").is_none());
    }

    #[test]
    fn extract_url_credentials_username_only() {
        // URL with username but no password is valid per WHATWG standard
        // Password is returned as empty string
        let url = "https://alice@example.com:23003";
        let (user, pass) = extract_url_credentials(url).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(pass, ""); // Empty password, not None
    }

    #[test]
    fn extract_url_credentials_empty_host() {
        // URLs with credentials but empty host should return None
        assert!(extract_url_credentials("https://user:pass@").is_none());
        assert!(extract_url_credentials("https://user:pass@/path").is_none());
        assert!(extract_url_credentials("https://user:pass@:8080").is_none());
        assert!(extract_url_credentials("https://user:pass@:8080/path").is_none());
    }

    #[test]
    fn extract_url_credentials_http_scheme() {
        let url = "http://user:pass@localhost:3000";
        let (user, pass) = extract_url_credentials(url).unwrap();

        assert_eq!(user, "user");
        assert_eq!(pass, "pass");
    }
}
