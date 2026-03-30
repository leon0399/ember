//! Validation logic and parsed configuration types.
//!
//! This module provides validated, parsed types that are ready for use by the
//! application layer. Raw configuration types (like [`HttpPeerConfig`]) are
//! deserialized from TOML, then validated and converted into parsed types
//! (like [`ParsedHttpPeer`]) that guarantee:
//!
//! - URLs are well-formed
//! - Certificate pins are valid SPKI SHA-256 hashes
//! - Node public keys are valid X25519 keys
//! - Credentials are properly merged (explicit fields override URL-embedded)
//!
//! # Examples
//!
//! ```
//! use ember_config::{HttpPeerConfig, PeerCommon, ConfiguredTier};
//! use ember_config::{ParsedHttpPeer, ValidationError};
//!
//! // Create raw config (from TOML deserialization)
//! let config = HttpPeerConfig {
//!     common: PeerCommon {
//!         label: Some("Primary Mailbox".to_string()),
//!         tier: ConfiguredTier::Quorum,
//!         priority: 100,
//!     },
//!     url: "https://mailbox.example.com:23003".to_string(),
//!     cert_pin: Some("spki//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
//!     node_pubkey: None,
//!     username: Some("alice".to_string()),
//!     password: Some("secret".to_string()),
//! };
//!
//! // Validate and parse
//! let parsed: ParsedHttpPeer = config.try_into()?;
//!
//! // Parsed type has validated fields
//! assert_eq!(parsed.url, "https://mailbox.example.com:23003");
//! assert!(parsed.cert_pin.is_some());
//! assert_eq!(parsed.auth, Some(("alice".to_string(), "secret".to_string())));
//! # Ok::<(), ValidationError>(())
//! ```

use ember_identity::PublicID;
use thiserror::Error;
use url::Url;

#[cfg(feature = "mqtt")]
use crate::MqttPeerConfig;
#[cfg(feature = "http")]
use crate::{extract_url_credentials, parse_node_pubkey, CertPin, HttpPeerConfig};
use crate::{PeerCommon, SecurityError};

/// Errors that can occur during configuration validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Invalid URL format
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// Invalid certificate pin
    #[error("Invalid certificate pin: {0}")]
    InvalidCertPin(#[from] SecurityError),

    /// Conflicting authentication credentials
    #[error("Conflicting credentials: {0}")]
    ConflictingCredentials(String),

    /// Missing required field (reserved for future validation rules)
    #[allow(dead_code)]
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid URL scheme
    #[error("Invalid URL scheme: expected {expected}, got {actual}")]
    InvalidUrlScheme { expected: String, actual: String },
}

/// Validated HTTP peer configuration ready for use.
///
/// This type is produced by validating and parsing an [`HttpPeerConfig`].
/// All fields are guaranteed to be valid:
///
/// - `url` is a well-formed HTTP/HTTPS URL
/// - `cert_pin` (if present) is a valid SPKI SHA-256 hash
/// - `node_pubkey` (if present) is a valid X25519 public key
/// - `auth` credentials are properly merged (explicit fields override URL-embedded)
///
/// # Credential precedence
///
/// When both URL-embedded credentials and explicit `username`/`password` fields
/// are present, the explicit fields take precedence. This allows overriding
/// URL credentials without modifying the URL string.
///
/// | URL                      | username | password | Result      |
/// |--------------------------|----------|----------|-------------|
/// | `https://a:b@host`       | None     | None     | `("a", "b")` |
/// | `https://a:b@host`       | `"c"`    | `"d"`    | `("c", "d")` |
/// | `https://a:b@host`       | `"c"`    | None     | Error (incomplete) |
/// | `https://host`           | `"c"`    | `"d"`    | `("c", "d")` |
///
/// # Examples
///
/// ```
/// use ember_config::{HttpPeerConfig, PeerCommon, ConfiguredTier};
/// use ember_config::ParsedHttpPeer;
///
/// let config = HttpPeerConfig {
///     common: PeerCommon::default(),
///     url: "https://user:pass@example.com:23003".to_string(),
///     cert_pin: None,
///     node_pubkey: None,
///     username: None,
///     password: None,
/// };
///
/// let parsed: ParsedHttpPeer = config.try_into()?;
///
/// // URL-embedded credentials extracted
/// assert_eq!(parsed.auth, Some(("user".to_string(), "pass".to_string())));
/// # Ok::<(), ember_config::ValidationError>(())
/// ```
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
pub struct ParsedHttpPeer {
    /// Common peer fields (label, tier, priority)
    pub common: PeerCommon,

    /// Validated HTTP/HTTPS URL
    pub url: String,

    /// Validated certificate pin (if configured)
    pub cert_pin: Option<CertPin>,

    /// Validated node public key (if configured)
    pub node_pubkey: Option<PublicID>,

    /// Authentication credentials (username, password)
    ///
    /// Merged from explicit fields and URL-embedded credentials.
    /// Explicit fields take precedence.
    pub auth: Option<(String, String)>,
}

#[cfg(feature = "http")]
impl TryFrom<HttpPeerConfig> for ParsedHttpPeer {
    type Error = ValidationError;

    fn try_from(config: HttpPeerConfig) -> Result<Self, Self::Error> {
        validate_http_url(&config.url)?;

        let cert_pin = config.cert_pin.as_deref().map(CertPin::parse).transpose()?;

        let node_pubkey = config
            .node_pubkey
            .as_deref()
            .map(parse_node_pubkey)
            .transpose()?;

        let auth = merge_credentials(
            &config.url,
            config.username.as_deref(),
            config.password.as_deref(),
        )?;

        Ok(Self {
            common: config.common.normalize(),
            url: config.url,
            cert_pin,
            node_pubkey,
            auth,
        })
    }
}

/// Validated MQTT peer configuration ready for use.
///
/// This type is produced by validating and parsing an [`MqttPeerConfig`].
/// All fields are guaranteed to be valid:
///
/// - `url` is a well-formed MQTT/MQTTS URL
/// - `client_id` is preserved from config
///
/// # Examples
///
/// ```
/// use ember_config::{MqttPeerConfig, PeerCommon};
/// use ember_config::ParsedMqttPeer;
///
/// let config = MqttPeerConfig {
///     common: PeerCommon::default(),
///     url: "mqtts://broker.example.com:8883".to_string(),
///     client_id: Some("ember-client-123".to_string()),
///     topic_prefix: None,
///     username: None,
///     password: None,
/// };
///
/// let parsed: ParsedMqttPeer = config.try_into()?;
/// assert_eq!(parsed.url, "mqtts://broker.example.com:8883");
/// assert_eq!(parsed.client_id, Some("ember-client-123".to_string()));
/// # Ok::<(), ember_config::ValidationError>(())
/// ```
#[cfg(feature = "mqtt")]
#[derive(Debug, Clone)]
pub struct ParsedMqttPeer {
    /// Common peer fields (label, tier, priority)
    pub common: PeerCommon,

    /// Validated MQTT/MQTTS URL
    pub url: String,

    /// Client ID (auto-generated if not set by application layer)
    pub client_id: Option<String>,

    /// Topic prefix for messages (default: `ember/v1`)
    pub topic_prefix: Option<String>,

    /// Authentication credentials (username, password)
    ///
    /// Merged from explicit fields and URL-embedded credentials.
    /// Explicit fields take precedence.
    pub auth: Option<(String, String)>,
}

#[cfg(feature = "mqtt")]
impl TryFrom<MqttPeerConfig> for ParsedMqttPeer {
    type Error = ValidationError;

    fn try_from(config: MqttPeerConfig) -> Result<Self, Self::Error> {
        validate_mqtt_url(&config.url)?;

        // Merge credentials with same logic as HTTP
        let auth = merge_mqtt_credentials(
            &config.url,
            config.username.as_deref(),
            config.password.as_deref(),
        )?;

        Ok(Self {
            common: config.common.normalize(),
            url: config.url,
            client_id: config.client_id,
            topic_prefix: config.topic_prefix,
            auth,
        })
    }
}

/// Validate that a URL has a valid scheme from a list of allowed schemes.
///
/// This performs basic validation:
/// - URL contains `://` separator
/// - Scheme matches one of the allowed schemes (case-insensitive)
/// - Authority section (host) is present after the scheme
///
/// # Arguments
///
/// * `url` - The URL to validate
/// * `allowed_schemes` - Slice of allowed scheme names (lowercase)
///
/// # Errors
///
/// Returns [`ValidationError::InvalidUrl`] if the URL is malformed.
/// Returns [`ValidationError::InvalidUrlScheme`] if the scheme is not in the allowed list.
fn validate_url_scheme(url_str: &str, allowed_schemes: &[&str]) -> Result<(), ValidationError> {
    // Use the standard url crate for WHATWG-compliant URL parsing
    // This validates:
    // - URL is well-formed per WHATWG spec
    // - Ports are in valid range (0-65535)
    // - Host contains only valid characters
    // - Authority section is present
    let url = Url::parse(url_str)
        .map_err(|e| ValidationError::InvalidUrl(format!("failed to parse URL: {e}")))?;

    // Validate scheme is in allowed list (case-insensitive)
    let scheme_lower = url.scheme().to_lowercase();
    if !allowed_schemes.contains(&scheme_lower.as_str()) {
        return Err(ValidationError::InvalidUrlScheme {
            expected: allowed_schemes.join(" or "),
            actual: url.scheme().to_string(),
        });
    }

    // Validate that URL has a non-empty host
    // For HTTP/HTTPS URLs, a host is required
    match url.host_str() {
        None | Some("") => {
            return Err(ValidationError::InvalidUrl(format!(
                "missing host in URL: {url_str}"
            )));
        }
        Some(_) => {} // Host present and non-empty
    }

    Ok(())
}

/// Validate that a URL is a well-formed HTTP/HTTPS URL.
///
/// This performs basic validation:
/// - URL contains `://` separator
/// - Scheme is `http` or `https` (case-insensitive)
///
/// # Errors
///
/// Returns [`ValidationError::InvalidUrl`] if the URL is malformed.
/// Returns [`ValidationError::InvalidUrlScheme`] if the scheme is not HTTP/HTTPS.
///
/// # Examples
///
/// ```
/// use ember_config::validate_http_url;
///
/// // Valid URLs
/// assert!(validate_http_url("https://example.com").is_ok());
/// assert!(validate_http_url("http://localhost:3000").is_ok());
/// assert!(validate_http_url("HTTPS://EXAMPLE.COM").is_ok()); // Case-insensitive
///
/// // Invalid URLs
/// assert!(validate_http_url("mqtts://broker.example.com").is_err()); // Wrong scheme
/// assert!(validate_http_url("not a url").is_err()); // Malformed
/// assert!(validate_http_url("").is_err()); // Empty
/// ```
#[cfg(feature = "http")]
pub fn validate_http_url(url: &str) -> Result<(), ValidationError> {
    validate_url_scheme(url, &["http", "https"])
}

/// Validate that a URL is a well-formed MQTT/MQTTS URL.
///
/// This performs basic validation:
/// - URL contains `://` separator
/// - Scheme is `mqtt` or `mqtts` (case-insensitive)
///
/// # Errors
///
/// Returns [`ValidationError::InvalidUrl`] if the URL is malformed.
/// Returns [`ValidationError::InvalidUrlScheme`] if the scheme is not MQTT/MQTTS.
///
/// # Examples
///
/// ```
/// use ember_config::validate_mqtt_url;
///
/// // Valid URLs
/// assert!(validate_mqtt_url("mqtt://broker.example.com").is_ok());
/// assert!(validate_mqtt_url("mqtts://broker.example.com:8883").is_ok());
/// assert!(validate_mqtt_url("MQTTS://BROKER.EXAMPLE.COM").is_ok()); // Case-insensitive
///
/// // Invalid URLs
/// assert!(validate_mqtt_url("https://example.com").is_err()); // Wrong scheme
/// assert!(validate_mqtt_url("not a url").is_err()); // Malformed
/// assert!(validate_mqtt_url("").is_err()); // Empty
/// ```
#[cfg(feature = "mqtt")]
pub fn validate_mqtt_url(url: &str) -> Result<(), ValidationError> {
    validate_url_scheme(url, &["mqtt", "mqtts"])
}

/// Merge authentication credentials from URL and explicit config fields.
///
/// This implements the credential precedence rules:
///
/// 1. If explicit `username` and `password` are both provided, use them
/// 2. If only one of `username`/`password` is provided, return error
/// 3. Otherwise, extract credentials from URL (if present)
/// 4. If no credentials anywhere, return `None`
///
/// # Arguments
///
/// * `url` - The peer URL (may contain embedded credentials)
/// * `username` - Explicit username from config (overrides URL)
/// * `password` - Explicit password from config (overrides URL)
///
/// # Errors
///
/// Returns [`ValidationError::ConflictingCredentials`] if only one of
/// `username`/`password` is provided (incomplete explicit credentials),
/// or if URL contains incomplete credentials (username without password or vice versa).
///
/// # Examples
///
/// ```
/// use ember_config::merge_credentials;
///
/// // Explicit credentials override URL
/// let url = "https://url_user:url_pass@example.com";
/// let auth = merge_credentials(url, Some("explicit_user"), Some("explicit_pass"))?;
/// assert_eq!(auth, Some(("explicit_user".to_string(), "explicit_pass".to_string())));
///
/// // URL credentials used when no explicit fields
/// let auth = merge_credentials(url, None, None)?;
/// assert_eq!(auth, Some(("url_user".to_string(), "url_pass".to_string())));
///
/// // No credentials anywhere
/// let url = "https://example.com";
/// let auth = merge_credentials(url, None, None)?;
/// assert_eq!(auth, None);
///
/// // Error: incomplete explicit credentials
/// assert!(merge_credentials(url, Some("user"), None).is_err());
/// # Ok::<(), ember_config::ValidationError>(())
/// ```
#[cfg(feature = "http")]
pub fn merge_credentials(
    url: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<Option<(String, String)>, ValidationError> {
    match (username, password) {
        // Both explicit fields provided: use them (override URL)
        (Some(u), Some(p)) => Ok(Some((u.to_string(), p.to_string()))),

        // Only one explicit field provided: error (incomplete)
        (Some(_), None) => Err(ValidationError::ConflictingCredentials(
            "username provided but password missing".to_string(),
        )),
        (None, Some(_)) => Err(ValidationError::ConflictingCredentials(
            "password provided but username missing".to_string(),
        )),

        // No explicit fields: extract from URL (if present) and validate completeness
        (None, None) => match extract_url_credentials(url) {
            Some((u, p)) if !u.is_empty() && !p.is_empty() => Ok(Some((u, p))),
            Some((u, p)) if u.is_empty() && !p.is_empty() => {
                Err(ValidationError::ConflictingCredentials(
                    "URL contains password without username".to_string(),
                ))
            }
            Some((u, p)) if !u.is_empty() && p.is_empty() => {
                Err(ValidationError::ConflictingCredentials(
                    "URL contains username without password".to_string(),
                ))
            }
            _ => Ok(None),
        },
    }
}

/// Merge MQTT authentication credentials with precedence rules.
///
/// This function implements the same credential precedence logic as HTTP:
/// 1. If both explicit username AND password provided, use them (override URL)
/// 2. If only one explicit field provided, error (incomplete credentials)
/// 3. If no explicit fields, extract from URL (if present)
/// 4. If no credentials anywhere, return `None`
///
/// # Arguments
///
/// * `url` - The MQTT broker URL (may contain embedded credentials)
/// * `username` - Explicit username from config (overrides URL)
/// * `password` - Explicit password from config (overrides URL)
///
/// # Errors
///
/// Returns [`ValidationError::ConflictingCredentials`] if only one of
/// `username`/`password` is provided (incomplete explicit credentials),
/// or if URL contains incomplete credentials (username without password or vice versa).
#[cfg(feature = "mqtt")]
pub fn merge_mqtt_credentials(
    url: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<Option<(String, String)>, ValidationError> {
    match (username, password) {
        // Both explicit fields provided: use them (override URL)
        (Some(u), Some(p)) => Ok(Some((u.to_string(), p.to_string()))),

        // Only one explicit field provided: error (incomplete)
        (Some(_), None) => Err(ValidationError::ConflictingCredentials(
            "username provided but password missing".to_string(),
        )),
        (None, Some(_)) => Err(ValidationError::ConflictingCredentials(
            "password provided but username missing".to_string(),
        )),

        // No explicit fields: extract from URL (if present) and validate completeness
        (None, None) => match extract_url_credentials(url) {
            Some((u, p)) if !u.is_empty() && !p.is_empty() => Ok(Some((u, p))),
            Some((u, p)) if u.is_empty() && !p.is_empty() => {
                Err(ValidationError::ConflictingCredentials(
                    "URL contains password without username".to_string(),
                ))
            }
            Some((u, p)) if !u.is_empty() && p.is_empty() => {
                Err(ValidationError::ConflictingCredentials(
                    "URL contains username without password".to_string(),
                ))
            }
            _ => Ok(None),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_url_scheme_empty() {
        let err = validate_url_scheme("", &["http", "https"]).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrl(_)));
    }

    #[test]
    fn validate_url_scheme_no_separator() {
        let err = validate_url_scheme("example.com", &["http"]).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrl(_)));
    }

    #[test]
    fn validate_url_scheme_wrong_scheme() {
        let err = validate_url_scheme("ftp://example.com", &["http", "https"]).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrlScheme { .. }));
    }

    #[test]
    fn validate_url_scheme_case_insensitive() {
        assert!(validate_url_scheme("HTTPS://EXAMPLE.COM", &["http", "https"]).is_ok());
        assert!(validate_url_scheme("Http://example.com", &["http", "https"]).is_ok());
    }

    #[test]
    fn validate_url_scheme_missing_authority() {
        // URL with empty authority - url crate rejects this for http/https schemes
        let err = validate_url_scheme("https://", &["https"]).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrl(_)));

        // Note: Per WHATWG URL spec, "https:///path" parses as:
        //   scheme="https", host="path", path="/"
        // The third slash starts a new segment, not part of the authority.
        // This is actually a VALID URL (host="path"), so our validation accepts it.
        // If we wanted to test truly empty host, we'd need different test cases.
    }
}

#[cfg(all(test, feature = "http"))]
mod http_tests {
    use super::*;
    use crate::{ConfiguredTier, HttpPeerConfig};
    use base64::Engine;
    use ember_identity::Identity;

    fn make_pubkey_base64() -> String {
        let identity = Identity::generate();
        base64::engine::general_purpose::STANDARD.encode(identity.public_id().to_bytes())
    }

    fn make_cert_pin() -> String {
        let hash = [0u8; 32];
        let base64_hash = base64::engine::general_purpose::STANDARD.encode(hash);
        format!("spki//sha256/{base64_hash}")
    }

    #[test]
    fn validate_http_url_valid() {
        assert!(validate_http_url("https://example.com").is_ok());
        assert!(validate_http_url("http://localhost:3000").is_ok());
        assert!(validate_http_url("https://user:pass@example.com:23003/api").is_ok());
        assert!(validate_http_url("HTTPS://EXAMPLE.COM").is_ok());
    }

    #[test]
    fn validate_http_url_wrong_scheme() {
        let err = validate_http_url("mqtts://broker.example.com").unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrlScheme { .. }));
    }

    #[test]
    fn validate_http_url_empty_host_after_credentials() {
        // URLs with credentials but empty host should be rejected
        let err = validate_http_url("https://user:pass@").unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrl(_)));

        let err = validate_http_url("https://user:pass@/path").unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrl(_)));

        let err = validate_http_url("https://user:pass@:8080").unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrl(_)));

        let err = validate_http_url("https://user:pass@:8080/path").unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrl(_)));
    }

    #[test]
    fn validate_http_url_invalid_port() {
        // Port exceeds valid range (0-65535)
        let err = validate_http_url("https://example.com:99999").unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrl(_)));

        // Negative port
        let err = validate_http_url("https://example.com:-1").unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrl(_)));

        // Non-numeric port
        let err = validate_http_url("https://example.com:abc").unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrl(_)));
    }

    #[test]
    fn validate_http_url_invalid_host() {
        // Spaces in hostname
        let err = validate_http_url("https://ex ample.com").unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrl(_)));

        // Invalid characters
        let err = validate_http_url("https://example<>.com").unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrl(_)));
    }

    #[test]
    fn merge_credentials_explicit_override_url() {
        let url = "https://url_user:url_pass@example.com";
        let auth = merge_credentials(url, Some("explicit_user"), Some("explicit_pass")).unwrap();
        assert_eq!(
            auth,
            Some(("explicit_user".to_string(), "explicit_pass".to_string()))
        );
    }

    #[test]
    fn merge_credentials_from_url() {
        let url = "https://url_user:url_pass@example.com";
        let auth = merge_credentials(url, None, None).unwrap();
        assert_eq!(auth, Some(("url_user".to_string(), "url_pass".to_string())));
    }

    #[test]
    fn merge_credentials_none() {
        let url = "https://example.com";
        let auth = merge_credentials(url, None, None).unwrap();
        assert_eq!(auth, None);
    }

    #[test]
    fn merge_credentials_incomplete_username_only() {
        let err = merge_credentials("https://example.com", Some("user"), None).unwrap_err();
        assert!(matches!(err, ValidationError::ConflictingCredentials(_)));
    }

    #[test]
    fn merge_credentials_incomplete_password_only() {
        let err = merge_credentials("https://example.com", None, Some("pass")).unwrap_err();
        assert!(matches!(err, ValidationError::ConflictingCredentials(_)));
    }

    #[test]
    fn parsed_http_peer_minimal() {
        let config = HttpPeerConfig {
            common: PeerCommon::default(),
            url: "https://example.com:23003".to_string(),
            cert_pin: None,
            node_pubkey: None,
            username: None,
            password: None,
        };

        let parsed: ParsedHttpPeer = config.try_into().unwrap();

        assert_eq!(parsed.url, "https://example.com:23003");
        assert!(parsed.cert_pin.is_none());
        assert!(parsed.node_pubkey.is_none());
        assert!(parsed.auth.is_none());
    }

    #[test]
    fn parsed_http_peer_with_cert_pin() {
        let config = HttpPeerConfig {
            common: PeerCommon::default(),
            url: "https://example.com:23003".to_string(),
            cert_pin: Some(make_cert_pin()),
            node_pubkey: None,
            username: None,
            password: None,
        };

        let parsed: ParsedHttpPeer = config.try_into().unwrap();
        assert!(parsed.cert_pin.is_some());
    }

    #[test]
    fn parsed_http_peer_with_node_pubkey() {
        let config = HttpPeerConfig {
            common: PeerCommon::default(),
            url: "https://example.com:23003".to_string(),
            cert_pin: None,
            node_pubkey: Some(make_pubkey_base64()),
            username: None,
            password: None,
        };

        let parsed: ParsedHttpPeer = config.try_into().unwrap();
        assert!(parsed.node_pubkey.is_some());
    }

    #[test]
    fn parsed_http_peer_with_explicit_auth() {
        let config = HttpPeerConfig {
            common: PeerCommon::default(),
            url: "https://example.com:23003".to_string(),
            cert_pin: None,
            node_pubkey: None,
            username: Some("alice".to_string()),
            password: Some("secret".to_string()),
        };

        let parsed: ParsedHttpPeer = config.try_into().unwrap();
        assert_eq!(
            parsed.auth,
            Some(("alice".to_string(), "secret".to_string()))
        );
    }

    #[test]
    fn parsed_http_peer_with_url_embedded_auth() {
        let config = HttpPeerConfig {
            common: PeerCommon::default(),
            url: "https://alice:secret@example.com:23003".to_string(),
            cert_pin: None,
            node_pubkey: None,
            username: None,
            password: None,
        };

        let parsed: ParsedHttpPeer = config.try_into().unwrap();
        assert_eq!(
            parsed.auth,
            Some(("alice".to_string(), "secret".to_string()))
        );
    }

    #[test]
    fn parsed_http_peer_explicit_overrides_url_auth() {
        let config = HttpPeerConfig {
            common: PeerCommon::default(),
            url: "https://url_user:url_pass@example.com:23003".to_string(),
            cert_pin: None,
            node_pubkey: None,
            username: Some("explicit_user".to_string()),
            password: Some("explicit_pass".to_string()),
        };

        let parsed: ParsedHttpPeer = config.try_into().unwrap();
        assert_eq!(
            parsed.auth,
            Some(("explicit_user".to_string(), "explicit_pass".to_string()))
        );
    }

    #[test]
    fn parsed_http_peer_invalid_url_scheme() {
        let config = HttpPeerConfig {
            common: PeerCommon::default(),
            url: "mqtts://broker.example.com".to_string(),
            cert_pin: None,
            node_pubkey: None,
            username: None,
            password: None,
        };

        let err = ParsedHttpPeer::try_from(config).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrlScheme { .. }));
    }

    #[test]
    fn parsed_http_peer_invalid_cert_pin() {
        let config = HttpPeerConfig {
            common: PeerCommon::default(),
            url: "https://example.com".to_string(),
            cert_pin: Some("invalid!!!".to_string()),
            node_pubkey: None,
            username: None,
            password: None,
        };

        let err = ParsedHttpPeer::try_from(config).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidCertPin(_)));
    }

    #[test]
    fn parsed_http_peer_invalid_node_pubkey() {
        let config = HttpPeerConfig {
            common: PeerCommon::default(),
            url: "https://example.com".to_string(),
            cert_pin: None,
            node_pubkey: Some("invalid!!!".to_string()),
            username: None,
            password: None,
        };

        let err = ParsedHttpPeer::try_from(config).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidCertPin(_)));
    }

    #[test]
    fn parsed_http_peer_incomplete_credentials() {
        let config = HttpPeerConfig {
            common: PeerCommon::default(),
            url: "https://example.com".to_string(),
            cert_pin: None,
            node_pubkey: None,
            username: Some("alice".to_string()),
            password: None,
        };

        let err = ParsedHttpPeer::try_from(config).unwrap_err();
        assert!(matches!(err, ValidationError::ConflictingCredentials(_)));
    }

    #[test]
    fn parsed_http_peer_preserves_common_fields() {
        let config = HttpPeerConfig {
            common: PeerCommon {
                label: Some("Test Peer".to_string()),
                tier: ConfiguredTier::BestEffort,
                priority: 200,
            },
            url: "https://example.com".to_string(),
            cert_pin: None,
            node_pubkey: None,
            username: None,
            password: None,
        };

        let parsed: ParsedHttpPeer = config.try_into().unwrap();

        assert_eq!(parsed.common.label, Some("Test Peer".to_string()));
        assert_eq!(parsed.common.priority, 200);
    }

    #[test]
    fn parsed_http_peer_filters_empty_label() {
        let config = HttpPeerConfig {
            common: PeerCommon {
                label: Some(String::new()), // Empty label
                tier: ConfiguredTier::Quorum,
                priority: 100,
            },
            url: "https://example.com".to_string(),
            cert_pin: None,
            node_pubkey: None,
            username: None,
            password: None,
        };

        let parsed: ParsedHttpPeer = config.try_into().unwrap();

        // Empty label should be filtered out to None
        assert_eq!(parsed.common.label, None);
    }
}

#[cfg(all(test, feature = "mqtt"))]
mod mqtt_tests {
    use super::*;
    use crate::{ConfiguredTier, MqttPeerConfig};

    #[test]
    fn validate_mqtt_url_valid() {
        assert!(validate_mqtt_url("mqtt://broker.example.com").is_ok());
        assert!(validate_mqtt_url("mqtts://broker.example.com:8883").is_ok());
        assert!(validate_mqtt_url("MQTTS://BROKER.EXAMPLE.COM").is_ok());
    }

    #[test]
    fn validate_mqtt_url_wrong_scheme() {
        let err = validate_mqtt_url("https://example.com").unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrlScheme { .. }));
    }

    #[test]
    fn parsed_mqtt_peer_minimal() {
        let config = MqttPeerConfig {
            common: PeerCommon::default(),
            url: "mqtts://broker.example.com:8883".to_string(),
            client_id: None,
            topic_prefix: None,
            username: None,
            password: None,
        };

        let parsed: ParsedMqttPeer = config.try_into().unwrap();

        assert_eq!(parsed.url, "mqtts://broker.example.com:8883");
        assert!(parsed.client_id.is_none());
    }

    #[test]
    fn parsed_mqtt_peer_with_client_id() {
        let config = MqttPeerConfig {
            common: PeerCommon::default(),
            url: "mqtt://broker.example.com".to_string(),
            client_id: Some("ember-client-123".to_string()),
            topic_prefix: None,
            username: None,
            password: None,
        };

        let parsed: ParsedMqttPeer = config.try_into().unwrap();
        assert_eq!(parsed.client_id, Some("ember-client-123".to_string()));
    }

    #[test]
    fn parsed_mqtt_peer_invalid_url_scheme() {
        let config = MqttPeerConfig {
            common: PeerCommon::default(),
            url: "https://example.com".to_string(),
            client_id: None,
            topic_prefix: None,
            username: None,
            password: None,
        };

        let err = ParsedMqttPeer::try_from(config).unwrap_err();
        assert!(matches!(err, ValidationError::InvalidUrlScheme { .. }));
    }

    #[test]
    fn parsed_mqtt_peer_filters_empty_label() {
        let config = MqttPeerConfig {
            common: PeerCommon {
                label: Some(String::new()), // Empty label
                tier: ConfiguredTier::Quorum,
                priority: 100,
            },
            url: "mqtt://broker.example.com".to_string(),
            client_id: None,
            topic_prefix: None,
            username: None,
            password: None,
        };

        let parsed: ParsedMqttPeer = config.try_into().unwrap();

        // Empty label should be filtered out to None
        assert_eq!(parsed.common.label, None);
    }

    #[test]
    fn parsed_mqtt_peer_case_insensitive_scheme() {
        let config = MqttPeerConfig {
            common: PeerCommon::default(),
            url: "MQTTS://BROKER.EXAMPLE.COM:8883".to_string(),
            client_id: None,
            topic_prefix: None,
            username: None,
            password: None,
        };

        let parsed: ParsedMqttPeer = config.try_into().unwrap();
        assert_eq!(parsed.url, "MQTTS://BROKER.EXAMPLE.COM:8883");
    }

    #[cfg(feature = "mqtt")]
    #[test]
    fn test_mqtt_merge_credentials_explicit() {
        let url = "mqtt://url_user:url_pass@broker:1883";
        let result = merge_mqtt_credentials(url, Some("explicit"), Some("secret")).unwrap();
        assert_eq!(result, Some(("explicit".to_string(), "secret".to_string())));
    }

    #[cfg(feature = "mqtt")]
    #[test]
    fn test_mqtt_merge_credentials_url_only() {
        let url = "mqtt://url_user:url_pass@broker:1883";
        let result = merge_mqtt_credentials(url, None, None).unwrap();
        assert_eq!(
            result,
            Some(("url_user".to_string(), "url_pass".to_string()))
        );
    }

    #[cfg(feature = "mqtt")]
    #[test]
    fn test_mqtt_merge_credentials_incomplete_username() {
        let url = "mqtt://broker:1883";
        let err = merge_mqtt_credentials(url, Some("user"), None).unwrap_err();
        assert!(matches!(err, ValidationError::ConflictingCredentials(_)));
    }

    #[cfg(feature = "mqtt")]
    #[test]
    fn test_mqtt_merge_credentials_incomplete_password() {
        let url = "mqtt://broker:1883";
        let err = merge_mqtt_credentials(url, None, Some("pass")).unwrap_err();
        assert!(matches!(err, ValidationError::ConflictingCredentials(_)));
    }

    #[cfg(feature = "mqtt")]
    #[test]
    fn test_mqtt_merge_credentials_none() {
        let url = "mqtt://broker:1883";
        let result = merge_mqtt_credentials(url, None, None).unwrap();
        assert_eq!(result, None);
    }

    #[cfg(feature = "mqtt")]
    #[test]
    fn test_parsed_mqtt_peer_with_auth() {
        let config = MqttPeerConfig {
            common: PeerCommon::default(),
            url: "mqtts://broker:8883".to_string(),
            client_id: None,
            topic_prefix: None,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
        };

        let parsed: ParsedMqttPeer = config.try_into().unwrap();
        assert_eq!(parsed.auth, Some(("user".to_string(), "pass".to_string())));
    }

    #[cfg(feature = "mqtt")]
    #[test]
    fn test_parsed_mqtt_peer_url_auth_precedence() {
        let config = MqttPeerConfig {
            common: PeerCommon::default(),
            url: "mqtts://url_user:url_pass@broker:8883".to_string(),
            client_id: None,
            topic_prefix: None,
            username: Some("config_user".to_string()),
            password: Some("config_pass".to_string()),
        };

        let parsed: ParsedMqttPeer = config.try_into().unwrap();
        // Explicit config should override URL
        assert_eq!(
            parsed.auth,
            Some(("config_user".to_string(), "config_pass".to_string()))
        );
    }
}
