//! Signed HTTP Headers for Node-to-Node Communication
//!
//! This module implements XEdDSA-signed HTTP headers for authenticating
//! node-to-node requests. Headers include:
//!
//! - `X-Node-ID`: Hex-encoded node ID (derived from routing key)
//! - `X-Node-Pubkey`: Base64-encoded X25519 public key
//! - `X-Node-Timestamp`: Unix timestamp (seconds)
//! - `X-Node-Dest`: Intended destination hostname:port
//! - `X-Node-Signature`: Base64-encoded XEdDSA signature
//!
//! The signature covers: `node_id:timestamp:method:path:body_hash:dest_host`

use crate::node_identity::NodeIdentity;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::prelude::*;
use reme_identity::PublicID;
use std::time::{SystemTime, UNIX_EPOCH};

/// Header names for signed node requests (lowercase for HTTP compliance)
pub const HEADER_NODE_ID: &str = "x-node-id";
pub const HEADER_NODE_PUBKEY: &str = "x-node-pubkey";
pub const HEADER_NODE_TIMESTAMP: &str = "x-node-timestamp";
pub const HEADER_NODE_DEST: &str = "x-node-dest";
pub const HEADER_NODE_SIGNATURE: &str = "x-node-signature";

/// Maximum age of a valid timestamp (5 minutes in the past)
const MAX_TIMESTAMP_AGE_SECS: u64 = 5 * 60;

/// Maximum future timestamp allowed (30 seconds)
const MAX_TIMESTAMP_FUTURE_SECS: u64 = 30;

/// Errors that can occur during signature verification
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("Missing required header: {0}")]
    MissingHeader(&'static str),

    #[error("Invalid header value: {0}")]
    InvalidHeader(&'static str),

    #[error("Duplicate header: {0}")]
    DuplicateHeader(&'static str),

    #[error("Timestamp expired (older than {MAX_TIMESTAMP_AGE_SECS} seconds)")]
    TimestampExpired,

    #[error("Timestamp too far in future (more than {MAX_TIMESTAMP_FUTURE_SECS} seconds)")]
    TimestampFuture,

    #[error("Destination mismatch: expected one of {expected:?}, got {got}")]
    DestinationMismatch { expected: Vec<String>, got: String },

    #[error("Node ID does not match public key")]
    NodeIdMismatch,

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid signature")]
    InvalidSignature,
}

/// Signed headers for outgoing requests
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    pub node_id: String,
    pub pubkey: String,
    pub timestamp: u64,
    pub dest_host: String,
    pub signature: String,
}

impl SignedHeaders {
    /// Create signed headers for an outgoing request.
    ///
    /// # Arguments
    /// * `identity` - Node's cryptographic identity
    /// * `method` - HTTP method (e.g., "POST")
    /// * `path` - Request path (e.g., "/api/v1/submit")
    /// * `body` - Request body bytes
    /// * `dest_host` - Destination hostname:port (e.g., "node2.example.com:3000")
    pub fn sign(
        identity: &NodeIdentity,
        method: &str,
        path: &str,
        body: &[u8],
        dest_host: &str,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs();

        Self::sign_with_timestamp(identity, method, path, body, dest_host, timestamp)
    }

    /// Create signed headers with a specific timestamp (for testing).
    pub fn sign_with_timestamp(
        identity: &NodeIdentity,
        method: &str,
        path: &str,
        body: &[u8],
        dest_host: &str,
        timestamp: u64,
    ) -> Self {
        let node_id = identity.node_id().to_string();
        let pubkey = BASE64.encode(identity.public_id().to_bytes());
        let canonical_dest = canonicalize_host(dest_host);
        let canonical_path = canonicalize_path(path);

        let message = build_signed_message(
            &node_id,
            timestamp,
            method,
            &canonical_path,
            body,
            &canonical_dest,
        );

        let signature = identity.sign(message.as_bytes());
        let signature_b64 = BASE64.encode(signature);

        Self {
            node_id,
            pubkey,
            timestamp,
            dest_host: canonical_dest,
            signature: signature_b64,
        }
    }

    /// Convert to HTTP header pairs.
    pub fn to_headers(&self) -> Vec<(&'static str, String)> {
        vec![
            (HEADER_NODE_ID, self.node_id.clone()),
            (HEADER_NODE_PUBKEY, self.pubkey.clone()),
            (HEADER_NODE_TIMESTAMP, self.timestamp.to_string()),
            (HEADER_NODE_DEST, self.dest_host.clone()),
            (HEADER_NODE_SIGNATURE, self.signature.clone()),
        ]
    }
}

/// Verification context for incoming signed requests.
///
/// Uses references to avoid cloning on the hot path.
pub struct SignatureVerifier<'a> {
    /// Canonical public hostname
    public_host: Option<&'a str>,
    /// Additional acceptable hostnames
    additional_hosts: &'a [String],
}

impl<'a> SignatureVerifier<'a> {
    /// Create a new verifier.
    ///
    /// If `public_host` is None, destination verification is skipped (insecure).
    pub fn new(public_host: Option<&'a str>, additional_hosts: &'a [String]) -> Self {
        Self {
            public_host,
            additional_hosts,
        }
    }

    /// Check if incoming headers indicate a node-to-node request.
    ///
    /// Returns true if any X-Node-* headers are present.
    pub fn has_node_headers(&self, headers: &axum::http::HeaderMap) -> bool {
        headers.contains_key(HEADER_NODE_ID)
            || headers.contains_key(HEADER_NODE_PUBKEY)
            || headers.contains_key(HEADER_NODE_TIMESTAMP)
            || headers.contains_key(HEADER_NODE_DEST)
            || headers.contains_key(HEADER_NODE_SIGNATURE)
    }

    /// Verify signed headers on an incoming request.
    ///
    /// # Arguments
    /// * `headers` - HTTP headers from the request
    /// * `method` - HTTP method
    /// * `path` - Request path
    /// * `body` - Request body bytes
    ///
    /// # Returns
    /// The verified PublicID of the sending node on success.
    pub fn verify(
        &self,
        headers: &axum::http::HeaderMap,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<PublicID, SignatureError> {
        // Extract headers (checking for duplicates)
        let node_id = self.extract_single_header(headers, HEADER_NODE_ID)?;
        let pubkey_b64 = self.extract_single_header(headers, HEADER_NODE_PUBKEY)?;
        let timestamp_str = self.extract_single_header(headers, HEADER_NODE_TIMESTAMP)?;
        let dest_host = self.extract_single_header(headers, HEADER_NODE_DEST)?;
        let signature_b64 = self.extract_single_header(headers, HEADER_NODE_SIGNATURE)?;

        // 1. Check timestamp first (cheap operation, prevents signature DoS)
        let timestamp: u64 = timestamp_str
            .parse()
            .map_err(|_| SignatureError::InvalidHeader(HEADER_NODE_TIMESTAMP))?;
        self.verify_timestamp(timestamp)?;

        // 2. Check destination matches our hostname
        self.verify_destination(&dest_host)?;

        // 3. Decode and validate public key
        let pubkey_bytes = BASE64
            .decode(pubkey_b64.as_bytes())
            .map_err(|_| SignatureError::InvalidHeader(HEADER_NODE_PUBKEY))?;
        let pubkey_arr: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| SignatureError::InvalidPublicKey("expected 32 bytes".into()))?;
        let public_id = PublicID::try_from_bytes(&pubkey_arr)
            .map_err(|_| SignatureError::InvalidPublicKey("low-order point rejected".into()))?;

        // 4. Verify node_id matches derived value
        let derived_node_id = crate::node_identity::node_id_hex(&public_id);
        if !constant_time_eq(node_id.as_bytes(), derived_node_id.as_bytes()) {
            return Err(SignatureError::NodeIdMismatch);
        }

        // 5. Reconstruct and verify signature (expensive, do last)
        let canonical_path = canonicalize_path(path);
        let canonical_dest = canonicalize_host(&dest_host);

        let message = build_signed_message(
            &node_id,
            timestamp,
            method,
            &canonical_path,
            body,
            &canonical_dest,
        );

        let signature_bytes = BASE64
            .decode(signature_b64.as_bytes())
            .map_err(|_| SignatureError::InvalidHeader(HEADER_NODE_SIGNATURE))?;
        let signature: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| SignatureError::InvalidSignature)?;

        if !public_id.verify_xeddsa(message.as_bytes(), &signature) {
            return Err(SignatureError::InvalidSignature);
        }

        Ok(public_id)
    }

    /// Extract a single header value, rejecting duplicates.
    fn extract_single_header(
        &self,
        headers: &axum::http::HeaderMap,
        name: &'static str,
    ) -> Result<String, SignatureError> {
        let mut values = headers.get_all(name).iter();

        let first = values
            .next()
            .ok_or(SignatureError::MissingHeader(name))?
            .to_str()
            .map_err(|_| SignatureError::InvalidHeader(name))?;

        // Reject if there are duplicate headers
        if values.next().is_some() {
            return Err(SignatureError::DuplicateHeader(name));
        }

        Ok(first.to_string())
    }

    /// Verify timestamp is within acceptable bounds.
    fn verify_timestamp(&self, timestamp: u64) -> Result<(), SignatureError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs();

        // Check for future timestamps
        if timestamp > now + MAX_TIMESTAMP_FUTURE_SECS {
            return Err(SignatureError::TimestampFuture);
        }

        // Check for expired timestamps
        if timestamp + MAX_TIMESTAMP_AGE_SECS < now {
            return Err(SignatureError::TimestampExpired);
        }

        Ok(())
    }

    /// Verify destination matches our configured hostname.
    fn verify_destination(&self, dest_host: &str) -> Result<(), SignatureError> {
        // If no public_host configured, skip verification (insecure mode)
        let Some(public_host) = self.public_host else {
            return Ok(());
        };

        let canonical_dest = canonicalize_host(dest_host);
        let canonical_public = canonicalize_host(public_host);

        // Check primary host
        if canonical_dest == canonical_public {
            return Ok(());
        }

        // Check additional hosts
        for host in self.additional_hosts {
            if canonical_dest == canonicalize_host(host) {
                return Ok(());
            }
        }

        // Build expected list for error message
        let mut expected = vec![canonical_public];
        for host in self.additional_hosts {
            expected.push(canonicalize_host(host));
        }

        Err(SignatureError::DestinationMismatch {
            expected,
            got: canonical_dest,
        })
    }
}

/// Build the message that gets signed.
fn build_signed_message(
    node_id: &str,
    timestamp: u64,
    method: &str,
    path: &str,
    body: &[u8],
    dest_host: &str,
) -> String {
    let body_hash = hex::encode(blake3::hash(body).as_bytes());
    format!(
        "{}:{}:{}:{}:{}:{}",
        node_id,
        timestamp,
        method.to_uppercase(),
        path,
        body_hash,
        dest_host
    )
}

/// Canonicalize a hostname for consistent comparison.
///
/// Only performs safe, scheme-independent transformations:
/// - Lowercase (DNS is case-insensitive)
/// - Remove trailing dot from hostname (DNS FQDN notation)
///
/// Ports are preserved as-is. Operators must ensure `public_host` config
/// matches exactly what peers use in URLs (including port if non-default).
/// We intentionally do NOT strip "default" ports (80/443) because:
/// 1. We don't have scheme information to know what's "default"
/// 2. A service could run on port 443 without HTTPS
fn canonicalize_host(host: &str) -> String {
    let result = host.to_lowercase();

    // Handle IPv6 addresses: [host]:port format
    if result.starts_with('[') {
        // IPv6 in brackets - trailing dot doesn't apply, return as-is (lowercased)
        return result;
    }

    // For IPv4/hostname, check for trailing dot before any port
    // Format is either "hostname" or "hostname:port" or "hostname.:port"
    if let Some(colon_pos) = result.rfind(':') {
        // Has port - check for trailing dot on hostname part
        let hostname = &result[..colon_pos];
        let port_part = &result[colon_pos..]; // includes the colon
        let hostname_clean = hostname.strip_suffix('.').unwrap_or(hostname);
        format!("{}{}", hostname_clean, port_part)
    } else {
        // No port - just strip trailing dot if present
        result.strip_suffix('.').unwrap_or(&result).to_string()
    }
}

/// Canonicalize a path for consistent comparison.
///
/// - Resolve `.` and `..` segments
/// - Remove double slashes
fn canonicalize_path(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();

    for segment in path.split('/') {
        match segment {
            "" | "." => {
                // Skip empty segments (from double slashes) and current dir
            }
            ".." => {
                // Go up one level if possible
                segments.pop();
            }
            s => {
                segments.push(s);
            }
        }
    }

    // Reconstruct with leading slash
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reme_identity::Identity;

    fn test_identity() -> NodeIdentity {
        let identity = Identity::generate();
        NodeIdentity::new(identity)
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let identity = test_identity();
        let dest_host = "node2.example.com:3000";
        let method = "POST";
        let path = "/api/v1/submit";
        let body = b"test body content";

        let headers = SignedHeaders::sign(&identity, method, path, body, dest_host);

        // Build header map
        let mut header_map = axum::http::HeaderMap::new();
        for (name, value) in headers.to_headers() {
            header_map.insert(
                axum::http::header::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }

        // Verify
        let verifier = SignatureVerifier::new(Some(dest_host), &[]);
        let result = verifier.verify(&header_map, method, path, body);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), *identity.public_id());
    }

    #[test]
    fn test_tampered_body_rejected() {
        let identity = test_identity();
        let dest_host = "node2.example.com:3000";
        let method = "POST";
        let path = "/api/v1/submit";
        let body = b"original body";

        let headers = SignedHeaders::sign(&identity, method, path, body, dest_host);

        let mut header_map = axum::http::HeaderMap::new();
        for (name, value) in headers.to_headers() {
            header_map.insert(
                axum::http::header::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }

        // Try to verify with tampered body
        let verifier = SignatureVerifier::new(Some(dest_host), &[]);
        let result = verifier.verify(&header_map, method, path, b"tampered body");
        assert_eq!(result, Err(SignatureError::InvalidSignature));
    }

    #[test]
    fn test_expired_timestamp_rejected() {
        let identity = test_identity();
        let dest_host = "node2.example.com:3000";
        let method = "POST";
        let path = "/api/v1/submit";
        let body = b"test body";

        // Sign with old timestamp (6 minutes ago)
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 6 * 60;

        let headers =
            SignedHeaders::sign_with_timestamp(&identity, method, path, body, dest_host, old_timestamp);

        let mut header_map = axum::http::HeaderMap::new();
        for (name, value) in headers.to_headers() {
            header_map.insert(
                axum::http::header::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }

        let verifier = SignatureVerifier::new(Some(dest_host), &[]);
        let result = verifier.verify(&header_map, method, path, body);
        assert_eq!(result, Err(SignatureError::TimestampExpired));
    }

    #[test]
    fn test_future_timestamp_rejected() {
        let identity = test_identity();
        let dest_host = "node2.example.com:3000";
        let method = "POST";
        let path = "/api/v1/submit";
        let body = b"test body";

        // Sign with future timestamp (1 minute ahead)
        let future_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;

        let headers =
            SignedHeaders::sign_with_timestamp(&identity, method, path, body, dest_host, future_timestamp);

        let mut header_map = axum::http::HeaderMap::new();
        for (name, value) in headers.to_headers() {
            header_map.insert(
                axum::http::header::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }

        let verifier = SignatureVerifier::new(Some(dest_host), &[]);
        let result = verifier.verify(&header_map, method, path, body);
        assert_eq!(result, Err(SignatureError::TimestampFuture));
    }

    #[test]
    fn test_wrong_destination_rejected() {
        let identity = test_identity();
        let dest_host = "node2.example.com:3000";
        let method = "POST";
        let path = "/api/v1/submit";
        let body = b"test body";

        let headers = SignedHeaders::sign(&identity, method, path, body, dest_host);

        let mut header_map = axum::http::HeaderMap::new();
        for (name, value) in headers.to_headers() {
            header_map.insert(
                axum::http::header::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }

        // Verify with different destination
        let verifier = SignatureVerifier::new(Some("node3.example.com:3000"), &[]);
        let result = verifier.verify(&header_map, method, path, body);
        assert!(matches!(result, Err(SignatureError::DestinationMismatch { .. })));
    }

    #[test]
    fn test_additional_hosts_accepted() {
        let identity = test_identity();
        let dest_host = "192.168.1.5:3000";
        let method = "POST";
        let path = "/api/v1/submit";
        let body = b"test body";

        let headers = SignedHeaders::sign(&identity, method, path, body, dest_host);

        let mut header_map = axum::http::HeaderMap::new();
        for (name, value) in headers.to_headers() {
            header_map.insert(
                axum::http::header::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }

        // Verify with additional_hosts including the IP
        let additional = vec!["192.168.1.5:3000".to_string()];
        let verifier = SignatureVerifier::new(Some("node.example.com:3000"), &additional);
        let result = verifier.verify(&header_map, method, path, body);
        assert!(result.is_ok());
    }

    #[test]
    fn test_canonicalize_host() {
        // Lowercase
        assert_eq!(canonicalize_host("Node.Example.COM:3000"), "node.example.com:3000");

        // Ports are preserved (no scheme-dependent stripping)
        assert_eq!(canonicalize_host("example.com:80"), "example.com:80");
        assert_eq!(canonicalize_host("example.com:443"), "example.com:443");
        assert_eq!(canonicalize_host("example.com:8080"), "example.com:8080");

        // Remove trailing dot
        assert_eq!(canonicalize_host("example.com."), "example.com");
        assert_eq!(canonicalize_host("example.com.:443"), "example.com:443");

        // IPv6 addresses
        assert_eq!(canonicalize_host("[::1]:3000"), "[::1]:3000");
        assert_eq!(canonicalize_host("[::1]:80"), "[::1]:80");
        assert_eq!(canonicalize_host("[::1]:443"), "[::1]:443");
        assert_eq!(canonicalize_host("[2001:db8::1]:8080"), "[2001:db8::1]:8080");
        assert_eq!(canonicalize_host("[2001:DB8::1]:8080"), "[2001:db8::1]:8080"); // lowercase
        assert_eq!(canonicalize_host("[::1]"), "[::1]"); // no port
    }

    #[test]
    fn test_canonicalize_path() {
        // Normal path
        assert_eq!(canonicalize_path("/api/v1/submit"), "/api/v1/submit");

        // Double slashes
        assert_eq!(canonicalize_path("/api//v1///submit"), "/api/v1/submit");

        // Current dir
        assert_eq!(canonicalize_path("/api/./v1/./submit"), "/api/v1/submit");

        // Parent dir
        assert_eq!(canonicalize_path("/api/v2/../v1/submit"), "/api/v1/submit");
        assert_eq!(canonicalize_path("/api/v1/../v1/./submit"), "/api/v1/submit");

        // Root
        assert_eq!(canonicalize_path("/"), "/");
        assert_eq!(canonicalize_path("//"), "/");
    }

    #[test]
    fn test_node_id_pubkey_mismatch_rejected() {
        let identity = test_identity();
        let other_identity = test_identity();
        let dest_host = "node2.example.com:3000";
        let method = "POST";
        let path = "/api/v1/submit";
        let body = b"test body";

        let mut headers = SignedHeaders::sign(&identity, method, path, body, dest_host);

        // Swap in a different public key
        headers.pubkey = BASE64.encode(other_identity.public_id().to_bytes());

        let mut header_map = axum::http::HeaderMap::new();
        for (name, value) in headers.to_headers() {
            header_map.insert(
                axum::http::header::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }

        let verifier = SignatureVerifier::new(Some(dest_host), &[]);
        let result = verifier.verify(&header_map, method, path, body);
        assert_eq!(result, Err(SignatureError::NodeIdMismatch));
    }

    #[test]
    fn test_duplicate_header_rejected() {
        let identity = test_identity();
        let dest_host = "node2.example.com:3000";
        let method = "POST";
        let path = "/api/v1/submit";
        let body = b"test body";

        let headers = SignedHeaders::sign(&identity, method, path, body, dest_host);

        let mut header_map = axum::http::HeaderMap::new();
        for (name, value) in headers.to_headers() {
            header_map.insert(
                axum::http::header::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }

        // Add duplicate signature header
        header_map.append(
            HEADER_NODE_SIGNATURE,
            "duplicate_value".parse().unwrap(),
        );

        let verifier = SignatureVerifier::new(Some(dest_host), &[]);
        let result = verifier.verify(&header_map, method, path, body);
        assert_eq!(result, Err(SignatureError::DuplicateHeader(HEADER_NODE_SIGNATURE)));
    }

    #[test]
    fn test_no_public_host_accepts_any_destination() {
        let identity = test_identity();
        let dest_host = "any.host.com:9999";
        let method = "POST";
        let path = "/api/v1/submit";
        let body = b"test body";

        let headers = SignedHeaders::sign(&identity, method, path, body, dest_host);

        let mut header_map = axum::http::HeaderMap::new();
        for (name, value) in headers.to_headers() {
            header_map.insert(
                axum::http::header::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }

        // No public_host configured - should accept any destination
        let verifier = SignatureVerifier::new(None, &[]);
        let result = verifier.verify(&header_map, method, path, body);
        assert!(result.is_ok());
    }
}
