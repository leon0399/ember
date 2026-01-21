use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::*;
use futures::future::join_all;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
use rand::Rng;
use reme_identity::PublicID;
use reme_message::{MessageID, OuterEnvelope, RoutingKey, SignedAckTombstone, WirePayload};
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, info, warn};
use url::Url;

use reme_encryption::build_identity_sign_data;

use crate::tls::{CertPin, PinningVerifier};
use crate::url_auth::parse_url_with_auth;
use crate::{Transport, TransportError};

/// Response from the identity endpoint.
///
/// Privacy-preserving: returns only the signature, not the node's identity.
/// Clients verify the signature against known contacts' public keys.
#[derive(Debug, Deserialize)]
struct IdentityResponse {
    /// Base64-encoded 64-byte `XEdDSA` signature
    signature: String,
}

/// Node configuration for `HttpTransport`.
#[derive(Debug, Clone)]
pub struct NodeSpec {
    /// Node URL (http:// or https://)
    pub url: String,
    /// Optional certificate pin for TLS verification
    pub cert_pin: Option<CertPin>,
}

/// HTTP transport client for communicating with mailbox nodes (MIK-only, no prekeys)
///
/// Supports multiple nodes for redundancy. When multiple nodes are configured:
/// - Payloads (messages/tombstones) are sent to ALL nodes (broadcast)
/// - Messages are fetched from ALL nodes and deduplicated
pub struct HttpTransport {
    base_urls: Vec<String>,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct SubmitResponse {
    #[allow(dead_code)]
    status: String,
}

#[derive(Debug, Deserialize)]
struct FetchResponse {
    payloads: Vec<String>,
}

impl HttpTransport {
    /// Create a new HTTP transport with a single node URL
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_urls: vec![base_url.into()],
            client: Client::new(),
        }
    }

    /// Create a new HTTP transport with multiple node URLs for redundancy
    pub fn with_nodes(base_urls: Vec<String>) -> Self {
        assert!(!base_urls.is_empty(), "At least one node URL is required");
        Self {
            base_urls,
            client: Client::new(),
        }
    }

    /// Create with a custom reqwest client and single node
    pub fn with_client(base_url: impl Into<String>, client: Client) -> Self {
        Self {
            base_urls: vec![base_url.into()],
            client,
        }
    }

    /// Create with a custom reqwest client and multiple nodes
    pub fn with_nodes_and_client(base_urls: Vec<String>, client: Client) -> Self {
        assert!(!base_urls.is_empty(), "At least one node URL is required");
        Self { base_urls, client }
    }

    /// Create a new HTTP transport with node configurations (URLs + optional pins).
    ///
    /// This is the recommended constructor for production use. It:
    /// - Builds a custom TLS client with certificate pinning
    /// - Warns on HTTP URLs (unencrypted)
    /// - Warns on HTTPS URLs without pins (vulnerable to MITM)
    ///
    /// # Example
    /// ```ignore
    /// let nodes = vec![
    ///     NodeSpec { url: "https://node1.example.com".into(), cert_pin: Some(pin) },
    ///     NodeSpec { url: "https://node2.example.com".into(), cert_pin: None },
    /// ];
    /// let transport = HttpTransport::with_nodes_config(nodes)?;
    /// ```
    pub fn with_nodes_config(nodes: Vec<NodeSpec>) -> Result<Self, TransportError> {
        if nodes.is_empty() {
            return Err(TransportError::TlsConfig(
                "At least one node is required".to_string(),
            ));
        }

        // Collect pins and emit warnings
        let mut pins: HashMap<String, CertPin> = HashMap::new();
        for node in &nodes {
            if node.url.starts_with("http://") {
                warn!(
                    "Node {} uses unencrypted HTTP - credentials and messages may be exposed",
                    sanitize_url_for_log(&node.url)
                );
            } else if node.url.starts_with("https://") {
                if let Some(ref pin) = node.cert_pin {
                    if let Some(host) = extract_hostname(&node.url) {
                        pins.insert(host, pin.clone());
                        info!(
                            "Certificate pinning enabled for {}",
                            sanitize_url_for_log(&node.url)
                        );
                    } else {
                        // Fail if we can't extract hostname for a pinned URL
                        return Err(TransportError::TlsConfig(format!(
                            "Could not extract hostname from URL '{}' to apply certificate pin",
                            sanitize_url_for_log(&node.url)
                        )));
                    }
                } else {
                    warn!(
                        "Node {} has no certificate pin - vulnerable to MITM attacks",
                        sanitize_url_for_log(&node.url)
                    );
                }
            }
        }

        // Build TLS client with pinning verifier
        let client = build_pinning_client(pins)?;
        let base_urls = nodes.into_iter().map(|n| n.url).collect();

        Ok(Self { base_urls, client })
    }

    /// Get the configured node URLs
    pub fn node_urls(&self) -> &[String] {
        &self.base_urls
    }

    /// Verify node identity via challenge-response.
    ///
    /// Generates a random challenge, requests a signature, and verifies it against
    /// the expected public key. This is privacy-preserving: the node never reveals
    /// its identity, preventing enumeration attacks.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the node (e.g., `http://localhost:3000`)
    /// * `expected_pubkey` - The expected node public key (from known contacts)
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid for the expected public key.
    ///
    /// # Errors
    ///
    /// - `TransportError::Network` - Connection failed
    /// - `TransportError::ServerError` - Server returned error
    /// - `TransportError::Serialization` - Response parsing failed
    /// - `TransportError::SignatureVerificationFailed` - Signature invalid for expected key
    pub async fn verify_identity(
        &self,
        base_url: &str,
        expected_pubkey: &PublicID,
    ) -> Result<(), TransportError> {
        // Generate 32-byte random challenge
        let challenge: [u8; 32] = rand::rng().random();
        let challenge_b64 = BASE64_STANDARD.encode(challenge);

        // Parse URL and extract credentials if present
        let parsed = parse_url_with_auth(base_url)
            .map_err(|e| TransportError::Network(format!("Invalid URL: {e}")))?;

        // URL-encode the base64 challenge since + and / are special in URLs.
        // Standard base64 uses +, /, and = which need encoding in query parameters.
        let challenge_encoded = percent_encode(challenge_b64.as_bytes(), NON_ALPHANUMERIC);

        let url = format!(
            "{}/api/v1/identity?challenge={}",
            parsed.url.trim_end_matches('/'),
            challenge_encoded
        );

        let mut request = self.client.get(&url);

        // Add Basic Auth if credentials were embedded in URL
        if let Some((username, password)) = parsed.auth {
            request = request.basic_auth(username, Some(password));
        }

        let response = request
            .send()
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            if status == reqwest::StatusCode::UNAUTHORIZED {
                return Err(TransportError::AuthenticationFailed);
            }
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown error".to_string());
            return Err(TransportError::ServerError(format!(
                "HTTP {status}: {body}"
            )));
        }

        let identity_response: IdentityResponse = response
            .json()
            .await
            .map_err(|e| TransportError::Serialization(format!("JSON parse error: {e}")))?;

        // Build sign data using shared helper and expected pubkey
        let expected_pubkey_bytes = expected_pubkey.to_bytes();
        let sign_data = build_identity_sign_data(&challenge, &expected_pubkey_bytes);

        // Decode and verify signature against expected pubkey
        let signature: [u8; 64] = BASE64_STANDARD
            .decode(&identity_response.signature)
            .map_err(|e| TransportError::Serialization(format!("Invalid signature base64: {e}")))?
            .try_into()
            .map_err(|_| {
                TransportError::Serialization("signature must be exactly 64 bytes".to_string())
            })?;

        if !expected_pubkey.verify_xeddsa(&sign_data, &signature) {
            return Err(TransportError::SignatureVerificationFailed);
        }

        debug!("Verified identity for {}", expected_pubkey);

        Ok(())
    }

    /// Submit wire payload to a single node
    ///
    /// Supports URL-embedded credentials (e.g., `http://user:pass@host/`)
    /// which are extracted and sent as HTTP Basic Auth headers.
    async fn submit_to_node(
        &self,
        base_url: &str,
        payload_b64: &str,
    ) -> Result<(), TransportError> {
        // Parse URL and extract credentials if present
        let parsed = parse_url_with_auth(base_url)
            .map_err(|e| TransportError::Network(format!("Invalid URL: {e}")))?;

        let url = format!("{}/api/v1/submit", parsed.url.trim_end_matches('/'));

        let mut request = self
            .client
            .post(&url)
            .header("Content-Type", "text/plain")
            .body(payload_b64.to_string());

        // Add Basic Auth if credentials were embedded in URL
        if let Some((username, password)) = parsed.auth {
            request = request.basic_auth(username, Some(password));
        }

        let response = request
            .send()
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            if status == reqwest::StatusCode::UNAUTHORIZED {
                return Err(TransportError::AuthenticationFailed);
            }
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown error".to_string());
            return Err(TransportError::ServerError(format!(
                "HTTP {status}: {body}"
            )));
        }

        let _result: SubmitResponse = response
            .json()
            .await
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        Ok(())
    }

    /// Fetch messages from a single node
    ///
    /// Supports URL-embedded credentials (e.g., `http://user:pass@host/`)
    /// which are extracted and sent as HTTP Basic Auth headers.
    async fn fetch_from_node(
        &self,
        base_url: &str,
        routing_key_b64: &str,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        // Parse URL and extract credentials if present
        let parsed = parse_url_with_auth(base_url)
            .map_err(|e| TransportError::Network(format!("Invalid URL: {e}")))?;

        let url = format!(
            "{}/api/v1/fetch/{}",
            parsed.url.trim_end_matches('/'),
            routing_key_b64
        );

        let mut request = self.client.get(&url);

        // Add Basic Auth if credentials were embedded in URL
        if let Some((username, password)) = parsed.auth {
            request = request.basic_auth(username, Some(password));
        }

        let response = request
            .send()
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            if status == reqwest::StatusCode::UNAUTHORIZED {
                return Err(TransportError::AuthenticationFailed);
            }
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown error".to_string());
            return Err(TransportError::ServerError(format!(
                "HTTP {status}: {body}"
            )));
        }

        let result: FetchResponse = response
            .json()
            .await
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        // Decode and deserialize each wire payload
        let mut envelopes = Vec::new();
        for blob in result.payloads {
            let wire_bytes = BASE64_STANDARD
                .decode(&blob)
                .map_err(|e| TransportError::Serialization(format!("base64 decode: {e}")))?;

            let payload = WirePayload::decode(&wire_bytes)
                .map_err(|e| TransportError::Serialization(format!("wire decode: {e}")))?;

            // Only extract messages (tombstones are handled separately)
            if let WirePayload::Message(envelope) = payload {
                envelopes.push(envelope);
            }
        }

        Ok(envelopes)
    }

    /// Fetch messages once from all configured nodes and deduplicate
    ///
    /// This method performs a single fetch operation, useful for:
    /// - Testing scenarios
    /// - One-shot message retrieval
    /// - Initial sync before starting push-based receiving
    ///
    /// For continuous message receiving, use `MessageReceiver` instead.
    pub async fn fetch_once(
        &self,
        routing_key: &RoutingKey,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        let routing_key_b64 = URL_SAFE_NO_PAD.encode(routing_key);

        // Fetch from all nodes in parallel
        let futures: Vec<_> = self
            .base_urls
            .iter()
            .map(|url| self.fetch_from_node(url, &routing_key_b64))
            .collect();

        let results = join_all(futures).await;

        // Aggregate and deduplicate by message_id
        let mut messages_by_id: HashMap<MessageID, OuterEnvelope> = HashMap::new();
        let mut last_error = None;
        let mut success_count = 0;

        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(messages) => {
                    debug!(
                        "Fetched {} messages from node {}",
                        messages.len(),
                        self.base_urls[i]
                    );
                    success_count += 1;
                    for msg in messages {
                        messages_by_id.insert(msg.message_id, msg);
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch from node {}: {}", self.base_urls[i], e);
                    last_error = Some(e);
                }
            }
        }

        // If we got messages from at least one node, return them
        if success_count > 0 {
            let messages: Vec<_> = messages_by_id.into_values().collect();
            debug!(
                "Fetched {} unique messages from {}/{} nodes",
                messages.len(),
                success_count,
                self.base_urls.len()
            );
            Ok(messages)
        } else {
            Err(last_error.unwrap_or(TransportError::Network("All nodes failed".to_string())))
        }
    }
}

#[async_trait]
impl Transport for HttpTransport {
    /// Submit message to all configured nodes (broadcast)
    ///
    /// Returns success if ANY node accepts the message.
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        // Encode as WirePayload (includes type discriminator)
        let wire_payload = WirePayload::Message(envelope);
        let wire_bytes = wire_payload.encode();

        // Base64 encode
        let envelope_b64 = BASE64_STANDARD.encode(&wire_bytes);

        // Submit to all nodes in parallel
        let futures: Vec<_> = self
            .base_urls
            .iter()
            .map(|url| self.submit_to_node(url, &envelope_b64))
            .collect();

        let results = join_all(futures).await;

        // Check results - succeed if ANY node succeeded
        let mut last_error = None;
        let mut success_count = 0;

        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(()) => {
                    debug!("Message submitted to node {}", self.base_urls[i]);
                    success_count += 1;
                }
                Err(e) => {
                    warn!("Failed to submit to node {}: {}", self.base_urls[i], e);
                    last_error = Some(e);
                }
            }
        }

        if success_count > 0 {
            debug!(
                "Message submitted to {}/{} nodes",
                success_count,
                self.base_urls.len()
            );
            Ok(())
        } else {
            Err(last_error.unwrap_or(TransportError::Network("All nodes failed".to_string())))
        }
    }

    /// Submit ack tombstone to all configured nodes (broadcast)
    ///
    /// Returns success if ANY node accepts the tombstone.
    async fn submit_ack_tombstone(
        &self,
        tombstone: SignedAckTombstone,
    ) -> Result<(), TransportError> {
        // Encode as WirePayload (includes type discriminator)
        let wire_payload = WirePayload::AckTombstone(tombstone);
        let wire_bytes = wire_payload.encode();

        // Base64 encode
        let tombstone_b64 = BASE64_STANDARD.encode(&wire_bytes);

        // Submit to all nodes in parallel
        let futures: Vec<_> = self
            .base_urls
            .iter()
            .map(|url| self.submit_to_node(url, &tombstone_b64))
            .collect();

        let results = join_all(futures).await;

        // Check results - succeed if ANY node succeeded
        let mut last_error = None;
        let mut success_count = 0;

        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(()) => {
                    debug!("AckTombstone submitted to node {}", self.base_urls[i]);
                    success_count += 1;
                }
                Err(e) => {
                    warn!(
                        "Failed to submit ack tombstone to node {}: {}",
                        self.base_urls[i], e
                    );
                    last_error = Some(e);
                }
            }
        }

        if success_count > 0 {
            debug!(
                "AckTombstone submitted to {}/{} nodes",
                success_count,
                self.base_urls.len()
            );
            Ok(())
        } else {
            Err(last_error.unwrap_or(TransportError::Network("All nodes failed".to_string())))
        }
    }
}

/// Extract hostname from URL for pin lookup.
fn extract_hostname(url_str: &str) -> Option<String> {
    Url::parse(url_str)
        .ok()
        .and_then(|u| u.host_str().map(std::string::ToString::to_string))
}

/// Sanitize URL for logging (remove credentials).
fn sanitize_url_for_log(url_str: &str) -> String {
    match parse_url_with_auth(url_str) {
        Ok(parsed) => parsed.url,
        // Don't return original URL on parse failure - it may contain credentials
        Err(_) => "[invalid URL]".to_string(),
    }
}

/// Build a reqwest client with TLS certificate pinning.
fn build_pinning_client(pins: HashMap<String, CertPin>) -> Result<Client, TransportError> {
    // Create pinning verifier (empty pins map = standard verification only)
    let verifier =
        PinningVerifier::new(pins).map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    // Build rustls client config with custom verifier.
    // Use ring as the crypto provider explicitly.
    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| TransportError::TlsConfig(format!("Failed to set protocol versions: {e}")))?
    // SAFETY: We use dangerous() to install a custom certificate verifier, but our
    // PinningVerifier still performs full certificate chain validation via the inner
    // WebPkiServerVerifier. The "dangerous" API is required because we add additional
    // pin verification on top of standard TLS validation - we do NOT bypass any security.
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(verifier))
    .with_no_client_auth();

    // Build reqwest client with custom TLS config
    Client::builder()
        .use_preconfigured_tls(tls_config)
        .build()
        .map_err(|e| TransportError::TlsConfig(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Json, Router};
    use serde::Serialize;
    use tokio::net::TcpListener;

    /// Start a minimal mock server for testing.
    async fn start_mock_server(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind");
        let addr = listener.local_addr().expect("Failed to get local addr");
        let url = format!("http://{addr}");

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("Server failed");
        });

        // Small delay for server startup
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        (url, handle)
    }

    #[test]
    fn test_http_transport_single_node() {
        let transport = HttpTransport::new("https://example.com");
        assert_eq!(transport.base_urls, vec!["https://example.com"]);
    }

    #[test]
    fn test_http_transport_multiple_nodes() {
        let transport = HttpTransport::with_nodes(vec![
            "https://node1.example.com".to_string(),
            "https://node2.example.com".to_string(),
            "https://node3.example.com".to_string(),
        ]);
        assert_eq!(transport.base_urls.len(), 3);
    }

    #[test]
    fn test_node_urls_accessor() {
        let transport = HttpTransport::with_nodes(vec![
            "https://a.com".to_string(),
            "https://b.com".to_string(),
        ]);
        assert_eq!(transport.node_urls(), &["https://a.com", "https://b.com"]);
    }

    #[test]
    #[should_panic(expected = "At least one node URL is required")]
    fn test_empty_nodes_panics() {
        HttpTransport::with_nodes(vec![]);
    }

    #[test]
    fn test_extract_hostname() {
        assert_eq!(
            extract_hostname("https://example.com:8443/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_hostname("http://localhost:3000"),
            Some("localhost".to_string())
        );
        assert_eq!(extract_hostname("invalid"), None);
    }

    #[test]
    fn test_sanitize_url_for_log() {
        assert_eq!(
            sanitize_url_for_log("https://user:pass@example.com/api"),
            "https://example.com/api"
        );
        assert_eq!(
            sanitize_url_for_log("https://example.com/api"),
            "https://example.com/api"
        );
        // Invalid URLs should return placeholder, not the original (which may contain credentials)
        assert_eq!(sanitize_url_for_log("not-a-url"), "[invalid URL]");
    }

    #[test]
    fn test_with_nodes_config_no_pins() {
        let nodes = vec![
            NodeSpec {
                url: "https://node1.example.com".to_string(),
                cert_pin: None,
            },
            NodeSpec {
                url: "https://node2.example.com".to_string(),
                cert_pin: None,
            },
        ];
        let transport = HttpTransport::with_nodes_config(nodes).unwrap();
        assert_eq!(transport.node_urls().len(), 2);
    }

    #[test]
    fn test_with_nodes_config_with_pins() {
        let pin =
            CertPin::parse("spki//sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let nodes = vec![NodeSpec {
            url: "https://example.com".to_string(),
            cert_pin: Some(pin),
        }];
        let transport = HttpTransport::with_nodes_config(nodes).unwrap();
        assert_eq!(transport.node_urls().len(), 1);
    }

    #[test]
    fn test_with_nodes_config_empty_returns_error() {
        let result = HttpTransport::with_nodes_config(vec![]);
        assert!(result.is_err());
        match result {
            Err(TransportError::TlsConfig(msg)) => {
                assert!(msg.contains("At least one node"));
            }
            _ => panic!("Expected TlsConfig error"),
        }
    }

    /// Test verify_identity with a valid server response.
    #[tokio::test]
    async fn test_verify_identity_valid_response() {
        use axum::extract::Query;
        use base64::prelude::*;
        use reme_identity::Identity;

        // Create a node identity for the mock server
        let node_identity = Identity::generate();
        let node_pubkey = *node_identity.public_id();

        // Clone for the closure
        let node_identity_clone = node_identity.to_bytes();

        #[derive(Deserialize)]
        struct IdentityQuery {
            challenge: String,
        }

        #[derive(Serialize)]
        struct MockIdentityResponse {
            signature: String,
        }

        let app = Router::new().route(
            "/api/v1/identity",
            get(move |Query(query): Query<IdentityQuery>| {
                let identity = Identity::from_bytes(&node_identity_clone);
                let pubkey_bytes = identity.public_id().to_bytes();

                // Decode and validate challenge
                let challenge: [u8; 32] = BASE64_STANDARD
                    .decode(&query.challenge)
                    .expect("Invalid challenge base64")
                    .try_into()
                    .expect("Challenge must be 32 bytes");

                let sign_data = build_identity_sign_data(&challenge, &pubkey_bytes);
                let signature = identity.sign_xeddsa(&sign_data);

                async move {
                    Json(MockIdentityResponse {
                        signature: BASE64_STANDARD.encode(signature),
                    })
                }
            }),
        );

        let (url, _handle) = start_mock_server(app).await;

        let transport = HttpTransport::new(&url);
        let result = transport.verify_identity(&url, &node_pubkey).await;

        assert!(
            result.is_ok(),
            "verify_identity should succeed: {:?}",
            result.err()
        );
    }

    /// Test verify_identity rejects invalid signatures.
    #[tokio::test]
    async fn test_verify_identity_invalid_signature_rejected() {
        use axum::extract::Query;
        use base64::prelude::*;
        use reme_identity::Identity;

        // Create a node identity (the one we expect)
        let expected_identity = Identity::generate();
        let expected_pubkey = *expected_identity.public_id();

        // Create a DIFFERENT identity that actually signs (wrong signer)
        let wrong_signer = Identity::generate();
        let wrong_signer_bytes = wrong_signer.to_bytes();

        #[derive(Deserialize)]
        struct IdentityQuery {
            challenge: String,
        }

        #[derive(Serialize)]
        struct MockIdentityResponse {
            signature: String,
        }

        let app = Router::new().route(
            "/api/v1/identity",
            get(move |Query(query): Query<IdentityQuery>| {
                let wrong_identity = Identity::from_bytes(&wrong_signer_bytes);
                let wrong_pubkey_bytes = wrong_identity.public_id().to_bytes();

                // Decode and validate challenge
                let challenge: [u8; 32] = BASE64_STANDARD
                    .decode(&query.challenge)
                    .expect("Invalid challenge base64")
                    .try_into()
                    .expect("Challenge must be 32 bytes");

                // Sign with WRONG key - this should be detected
                let sign_data = build_identity_sign_data(&challenge, &wrong_pubkey_bytes);
                let signature = wrong_identity.sign_xeddsa(&sign_data);

                async move {
                    Json(MockIdentityResponse {
                        signature: BASE64_STANDARD.encode(signature),
                    })
                }
            }),
        );

        let (url, _handle) = start_mock_server(app).await;

        let transport = HttpTransport::new(&url);
        // We pass the expected pubkey, but server signed with wrong key
        let result = transport.verify_identity(&url, &expected_pubkey).await;

        assert!(
            result.is_err(),
            "verify_identity should fail with invalid signature"
        );
        match result {
            Err(TransportError::SignatureVerificationFailed) => {}
            Err(e) => panic!("Expected SignatureVerificationFailed, got: {:?}", e),
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    /// Test verify_identity handles malformed response gracefully.
    #[tokio::test]
    async fn test_verify_identity_malformed_response() {
        use axum::response::IntoResponse;
        use reme_identity::Identity;

        let expected_pubkey = *Identity::generate().public_id();

        let app = Router::new().route(
            "/api/v1/identity",
            get(|| async { (axum::http::StatusCode::OK, "not json").into_response() }),
        );

        let (url, _handle) = start_mock_server(app).await;

        let transport = HttpTransport::new(&url);
        let result = transport.verify_identity(&url, &expected_pubkey).await;

        assert!(
            result.is_err(),
            "verify_identity should fail with malformed response"
        );
        match result {
            Err(TransportError::Serialization(_)) => {}
            Err(e) => panic!("Expected Serialization error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    /// Test verify_identity handles server error.
    #[tokio::test]
    async fn test_verify_identity_server_error() {
        use axum::response::IntoResponse;
        use reme_identity::Identity;

        let expected_pubkey = *Identity::generate().public_id();

        let app = Router::new().route(
            "/api/v1/identity",
            get(|| async {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error",
                )
                    .into_response()
            }),
        );

        let (url, _handle) = start_mock_server(app).await;

        let transport = HttpTransport::new(&url);
        let result = transport.verify_identity(&url, &expected_pubkey).await;

        assert!(
            result.is_err(),
            "verify_identity should fail with server error"
        );
        match result {
            Err(TransportError::ServerError(_)) => {}
            Err(e) => panic!("Expected ServerError, got: {:?}", e),
            Ok(_) => panic!("Expected error, got success"),
        }
    }
}
