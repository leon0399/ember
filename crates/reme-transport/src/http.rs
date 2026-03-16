use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::*;
use futures::future::join_all;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
use rand::Rng;
use reme_identity::PublicID;
use reme_message::{OuterEnvelope, RoutingKey, SignedAckTombstone, WirePayload};
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, info, warn};
use url::Url;

use reme_encryption::build_identity_sign_data;

use crate::http_pagination::validate_next_cursor;
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
    next_cursor: Option<String>,
    has_more: bool,
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
    /// a list of candidate public keys. This is privacy-preserving: the node never
    /// reveals its identity, preventing enumeration attacks.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the node (e.g., `http://localhost:3000`)
    /// * `candidates` - Known contacts' public keys to try verification against
    ///
    /// # Returns
    ///
    /// - `Ok(Some(pubkey))` if a candidate's signature is valid (Direct tier use)
    /// - `Ok(None)` if no candidates match (can use as relay - Quorum tier)
    ///
    /// # Errors
    ///
    /// - `TransportError::Network` - Connection failed
    /// - `TransportError::ServerError` - Server returned error
    /// - `TransportError::Serialization` - Response parsing failed
    pub async fn verify_identity(
        &self,
        base_url: &str,
        candidates: &[PublicID],
    ) -> Result<Option<PublicID>, TransportError> {
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

        // Decode signature once (shared across all candidate checks)
        let signature: [u8; 64] = BASE64_STANDARD
            .decode(&identity_response.signature)
            .map_err(|e| TransportError::Serialization(format!("Invalid signature base64: {e}")))?
            .try_into()
            .map_err(|_| {
                TransportError::Serialization("signature must be exactly 64 bytes".to_string())
            })?;

        // Try each candidate until one verifies
        for candidate in candidates {
            let sign_data = build_identity_sign_data(&challenge, &candidate.to_bytes());
            if candidate.verify_xeddsa(&sign_data, &signature) {
                debug!("Verified identity for {}", candidate);
                return Ok(Some(*candidate));
            }
        }

        // No match - can use as relay (Quorum tier)
        debug!(
            "No candidate matched for {} (relay mode)",
            sanitize_url_for_log(base_url)
        );
        Ok(None)
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
    async fn fetch_page_from_node(
        &self,
        base_url: &str,
        routing_key_b64: &str,
        after: Option<&str>,
    ) -> Result<FetchResponse, TransportError> {
        // Parse URL and extract credentials if present
        let parsed = parse_url_with_auth(base_url)
            .map_err(|e| TransportError::Network(format!("Invalid URL: {e}")))?;

        let url = format!(
            "{}/api/v1/fetch/{}",
            parsed.url.trim_end_matches('/'),
            routing_key_b64
        );

        let mut request = self.client.get(&url);
        if let Some(after) = after {
            request = request.query(&[("after", after)]);
        }

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

        response
            .json()
            .await
            .map_err(|e| TransportError::Serialization(e.to_string()))
    }

    fn decode_fetch_payloads(payloads: Vec<String>) -> Result<Vec<OuterEnvelope>, TransportError> {
        let mut envelopes = Vec::new();
        for blob in payloads {
            let wire_bytes = BASE64_STANDARD
                .decode(&blob)
                .map_err(|e| TransportError::Serialization(format!("base64 decode: {e}")))?;

            let payload = WirePayload::decode(&wire_bytes)
                .map_err(|e| TransportError::Serialization(format!("wire decode: {e}")))?;

            if let WirePayload::Message(envelope) = payload {
                envelopes.push(envelope);
            }
        }

        Ok(envelopes)
    }

    async fn fetch_from_node(
        &self,
        base_url: &str,
        routing_key_b64: &str,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        let mut after = None;
        let mut previous_cursor = None;
        let mut envelopes = Vec::new();

        loop {
            let page = self
                .fetch_page_from_node(base_url, routing_key_b64, after.as_deref())
                .await?;
            envelopes.extend(Self::decode_fetch_payloads(page.payloads)?);

            if !page.has_more {
                break;
            }

            let next_cursor = page.next_cursor.ok_or_else(|| {
                TransportError::ServerError(
                    "Paginated fetch response has_more=true but next_cursor is missing".to_string(),
                )
            })?;
            let parsed_next_cursor = validate_next_cursor(&next_cursor, previous_cursor)?;

            after = Some(next_cursor);
            previous_cursor = Some(parsed_next_cursor);
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

        // Aggregate and deduplicate by message_id, preserving conflicting variants
        let mut accumulated = crate::dedup::EnvelopeAccumulator::default();
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
                    crate::dedup::merge_envelopes(
                        &mut accumulated,
                        messages,
                        &sanitize_url_for_log(&self.base_urls[i]),
                    );
                }
                Err(e) => {
                    warn!("Failed to fetch from node {}: {}", self.base_urls[i], e);
                    last_error = Some(e);
                }
            }
        }

        // If we got messages from at least one node, return them
        if success_count > 0 {
            let messages = crate::dedup::flatten_variants(accumulated);
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
    use axum::{extract::Query, routing::get, Json, Router};
    use serde::{Deserialize, Serialize};
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

        let client = reqwest::Client::new();
        let health_url = format!("{url}/");
        let mut server_ready = false;
        for _ in 0..50 {
            if client.get(&health_url).send().await.is_ok() {
                server_ready = true;
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
        assert!(server_ready, "Mock server failed to start within 500ms");

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

    /// Test `verify_identity` with a valid server response - candidate matches.
    #[tokio::test]
    #[allow(clippy::items_after_statements)]
    async fn test_verify_identity_valid() {
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
        let result = transport.verify_identity(&url, &[node_pubkey]).await;

        assert!(
            result.is_ok(),
            "verify_identity should succeed: {:?}",
            result.err()
        );
        assert_eq!(
            result.unwrap(),
            Some(node_pubkey),
            "Should return the matched pubkey"
        );
    }

    /// Test `verify_identity` returns None when no candidates match (relay case).
    #[tokio::test]
    #[allow(clippy::items_after_statements)]
    async fn test_verify_identity_no_match() {
        use axum::extract::Query;
        use base64::prelude::*;
        use reme_identity::Identity;

        // Create a node identity (the one we expect)
        let expected_identity = Identity::generate();
        let expected_pubkey = *expected_identity.public_id();

        // Create a DIFFERENT identity that actually signs (the actual node)
        let actual_node = Identity::generate();
        let actual_node_bytes = actual_node.to_bytes();

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
                let node_identity = Identity::from_bytes(&actual_node_bytes);
                let node_pubkey_bytes = node_identity.public_id().to_bytes();

                // Decode and validate challenge
                let challenge: [u8; 32] = BASE64_STANDARD
                    .decode(&query.challenge)
                    .expect("Invalid challenge base64")
                    .try_into()
                    .expect("Challenge must be 32 bytes");

                // Sign with node's actual key (different from expected)
                let sign_data = build_identity_sign_data(&challenge, &node_pubkey_bytes);
                let signature = node_identity.sign_xeddsa(&sign_data);

                async move {
                    Json(MockIdentityResponse {
                        signature: BASE64_STANDARD.encode(signature),
                    })
                }
            }),
        );

        let (url, _handle) = start_mock_server(app).await;

        let transport = HttpTransport::new(&url);
        // We pass expected_pubkey as candidate, but server is a different node
        let result = transport.verify_identity(&url, &[expected_pubkey]).await;

        assert!(
            result.is_ok(),
            "verify_identity should succeed (relay case): {:?}",
            result.err()
        );
        assert_eq!(
            result.unwrap(),
            None,
            "Should return None when no candidates match (relay use case)"
        );
    }

    /// Test `verify_identity` with multiple candidates - second one matches.
    #[tokio::test]
    #[allow(clippy::items_after_statements)]
    async fn test_verify_identity_multiple_candidates() {
        use axum::extract::Query;
        use base64::prelude::*;
        use reme_identity::Identity;

        // Create multiple identities
        let first_identity = Identity::generate();
        let first_pubkey = *first_identity.public_id();

        let second_identity = Identity::generate();
        let second_pubkey = *second_identity.public_id();

        // Node uses second_identity
        let node_identity_bytes = second_identity.to_bytes();

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
                let identity = Identity::from_bytes(&node_identity_bytes);
                let pubkey_bytes = identity.public_id().to_bytes();

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
        // Pass both candidates - second one should match
        let result = transport
            .verify_identity(&url, &[first_pubkey, second_pubkey])
            .await;

        assert!(
            result.is_ok(),
            "verify_identity should succeed: {:?}",
            result.err()
        );
        assert_eq!(
            result.unwrap(),
            Some(second_pubkey),
            "Should return the second pubkey that matched"
        );
    }

    /// Test `verify_identity` handles malformed response gracefully.
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
        let result = transport.verify_identity(&url, &[expected_pubkey]).await;

        assert!(
            result.is_err(),
            "verify_identity should fail with malformed response"
        );
        match result {
            Err(TransportError::Serialization(_)) => {}
            Err(e) => panic!("Expected Serialization error, got: {e:?}"),
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    /// Test `verify_identity` handles server error.
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
        let result = transport.verify_identity(&url, &[expected_pubkey]).await;

        assert!(
            result.is_err(),
            "verify_identity should fail with server error"
        );
        match result {
            Err(TransportError::ServerError(_)) => {}
            Err(e) => panic!("Expected ServerError, got: {e:?}"),
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    /// Build a test envelope with a specific `message_id` and ciphertext.
    fn build_envelope_with_id(
        message_id: reme_message::MessageID,
        ciphertext: Vec<u8>,
    ) -> OuterEnvelope {
        let mut env = OuterEnvelope::new(
            reme_identity::RoutingKey::from([0u8; 16]),
            None,
            [0u8; 32],
            [0u8; 16],
            ciphertext,
        );
        env.message_id = message_id;
        env
    }

    /// Encode an envelope as a base64 wire payload string (for mock server responses).
    fn encode_envelope_payload(env: &OuterEnvelope) -> String {
        let wire = WirePayload::Message(env.clone());
        BASE64_STANDARD.encode(wire.encode())
    }

    #[derive(Serialize)]
    struct MockFetchResponse {
        payloads: Vec<String>,
        next_cursor: Option<String>,
        has_more: bool,
    }

    #[derive(Debug, Deserialize)]
    struct MockFetchQuery {
        after: Option<String>,
    }

    #[tokio::test]
    async fn test_fetch_once_conflicting_envelopes() {
        let msg_id = reme_message::MessageID::from_bytes([0x42; 16]);
        let env_a = build_envelope_with_id(msg_id, vec![0xAA; 50]);
        let env_b = build_envelope_with_id(msg_id, vec![0xBB; 50]);

        let payload_a = encode_envelope_payload(&env_a);
        let payload_b = encode_envelope_payload(&env_b);

        let app_a = Router::new().route(
            "/api/v1/fetch/{routing_key}",
            get(move || async move {
                Json(MockFetchResponse {
                    payloads: vec![payload_a.clone()],
                    next_cursor: Some("1".to_string()),
                    has_more: false,
                })
            }),
        );

        let app_b = Router::new().route(
            "/api/v1/fetch/{routing_key}",
            get(move || async move {
                Json(MockFetchResponse {
                    payloads: vec![payload_b.clone()],
                    next_cursor: Some("1".to_string()),
                    has_more: false,
                })
            }),
        );

        let (url_a, _h1) = start_mock_server(app_a).await;
        let (url_b, _h2) = start_mock_server(app_b).await;

        let transport = HttpTransport::with_nodes(vec![url_a, url_b]);
        let routing_key = reme_identity::RoutingKey::from([0u8; 16]);
        let result = transport.fetch_once(&routing_key).await.unwrap();

        assert_eq!(
            result.len(),
            2,
            "Both conflicting variants should be preserved"
        );
        assert!(result.contains(&env_a));
        assert!(result.contains(&env_b));
    }

    #[tokio::test]
    async fn test_fetch_once_identical_envelopes_deduped() {
        let msg_id = reme_message::MessageID::from_bytes([0x42; 16]);
        let env = build_envelope_with_id(msg_id, vec![0xAA; 50]);

        let payload = encode_envelope_payload(&env);
        let payload_clone = payload.clone();

        let app_a = Router::new().route(
            "/api/v1/fetch/{routing_key}",
            get(move || async move {
                Json(MockFetchResponse {
                    payloads: vec![payload.clone()],
                    next_cursor: Some("1".to_string()),
                    has_more: false,
                })
            }),
        );

        let app_b = Router::new().route(
            "/api/v1/fetch/{routing_key}",
            get(move || async move {
                Json(MockFetchResponse {
                    payloads: vec![payload_clone.clone()],
                    next_cursor: Some("1".to_string()),
                    has_more: false,
                })
            }),
        );

        let (url_a, _h1) = start_mock_server(app_a).await;
        let (url_b, _h2) = start_mock_server(app_b).await;

        let transport = HttpTransport::with_nodes(vec![url_a, url_b]);
        let routing_key = reme_identity::RoutingKey::from([0u8; 16]);
        let result = transport.fetch_once(&routing_key).await.unwrap();

        assert_eq!(
            result.len(),
            1,
            "Identical envelopes should be deduplicated"
        );
    }

    #[tokio::test]
    async fn test_fetch_once_follows_paginated_responses_in_order() {
        let env_1 = build_envelope_with_id(reme_message::MessageID::from_bytes([1; 16]), vec![1]);
        let env_2 = build_envelope_with_id(reme_message::MessageID::from_bytes([2; 16]), vec![2]);
        let env_3 = build_envelope_with_id(reme_message::MessageID::from_bytes([3; 16]), vec![3]);
        let env_4 = build_envelope_with_id(reme_message::MessageID::from_bytes([4; 16]), vec![4]);

        let payload_1 = encode_envelope_payload(&env_1);
        let payload_2 = encode_envelope_payload(&env_2);
        let payload_3 = encode_envelope_payload(&env_3);
        let payload_4 = encode_envelope_payload(&env_4);

        let app = Router::new().route(
            "/api/v1/fetch/{routing_key}",
            get(move |Query(query): Query<MockFetchQuery>| {
                let payload_1 = payload_1.clone();
                let payload_2 = payload_2.clone();
                let payload_3 = payload_3.clone();
                let payload_4 = payload_4.clone();

                async move {
                    let response = match query.after.as_deref() {
                        None => MockFetchResponse {
                            payloads: vec![payload_1, payload_2],
                            next_cursor: Some("2".to_string()),
                            has_more: true,
                        },
                        Some("2") => MockFetchResponse {
                            payloads: vec![payload_3],
                            next_cursor: Some("3".to_string()),
                            has_more: true,
                        },
                        Some("3") => MockFetchResponse {
                            payloads: vec![payload_4],
                            next_cursor: Some("4".to_string()),
                            has_more: false,
                        },
                        Some(other) => panic!("unexpected cursor {other}"),
                    };

                    Json(response)
                }
            }),
        );

        let (url, _handle) = start_mock_server(app).await;
        let transport = HttpTransport::new(url);
        let routing_key = reme_identity::RoutingKey::from([0u8; 16]);

        let result = transport.fetch_once(&routing_key).await.unwrap();
        let message_ids: Vec<_> = result.into_iter().map(|env| env.message_id).collect();

        assert_eq!(
            message_ids,
            vec![
                env_1.message_id,
                env_2.message_id,
                env_3.message_id,
                env_4.message_id
            ]
        );
    }

    #[tokio::test]
    async fn test_fetch_once_errors_when_has_more_missing_cursor() {
        let env = build_envelope_with_id(reme_message::MessageID::from_bytes([9; 16]), vec![9]);
        let payload = encode_envelope_payload(&env);

        let app = Router::new().route(
            "/api/v1/fetch/{routing_key}",
            get(move || async move {
                Json(MockFetchResponse {
                    payloads: vec![payload.clone()],
                    next_cursor: None,
                    has_more: true,
                })
            }),
        );

        let (url, _handle) = start_mock_server(app).await;
        let transport = HttpTransport::new(url);
        let routing_key = reme_identity::RoutingKey::from([0u8; 16]);
        let error = transport.fetch_once(&routing_key).await.unwrap_err();

        match error {
            TransportError::ServerError(message) => {
                assert!(
                    message.contains("next_cursor"),
                    "unexpected error: {message}"
                );
            }
            other => panic!("expected server error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_fetch_once_errors_when_next_cursor_regresses() {
        let env_1 = build_envelope_with_id(reme_message::MessageID::from_bytes([7; 16]), vec![7]);
        let env_2 = build_envelope_with_id(reme_message::MessageID::from_bytes([8; 16]), vec![8]);
        let payload_1 = encode_envelope_payload(&env_1);
        let payload_2 = encode_envelope_payload(&env_2);

        let app = Router::new().route(
            "/api/v1/fetch/{routing_key}",
            get(move |Query(query): Query<MockFetchQuery>| {
                let payload_1 = payload_1.clone();
                let payload_2 = payload_2.clone();

                async move {
                    let response = match query.after.as_deref() {
                        None => MockFetchResponse {
                            payloads: vec![payload_1],
                            next_cursor: Some("2".to_string()),
                            has_more: true,
                        },
                        Some("2") => MockFetchResponse {
                            payloads: vec![payload_2],
                            next_cursor: Some("1".to_string()),
                            has_more: true,
                        },
                        Some(other) => panic!("unexpected cursor {other}"),
                    };

                    Json(response)
                }
            }),
        );

        let (url, _handle) = start_mock_server(app).await;
        let transport = HttpTransport::new(url);
        let routing_key = reme_identity::RoutingKey::from([0u8; 16]);
        let error = transport.fetch_once(&routing_key).await.unwrap_err();

        match error {
            TransportError::ServerError(message) => {
                assert!(
                    message.contains("non-advancing next_cursor"),
                    "unexpected error: {message}"
                );
            }
            other => panic!("expected server error, got {other:?}"),
        }
    }
}
