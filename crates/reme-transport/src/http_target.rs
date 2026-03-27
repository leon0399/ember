//! HTTP transport target implementation.
//!
//! This module provides `HttpTarget`, a single-endpoint HTTP transport
//! with its own configuration, TLS client, and health tracking.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::*;
use reme_identity::PublicID;
use reme_message::{OuterEnvelope, RoutingKey, SignedAckTombstone, WirePayload};
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::http_pagination::{decode_fetch_payloads, validate_next_cursor};
use crate::target::{
    HealthData, HealthState, RawReceipt, TargetConfig, TargetHealth, TargetId, TargetKind,
    TransportTarget,
};
use crate::tls::{CertPin, PinningVerifier};
use crate::url_auth::parse_url_with_auth;
use crate::TransportError;

/// Configuration for a single HTTP target.
#[derive(Debug, Clone)]
pub struct HttpTargetConfig {
    /// Base target configuration.
    pub base: TargetConfig,

    /// Target URL (with optional embedded credentials).
    pub url: String,

    /// Optional certificate pin for TLS verification.
    pub cert_pin: Option<CertPin>,

    /// Explicit HTTP Basic Auth credentials (username, password).
    ///
    /// Takes precedence over URL-embedded credentials.
    pub auth: Option<(String, String)>,
}

impl HttpTargetConfig {
    /// Create a new HTTP target configuration.
    pub fn new(url: impl Into<String>, kind: TargetKind) -> Self {
        let url = url.into();
        let id = TargetId::http(&url);
        Self {
            base: TargetConfig::new(id, kind),
            url,
            cert_pin: None,
            auth: None,
        }
    }

    /// Create a stable HTTP target (mailbox node, configured peer).
    pub fn stable(url: impl Into<String>) -> Self {
        Self::new(url, TargetKind::Stable)
    }

    /// Create an ephemeral HTTP target (discovered peer).
    pub fn ephemeral(url: impl Into<String>) -> Self {
        Self::new(url, TargetKind::Ephemeral)
    }

    /// Set the certificate pin for TLS verification.
    pub fn with_cert_pin(mut self, pin: CertPin) -> Self {
        self.cert_pin = Some(pin);
        self
    }

    /// Set explicit HTTP Basic Auth credentials.
    ///
    /// Takes precedence over URL-embedded credentials.
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some((username.into(), password.into()));
        self
    }

    /// Set a human-readable label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.base.label = Some(label.into());
        self
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.base.priority = priority;
        self
    }

    /// Set the request timeout.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.base.request_timeout = timeout;
        self
    }

    /// Set the connect timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.base.connect_timeout = timeout;
        self
    }

    /// Set the node's public identity for receipt verification.
    ///
    /// When set, receipts from this target can be verified using this public key.
    /// The `routing_key()` derived from this is also used to filter targets
    /// during Direct tier delivery.
    pub fn with_node_pubkey(mut self, pubkey: PublicID) -> Self {
        self.base.node_pubkey = Some(pubkey);
        self
    }

    /// Set an optional node public identity.
    pub fn with_node_pubkey_opt(mut self, pubkey: Option<PublicID>) -> Self {
        self.base.node_pubkey = pubkey;
        self
    }

    /// Check if this target can serve messages for the given routing key.
    ///
    /// Delegates to the base `TargetConfig::can_serve()` method.
    pub fn can_serve(&self, routing_key: &RoutingKey) -> bool {
        self.base.can_serve(routing_key)
    }
}

/// A single HTTP endpoint transport target.
///
/// Each `HttpTarget` has its own:
/// - `reqwest::Client` with its own TLS configuration
/// - Certificate pin (if configured)
/// - Health tracking with circuit breaker
/// - Timeouts and priority
pub struct HttpTarget {
    config: HttpTargetConfig,
    client: Client,
    health: TargetHealth,
    /// Sanitized URL (credentials removed, parsed once in constructor).
    sanitized_url: String,
    /// URL-embedded auth credentials (parsed once in constructor).
    url_auth: Option<(String, String)>,
}

#[derive(Debug, Deserialize)]
struct SubmitResponse {
    results: Vec<FrameResultResponse>,
}

#[derive(Debug, Deserialize)]
struct FrameResultResponse {
    #[allow(dead_code)]
    status: String,
    ack_secret: Option<String>,
    signature: Option<String>,
    #[allow(dead_code)]
    error: Option<String>,
}

impl FrameResultResponse {
    /// Parse the response into a `RawReceipt`.
    fn into_raw_receipt(self) -> RawReceipt {
        let ack_secret = self.ack_secret.and_then(|s| {
            BASE64_STANDARD.decode(&s).ok().and_then(|bytes| {
                bytes
                    .try_into()
                    .map_err(|e: Vec<u8>| {
                        warn!("Invalid ack_secret length: {} (expected 16)", e.len());
                    })
                    .ok()
            })
        });

        let signature = self.signature.and_then(|s| {
            BASE64_STANDARD.decode(&s).ok().and_then(|bytes| {
                bytes
                    .try_into()
                    .map_err(|e: Vec<u8>| {
                        warn!("Invalid signature length: {} (expected 64)", e.len());
                    })
                    .ok()
            })
        });

        RawReceipt {
            ack_secret,
            signature,
        }
    }
}

#[derive(Debug, Deserialize)]
struct FetchResponse {
    payloads: Vec<String>,
    next_cursor: Option<String>,
    has_more: bool,
}

impl HttpTarget {
    /// Create a new HTTP target.
    ///
    /// Builds a custom HTTP client with:
    /// - Certificate pinning (if configured)
    /// - Request timeout from config
    /// - Connect timeout from config
    pub fn new(config: HttpTargetConfig) -> Result<Self, TransportError> {
        // Parse URL once to extract credentials and sanitized URL
        let parsed = parse_url_with_auth(&config.url)
            .map_err(|e| TransportError::Network(format!("Invalid URL: {e}")))?;

        let client = build_target_client(&config)?;
        let health = TargetHealth::new(
            config.base.circuit_breaker_threshold,
            config.base.circuit_breaker_recovery,
        );

        Ok(Self {
            config,
            client,
            health,
            sanitized_url: parsed.url,
            url_auth: parsed.auth,
        })
    }

    /// Get the target URL.
    pub fn url(&self) -> &str {
        &self.config.url
    }

    /// Get the certificate pin if configured.
    pub fn cert_pin(&self) -> Option<&CertPin> {
        self.config.cert_pin.as_ref()
    }

    /// Submit a wire payload to this target.
    ///
    /// Returns the raw receipt data from the node (if any).
    async fn submit_payload(&self, wire_bytes: &[u8]) -> Result<RawReceipt, TransportError> {
        let url = format!("{}/api/v1/submit", self.sanitized_url.trim_end_matches('/'));

        let bundle_body = reme_bundle::encode_body(&[wire_bytes]);

        let mut request = self
            .client
            .post(&url)
            .header("Content-Type", "application/vnd.reme.bundle")
            .timeout(self.config.base.request_timeout)
            .body(bundle_body);

        // Priority 1: Explicit auth from config
        // Priority 2: URL-embedded auth (legacy/backward compat)
        let auth = self.config.auth.as_ref().or(self.url_auth.as_ref());
        if let Some((username, password)) = auth {
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
            if status == reqwest::StatusCode::NOT_FOUND {
                return Err(TransportError::NotFound);
            }
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown error".to_string());
            return Err(TransportError::ServerError(format!(
                "HTTP {status}: {body}"
            )));
        }

        let result: SubmitResponse = response
            .json()
            .await
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        let frame = result.results.into_iter().next().ok_or_else(|| {
            TransportError::ServerError("empty results in submit response".to_string())
        })?;

        // Check for per-frame errors
        if let Some(ref error) = frame.error {
            let err_lower = error.to_lowercase();
            if err_lower.contains("not found") {
                return Err(TransportError::NotFound);
            }
            if err_lower.contains("invalid ack_secret") || err_lower.contains("authorization") {
                return Err(TransportError::ServerError(format!("403: {error}")));
            }
            return Err(TransportError::ServerError(error.clone()));
        }

        Ok(frame.into_raw_receipt())
    }

    /// Get a display label for logging.
    fn display_label(&self) -> String {
        self.config
            .base
            .label
            .clone()
            .unwrap_or_else(|| sanitize_url_for_log(&self.config.url))
    }

    /// Fetch messages once from this target.
    ///
    /// This method performs a single fetch operation from this endpoint.
    /// Health tracking is updated based on success/failure.
    pub async fn fetch_once(
        &self,
        routing_key: &RoutingKey,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        let start = Instant::now();
        let routing_key_b64 = URL_SAFE_NO_PAD.encode(routing_key);

        let result = self.fetch_from_endpoint(&routing_key_b64).await;

        match &result {
            Ok(messages) => {
                self.record_success(start.elapsed());
                if !messages.is_empty() {
                    debug!(
                        "Fetched {} messages from {}",
                        messages.len(),
                        self.display_label()
                    );
                }
            }
            Err(e) => {
                self.record_failure(e);
                warn!("Failed to fetch from {}: {}", self.display_label(), e);
            }
        }

        result
    }

    /// Internal fetch implementation.
    async fn fetch_page_from_endpoint(
        &self,
        routing_key_b64: &str,
        after: Option<&str>,
    ) -> Result<FetchResponse, TransportError> {
        let url = format!(
            "{}/api/v1/fetch/{}",
            self.sanitized_url.trim_end_matches('/'),
            routing_key_b64
        );

        let mut request = self
            .client
            .get(&url)
            .timeout(self.config.base.request_timeout);
        if let Some(after) = after {
            request = request.query(&[("after", after)]);
        }

        // Priority 1: Explicit auth from config
        // Priority 2: URL-embedded auth (legacy/backward compat)
        let auth = self.config.auth.as_ref().or(self.url_auth.as_ref());
        if let Some((username, password)) = auth {
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
            if status == reqwest::StatusCode::NOT_FOUND {
                return Err(TransportError::NotFound);
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

    async fn fetch_from_endpoint(
        &self,
        routing_key_b64: &str,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        let mut after = None;
        let mut previous_cursor = None;
        let mut envelopes = Vec::new();

        loop {
            let page = self
                .fetch_page_from_endpoint(routing_key_b64, after.as_deref())
                .await?;
            envelopes.extend(decode_fetch_payloads(page.payloads)?);

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
}

#[async_trait]
impl TransportTarget for HttpTarget {
    fn id(&self) -> &TargetId {
        &self.config.base.id
    }

    fn config(&self) -> &TargetConfig {
        &self.config.base
    }

    fn health(&self) -> HealthState {
        self.health.state()
    }

    fn is_available(&self) -> bool {
        self.health.is_available()
    }

    fn health_data(&self) -> HealthData {
        self.health.to_health_data()
    }

    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<RawReceipt, TransportError> {
        let start = Instant::now();

        // Encode as WirePayload
        let wire_payload = WirePayload::Message(envelope);
        let wire_bytes = wire_payload
            .encode()
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        let result = self.submit_payload(&wire_bytes).await;

        match &result {
            Ok(receipt) => {
                self.record_success(start.elapsed());
                debug!(
                    "Message submitted to {} (receipt: ack={}, sig={})",
                    self.display_label(),
                    receipt.ack_secret.is_some(),
                    receipt.signature.is_some()
                );
            }
            Err(e) => {
                self.record_failure(e);
                warn!(
                    "Failed to submit message to {}: {}",
                    self.display_label(),
                    e
                );
            }
        }

        result
    }

    async fn submit_ack_tombstone(
        &self,
        tombstone: SignedAckTombstone,
    ) -> Result<(), TransportError> {
        let start = Instant::now();

        // Encode as WirePayload
        let wire_payload = WirePayload::AckTombstone(tombstone);
        let wire_bytes = wire_payload
            .encode()
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        let result = self.submit_payload(&wire_bytes).await;

        match &result {
            Ok(_receipt) => {
                self.record_success(start.elapsed());
                debug!("AckTombstone submitted to {}", self.display_label());
            }
            Err(e) => {
                self.record_failure(e);
                warn!(
                    "Failed to submit ack tombstone to {}: {}",
                    self.display_label(),
                    e
                );
            }
        }

        // Discard receipt - tombstones don't need receipt verification
        result.map(|_| ())
    }

    fn record_success(&self, latency: Duration) {
        self.health.record_success(latency);
    }

    fn record_failure(&self, _error: &TransportError) {
        self.health.record_failure();
    }
}

/// Implement `Transport` trait for compatibility with `CompositeTransport`.
///
/// This allows `HttpTarget` to be used directly in the composite transport
/// for direct peer messaging, not just via `TransportPool`.
///
/// Note: Receipt data is discarded in this wrapper; use `TransportTarget`
/// directly if receipt verification is needed.
#[async_trait]
impl crate::Transport for HttpTarget {
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        // Discard receipt data - use TransportTarget directly for receipt verification
        <Self as TransportTarget>::submit_message(self, envelope)
            .await
            .map(|_receipt| ())
    }

    async fn submit_ack_tombstone(
        &self,
        tombstone: SignedAckTombstone,
    ) -> Result<(), TransportError> {
        <Self as TransportTarget>::submit_ack_tombstone(self, tombstone).await
    }
}

/// Build a reqwest client for a specific HTTP target.
fn build_target_client(config: &HttpTargetConfig) -> Result<Client, TransportError> {
    // Check if we need certificate pinning
    let has_pin = config.cert_pin.is_some() && config.url.starts_with("https://");

    if has_pin {
        // Extract hostname from URL
        let hostname = extract_hostname(&config.url).ok_or_else(|| {
            TransportError::TlsConfig(
                "Could not extract hostname from URL to apply certificate pin".to_string(),
            )
        })?;

        // has_pin already verified cert_pin is Some
        let pin = config.cert_pin.as_ref().expect("has_pin requires cert_pin");
        let pins = std::collections::HashMap::from([(hostname, pin.clone())]);

        // Create pinning verifier
        let verifier =
            PinningVerifier::new(pins).map_err(|e| TransportError::TlsConfig(e.to_string()))?;

        // Build rustls client config with custom verifier
        let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::TlsConfig(format!("Failed to set protocol versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

        // Build reqwest client with custom TLS config
        Client::builder()
            .use_preconfigured_tls(tls_config)
            .connect_timeout(config.base.connect_timeout)
            .timeout(config.base.request_timeout)
            .build()
            .map_err(|e| TransportError::TlsConfig(e.to_string()))
    } else {
        // Standard client without pinning
        Client::builder()
            .connect_timeout(config.base.connect_timeout)
            .timeout(config.base.request_timeout)
            .build()
            .map_err(|e| TransportError::TlsConfig(e.to_string()))
    }
}

/// Extract hostname from URL.
fn extract_hostname(url_str: &str) -> Option<String> {
    url::Url::parse(url_str)
        .ok()
        .and_then(|u| u.host_str().map(std::string::ToString::to_string))
}

/// Sanitize URL for logging (remove credentials).
fn sanitize_url_for_log(url_str: &str) -> String {
    match parse_url_with_auth(url_str) {
        Ok(parsed) => parsed.url,
        Err(_) => "[invalid URL]".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::Query, routing::get, Json, Router};
    use base64::prelude::BASE64_STANDARD;
    use reme_identity::RoutingKey;
    use reme_message::{MessageID, WirePayload};
    use serde::{Deserialize, Serialize};
    use tokio::net::TcpListener;

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

    fn build_envelope_with_id(message_id: MessageID, ciphertext: Vec<u8>) -> OuterEnvelope {
        let mut env = OuterEnvelope::new(
            RoutingKey::from([0u8; 16]),
            None,
            [0u8; 32],
            [0u8; 16],
            ciphertext,
        );
        env.message_id = message_id;
        env
    }

    fn encode_envelope_payload(env: &OuterEnvelope) -> String {
        let wire = WirePayload::Message(env.clone());
        BASE64_STANDARD.encode(wire.encode().unwrap())
    }

    #[derive(Debug, Deserialize)]
    struct MockFetchQuery {
        after: Option<String>,
    }

    #[derive(Debug, Serialize)]
    struct MockFetchResponse {
        payloads: Vec<String>,
        next_cursor: Option<String>,
        has_more: bool,
    }

    #[test]
    fn test_http_target_config_stable() {
        let config = HttpTargetConfig::stable("https://example.com:23003");
        assert_eq!(config.base.kind, TargetKind::Stable);
        assert_eq!(config.base.priority, 100);
        assert_eq!(config.base.request_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_http_target_config_ephemeral() {
        let config = HttpTargetConfig::ephemeral("http://192.168.1.50:23003");
        assert_eq!(config.base.kind, TargetKind::Ephemeral);
        assert_eq!(config.base.priority, 200);
        assert_eq!(config.base.request_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_http_target_config_builder() {
        let config = HttpTargetConfig::stable("https://node.example.com")
            .with_label("Primary mailbox")
            .with_priority(150)
            .with_request_timeout(Duration::from_secs(60));

        assert_eq!(config.base.label, Some("Primary mailbox".to_string()));
        assert_eq!(config.base.priority, 150);
        assert_eq!(config.base.request_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_http_target_creation() {
        let config = HttpTargetConfig::stable("http://localhost:23003");
        let target = HttpTarget::new(config).unwrap();

        assert_eq!(target.url(), "http://localhost:23003");
        assert!(target.is_available());
        assert_eq!(target.health(), HealthState::Healthy);
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
    }

    #[tokio::test]
    async fn test_fetch_once_follows_paginated_responses() {
        let env_1 = build_envelope_with_id(MessageID::from_bytes([1; 16]), vec![1]);
        let env_2 = build_envelope_with_id(MessageID::from_bytes([2; 16]), vec![2]);
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
                            next_cursor: Some("1".to_string()),
                            has_more: true,
                        },
                        Some("1") => MockFetchResponse {
                            payloads: vec![payload_2],
                            next_cursor: Some("2".to_string()),
                            has_more: false,
                        },
                        Some(other) => panic!("unexpected cursor {other}"),
                    };

                    Json(response)
                }
            }),
        );

        let (url, _handle) = start_mock_server(app).await;
        let target = HttpTarget::new(HttpTargetConfig::stable(url)).unwrap();
        let routing_key = RoutingKey::from([0u8; 16]);

        let result = target.fetch_once(&routing_key).await.unwrap();
        let message_ids: Vec<_> = result.into_iter().map(|env| env.message_id).collect();

        assert_eq!(message_ids, vec![env_1.message_id, env_2.message_id]);
    }

    #[tokio::test]
    async fn test_fetch_once_errors_when_has_more_missing_cursor() {
        let env = build_envelope_with_id(MessageID::from_bytes([9; 16]), vec![9]);
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
        let target = HttpTarget::new(HttpTargetConfig::stable(url)).unwrap();
        let routing_key = RoutingKey::from([0u8; 16]);
        let error = target.fetch_once(&routing_key).await.unwrap_err();

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
        let env_1 = build_envelope_with_id(MessageID::from_bytes([7; 16]), vec![7]);
        let env_2 = build_envelope_with_id(MessageID::from_bytes([8; 16]), vec![8]);
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
        let target = HttpTarget::new(HttpTargetConfig::stable(url)).unwrap();
        let routing_key = RoutingKey::from([0u8; 16]);
        let error = target.fetch_once(&routing_key).await.unwrap_err();

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
