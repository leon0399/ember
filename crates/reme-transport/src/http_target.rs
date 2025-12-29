//! HTTP transport target implementation.
//!
//! This module provides `HttpTarget`, a single-endpoint HTTP transport
//! with its own configuration, TLS client, and health tracking.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::*;
use reme_message::{OuterEnvelope, RoutingKey, SignedAckTombstone, TombstoneEnvelope, WirePayload};
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::target::{HealthData, HealthState, TargetConfig, TargetHealth, TargetId, TargetKind, TransportTarget};
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

impl HttpTarget {
    /// Create a new HTTP target.
    ///
    /// Builds a custom HTTP client with:
    /// - Certificate pinning (if configured)
    /// - Request timeout from config
    /// - Connect timeout from config
    pub fn new(config: HttpTargetConfig) -> Result<Self, TransportError> {
        let client = build_target_client(&config)?;
        let health = TargetHealth::new(
            config.base.circuit_breaker_threshold,
            config.base.circuit_breaker_recovery,
        );

        Ok(Self {
            config,
            client,
            health,
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
    async fn submit_payload(&self, payload_b64: &str) -> Result<(), TransportError> {
        // Parse URL and extract credentials if present
        let parsed = parse_url_with_auth(&self.config.url)
            .map_err(|e| TransportError::Network(format!("Invalid URL: {}", e)))?;

        let url = format!("{}/api/v1/submit", parsed.url.trim_end_matches('/'));

        let mut request = self
            .client
            .post(&url)
            .header("Content-Type", "text/plain")
            .timeout(self.config.base.request_timeout)
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
                "HTTP {}: {}",
                status, body
            )));
        }

        let _result: SubmitResponse = response
            .json()
            .await
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        Ok(())
    }

    /// Get a display label for logging.
    fn display_label(&self) -> String {
        if let Some(ref label) = self.config.base.label {
            label.clone()
        } else {
            sanitize_url_for_log(&self.config.url)
        }
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
    async fn fetch_from_endpoint(
        &self,
        routing_key_b64: &str,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        // Parse URL and extract credentials if present
        let parsed = parse_url_with_auth(&self.config.url)
            .map_err(|e| TransportError::Network(format!("Invalid URL: {}", e)))?;

        let url = format!(
            "{}/api/v1/fetch/{}",
            parsed.url.trim_end_matches('/'),
            routing_key_b64
        );

        let mut request = self.client.get(&url).timeout(self.config.base.request_timeout);

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
                "HTTP {}: {}",
                status, body
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
                .map_err(|e| TransportError::Serialization(format!("base64 decode: {}", e)))?;

            let payload = WirePayload::decode(&wire_bytes)
                .map_err(|e| TransportError::Serialization(format!("wire decode: {}", e)))?;

            // Only extract messages (tombstones are handled separately)
            if let WirePayload::Message(envelope) = payload {
                envelopes.push(envelope);
            }
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

    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        let start = Instant::now();

        // Encode as WirePayload
        let wire_payload = WirePayload::Message(envelope);
        let wire_bytes = wire_payload.encode();
        let payload_b64 = BASE64_STANDARD.encode(&wire_bytes);

        let result = self.submit_payload(&payload_b64).await;

        match &result {
            Ok(()) => {
                self.record_success(start.elapsed());
                debug!("Message submitted to {}", self.display_label());
            }
            Err(e) => {
                self.record_failure(e);
                warn!("Failed to submit message to {}: {}", self.display_label(), e);
            }
        }

        result
    }

    async fn submit_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), TransportError> {
        let start = Instant::now();

        // Encode as WirePayload
        let wire_payload = WirePayload::Tombstone(tombstone);
        let wire_bytes = wire_payload.encode();
        let payload_b64 = BASE64_STANDARD.encode(&wire_bytes);

        let result = self.submit_payload(&payload_b64).await;

        match &result {
            Ok(()) => {
                self.record_success(start.elapsed());
                debug!("Tombstone submitted to {}", self.display_label());
            }
            Err(e) => {
                self.record_failure(e);
                warn!("Failed to submit tombstone to {}: {}", self.display_label(), e);
            }
        }

        result
    }

    async fn submit_ack_tombstone(&self, tombstone: SignedAckTombstone) -> Result<(), TransportError> {
        let start = Instant::now();

        // Encode as WirePayload
        let wire_payload = WirePayload::AckTombstone(tombstone);
        let wire_bytes = wire_payload.encode();
        let payload_b64 = BASE64_STANDARD.encode(&wire_bytes);

        let result = self.submit_payload(&payload_b64).await;

        match &result {
            Ok(()) => {
                self.record_success(start.elapsed());
                debug!("AckTombstone submitted to {}", self.display_label());
            }
            Err(e) => {
                self.record_failure(e);
                warn!("Failed to submit ack tombstone to {}: {}", self.display_label(), e);
            }
        }

        result
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
#[async_trait]
impl crate::Transport for HttpTarget {
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        <Self as TransportTarget>::submit_message(self, envelope).await
    }

    async fn submit_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), TransportError> {
        <Self as TransportTarget>::submit_tombstone(self, tombstone).await
    }

    async fn submit_ack_tombstone(&self, tombstone: SignedAckTombstone) -> Result<(), TransportError> {
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
            TransportError::TlsConfig(format!(
                "Could not extract hostname from URL to apply certificate pin"
            ))
        })?;

        // Create pins map with single entry
        let mut pins = std::collections::HashMap::new();
        if let Some(ref pin) = config.cert_pin {
            pins.insert(hostname, pin.clone());
        }

        // Create pinning verifier
        let verifier = PinningVerifier::new(pins)
            .map_err(|e| TransportError::TlsConfig(e.to_string()))?;

        // Build rustls client config with custom verifier
        let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::TlsConfig(format!("Failed to set protocol versions: {}", e)))?
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
        .and_then(|u| u.host_str().map(|h| h.to_string()))
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
}
