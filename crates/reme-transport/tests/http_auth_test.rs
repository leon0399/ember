#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Integration tests for HTTP authentication precedence.
//!
//! Tests verify:
//! 1. Explicit auth (config) is applied correctly
//! 2. URL-embedded auth still works (backward compatibility)
//! 3. Explicit auth takes precedence over URL-embedded auth
//! 4. No auth = no Authorization header

use reme_identity::Identity;
use reme_message::{MessageID, OuterEnvelope, SignedAckTombstone};
use reme_transport::http_target::{HttpTarget, HttpTargetConfig};
use reme_transport::target::TargetKind;
use reme_transport::target::TransportTarget;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Match, Request};

/// Custom matcher that verifies Authorization header is NOT present.
struct NoAuthHeader;

impl Match for NoAuthHeader {
    fn matches(&self, request: &Request) -> bool {
        !request.headers.contains_key("authorization")
    }
}
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Build a minimal test `OuterEnvelope` for submission.
///
/// We don't need real encryption for auth tests, just a valid wire format.
fn build_test_envelope() -> OuterEnvelope {
    let bob = Identity::generate();
    let routing_key = bob.public_id().routing_key();

    // Build minimal OuterEnvelope (no actual encryption needed for auth tests)
    OuterEnvelope::new(
        routing_key,
        None,           // No TTL
        [0u8; 32],      // Dummy ephemeral key
        [0u8; 16],      // Dummy ack_hash
        vec![0u8; 100], // Dummy ciphertext
    )
}

/// Build a test `SignedAckTombstone` for submission.
fn build_test_tombstone() -> SignedAckTombstone {
    let alice = Identity::generate();
    let message_id = MessageID::new();
    let ack_secret = [42u8; 16];

    SignedAckTombstone::new(message_id, ack_secret, &alice.x25519_secret().to_bytes())
}

#[tokio::test]
async fn test_explicit_auth_applied() {
    // Start mock server expecting specific Basic Auth
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/submit"))
        .and(header(
            "Authorization",
            "Basic dXNlcjpwYXNzd29yZA==", // base64("user:password")
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"status": "ok"}]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Create HttpTarget with explicit auth
    let config =
        HttpTargetConfig::new(mock_server.uri(), TargetKind::Stable).with_auth("user", "password");

    let target = HttpTarget::new(config).expect("Failed to create HttpTarget");

    // Submit envelope
    let envelope = build_test_envelope();
    let result = target.submit_message(envelope).await;

    assert!(
        result.is_ok(),
        "Explicit auth should be applied: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_url_embedded_auth_works() {
    // Start mock server expecting URL-embedded auth
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/submit"))
        .and(header(
            "Authorization",
            "Basic dXJsX3VzZXI6dXJsX3Bhc3M=", // base64("url_user:url_pass")
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"status": "ok"}]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Create HttpTarget with URL-embedded auth
    let url_with_auth = format!("http://url_user:url_pass@{}", mock_server.address());
    let config = HttpTargetConfig::new(url_with_auth, TargetKind::Stable);

    let target = HttpTarget::new(config).expect("Failed to create HttpTarget");

    // Submit envelope
    let envelope = build_test_envelope();
    let result = target.submit_message(envelope).await;

    assert!(
        result.is_ok(),
        "URL-embedded auth should work: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_explicit_auth_takes_precedence() {
    // Start mock server expecting EXPLICIT auth, NOT URL-embedded auth
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/submit"))
        .and(header(
            "Authorization",
            "Basic Y29uZmlnX3VzZXI6Y29uZmlnX3Bhc3M=", // base64("config_user:config_pass")
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"status": "ok"}]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Create HttpTarget with BOTH URL-embedded and explicit auth
    // Explicit should win
    let url_with_auth = format!("http://url_user:url_pass@{}", mock_server.address());
    let config = HttpTargetConfig::new(url_with_auth, TargetKind::Stable)
        .with_auth("config_user", "config_pass");

    let target = HttpTarget::new(config).expect("Failed to create HttpTarget");

    // Submit envelope
    let envelope = build_test_envelope();
    let result = target.submit_message(envelope).await;

    assert!(
        result.is_ok(),
        "Explicit auth should take precedence: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_no_auth_no_header() {
    // Start mock server expecting NO Authorization header
    let mock_server = MockServer::start().await;

    // This mock will match requests WITHOUT Authorization header
    Mock::given(method("POST"))
        .and(NoAuthHeader)
        .and(path("/api/v1/submit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"status": "ok"}]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Create HttpTarget without any auth
    let config = HttpTargetConfig::new(mock_server.uri(), TargetKind::Stable);

    let target = HttpTarget::new(config).expect("Failed to create HttpTarget");

    // Submit envelope
    let envelope = build_test_envelope();
    let result = target.submit_message(envelope).await;

    assert!(
        result.is_ok(),
        "No auth should mean no Authorization header: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_tombstone_uses_explicit_auth() {
    // Start mock server expecting explicit auth for tombstone submission
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/submit"))
        .and(header(
            "Authorization",
            "Basic dG9tYl91c2VyOnRvbWJfcGFzcw==", // base64("tomb_user:tomb_pass")
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"status": "ok"}]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Create HttpTarget with explicit auth
    let config = HttpTargetConfig::new(mock_server.uri(), TargetKind::Stable)
        .with_auth("tomb_user", "tomb_pass");

    let target = HttpTarget::new(config).expect("Failed to create HttpTarget");

    // Submit tombstone
    let tombstone = build_test_tombstone();
    let result = target.submit_ack_tombstone(tombstone).await;

    assert!(
        result.is_ok(),
        "Explicit auth should be applied to tombstone: {:?}",
        result.err()
    );
}
