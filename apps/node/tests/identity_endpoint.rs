#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Integration tests for the identity endpoint.
//!
//! Tests that nodes correctly respond to challenge-response identity verification.

use base64::prelude::*;
use node::{
    api, node_identity::NodeIdentity, replication, PersistentMailboxStore, PersistentStoreConfig,
};
use reme_encryption::build_identity_sign_data;
use reme_identity::Identity;
use serde::Deserialize;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::TcpListener;

/// Response from /api/v1/identity
#[derive(Debug, Deserialize)]
struct IdentityResponse {
    signature: String,
}

/// Error response
#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

/// Create an identity and save it to a temp file.
fn create_temp_identity() -> (NodeIdentity, tempfile::TempDir) {
    let dir = tempdir().expect("Failed to create temp dir");
    let path = dir.path().join("node-identity.key");
    let identity = Identity::generate();
    std::fs::write(&path, identity.to_bytes()).expect("Failed to write identity");
    let node_identity = NodeIdentity::load_or_generate(&path).expect("Failed to load identity");
    (node_identity, dir)
}

/// Start a test node with optional signing identity.
async fn start_test_node(
    identity: Option<Arc<NodeIdentity>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().expect("Failed to get local addr");
    let url = format!("http://{addr}");

    let config = PersistentStoreConfig {
        max_messages_per_mailbox: 1000,
        default_ttl_secs: 3600,
    };
    let store =
        Arc::new(PersistentMailboxStore::open(":memory:", config).expect("Failed to create store"));

    let node_id = identity
        .as_ref()
        .map_or_else(|| "test-node".to_string(), |i| i.node_id().to_string());

    let replication = Arc::new(replication::ReplicationClient::with_identity(
        node_id,
        vec![],
        identity.clone(),
    ));

    let state = Arc::new(api::AppState {
        store,
        replication,
        auth: None,
        submit_key_limiter: None,
        mqtt_bridge: None,
        identity,
        public_host: None,
        additional_hosts: vec![],
        config: node::config::NodeConfig::default(),
    });
    let app = api::router(state, None);

    let url_clone = url.clone();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("Server failed");
    });

    // Wait for server readiness
    let health_url = format!("{url_clone}/api/v1/health");
    let client = reqwest::Client::new();
    let mut server_ready = false;
    for _ in 0..50 {
        if client.get(&health_url).send().await.is_ok() {
            server_ready = true;
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    assert!(server_ready, "Test server failed to start within 500ms");

    (url, handle)
}

/// Test: Valid challenge returns valid response with verifiable signature.
#[tokio::test]
async fn test_valid_challenge_returns_valid_response() {
    // Create node identity
    let (node_identity, _dir) = create_temp_identity();
    let node_pubkey = *node_identity.public_id();

    // Start node with identity
    let (url, _handle) = start_test_node(Some(Arc::new(node_identity))).await;

    // Generate a random 32-byte challenge
    let challenge: [u8; 32] = rand::random();
    let challenge_b64 = BASE64_STANDARD.encode(challenge);

    // Request identity verification
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{url}/api/v1/identity"))
        .query(&[("challenge", &challenge_b64)])
        .send()
        .await
        .expect("Request failed");

    assert!(response.status().is_success(), "Request should succeed");

    // PRIVACY CHECK: Parse raw JSON to verify no identity-revealing fields
    let raw_json: serde_json::Value = response.json().await.expect("Failed to parse response");

    assert!(
        raw_json.get("node_pubkey").is_none(),
        "Response should NOT contain node_pubkey (privacy)"
    );
    assert!(
        raw_json.get("routing_keys").is_none(),
        "Response should NOT contain routing_keys (privacy)"
    );
    assert!(
        raw_json.get("signature").is_some(),
        "Response should contain signature"
    );

    // Verify signature using the known public key
    // (In production, clients verify against their contacts' known keys)
    let signature: [u8; 64] = BASE64_STANDARD
        .decode(
            raw_json["signature"]
                .as_str()
                .expect("signature should be string"),
        )
        .expect("Invalid base64 signature")
        .try_into()
        .expect("Wrong signature length");

    // Reconstruct signed data using shared helper and known pubkey
    let sign_data = build_identity_sign_data(&challenge, &node_pubkey.to_bytes());

    assert!(
        node_pubkey.verify_xeddsa(&sign_data, &signature),
        "Signature should verify with node's public key"
    );
}

/// Test: No identity configured returns 401 Unauthorized.
#[tokio::test]
async fn test_no_identity_returns_401() {
    // Start node WITHOUT identity
    let (url, _handle) = start_test_node(None).await;

    // Generate a valid challenge
    let challenge: [u8; 32] = rand::random();
    let challenge_b64 = BASE64_STANDARD.encode(challenge);

    // Request identity verification
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{url}/api/v1/identity"))
        .query(&[("challenge", &challenge_b64)])
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        response.status().as_u16(),
        401,
        "Should return 401 Unauthorized when no identity configured"
    );

    let error: ErrorResponse = response.json().await.expect("Failed to parse error");
    assert!(
        error.error.contains("identity"),
        "Error message should mention identity"
    );
}

/// Test: Invalid challenge (not 32 bytes) returns 400 Bad Request.
#[tokio::test]
async fn test_invalid_challenge_length_returns_400() {
    // Create node identity
    let (node_identity, _dir) = create_temp_identity();

    // Start node with identity
    let (url, _handle) = start_test_node(Some(Arc::new(node_identity))).await;

    let client = reqwest::Client::new();

    // Test with too short challenge (16 bytes instead of 32)
    let short_challenge: [u8; 16] = rand::random();
    let short_challenge_b64 = BASE64_STANDARD.encode(short_challenge);

    let response = client
        .get(format!("{url}/api/v1/identity"))
        .query(&[("challenge", &short_challenge_b64)])
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        response.status().as_u16(),
        400,
        "Should return 400 Bad Request for short challenge"
    );

    let error: ErrorResponse = response.json().await.expect("Failed to parse error");
    assert!(
        error.error.contains("32 bytes"),
        "Error message should mention expected size"
    );

    // Test with too long challenge (64 bytes instead of 32)
    let long_challenge: [u8; 64] = rand::random();
    let long_challenge_b64 = BASE64_STANDARD.encode(long_challenge);

    let response = client
        .get(format!("{url}/api/v1/identity"))
        .query(&[("challenge", &long_challenge_b64)])
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        response.status().as_u16(),
        400,
        "Should return 400 Bad Request for long challenge"
    );
}

/// Test: Invalid base64 challenge returns 400 Bad Request.
#[tokio::test]
async fn test_invalid_base64_challenge_returns_400() {
    // Create node identity
    let (node_identity, _dir) = create_temp_identity();

    // Start node with identity
    let (url, _handle) = start_test_node(Some(Arc::new(node_identity))).await;

    // Send invalid base64
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{url}/api/v1/identity"))
        .query(&[("challenge", "not-valid-base64!!!")])
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        response.status().as_u16(),
        400,
        "Should return 400 Bad Request for invalid base64"
    );

    let error: ErrorResponse = response.json().await.expect("Failed to parse error");
    assert!(
        error.error.contains("base64") || error.error.contains("Invalid"),
        "Error message should mention base64 or invalid encoding"
    );
}

/// Test: Signature is specific to the challenge (different challenges produce different signatures).
#[tokio::test]
async fn test_signature_is_challenge_specific() {
    // Create node identity
    let (node_identity, _dir) = create_temp_identity();
    let node_pubkey = *node_identity.public_id();

    // Start node with identity
    let (url, _handle) = start_test_node(Some(Arc::new(node_identity))).await;

    let client = reqwest::Client::new();

    // First challenge
    let challenge1: [u8; 32] = rand::random();
    let challenge1_b64 = BASE64_STANDARD.encode(challenge1);

    let response1 = client
        .get(format!("{url}/api/v1/identity"))
        .query(&[("challenge", &challenge1_b64)])
        .send()
        .await
        .expect("Request failed");

    let identity1: IdentityResponse = response1.json().await.expect("Failed to parse response");
    let signature1: [u8; 64] = BASE64_STANDARD
        .decode(&identity1.signature)
        .expect("Invalid base64")
        .try_into()
        .expect("Wrong length");

    // Second different challenge
    let challenge2: [u8; 32] = rand::random();
    let challenge2_b64 = BASE64_STANDARD.encode(challenge2);

    let response2 = client
        .get(format!("{url}/api/v1/identity"))
        .query(&[("challenge", &challenge2_b64)])
        .send()
        .await
        .expect("Request failed");

    let identity2: IdentityResponse = response2.json().await.expect("Failed to parse response");
    let signature2: [u8; 64] = BASE64_STANDARD
        .decode(&identity2.signature)
        .expect("Invalid base64")
        .try_into()
        .expect("Wrong length");

    // Signatures should be different for different challenges
    assert_ne!(
        signature1, signature2,
        "Different challenges should produce different signatures"
    );

    // Verify both signatures using the known public key
    let node_pubkey_bytes = node_pubkey.to_bytes();
    let sign_data1 = build_identity_sign_data(&challenge1, &node_pubkey_bytes);
    let sign_data2 = build_identity_sign_data(&challenge2, &node_pubkey_bytes);

    assert!(
        node_pubkey.verify_xeddsa(&sign_data1, &signature1),
        "Signature 1 should verify with challenge 1"
    );
    assert!(
        node_pubkey.verify_xeddsa(&sign_data2, &signature2),
        "Signature 2 should verify with challenge 2"
    );

    // Cross-verification should fail (replay attack prevention)
    assert!(
        !node_pubkey.verify_xeddsa(&sign_data1, &signature2),
        "Signature 2 should NOT verify with challenge 1 data"
    );
    assert!(
        !node_pubkey.verify_xeddsa(&sign_data2, &signature1),
        "Signature 1 should NOT verify with challenge 2 data"
    );
}
