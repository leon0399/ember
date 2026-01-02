//! Integration tests for `ack_secret` receipt on submit
//!
//! Tests that nodes return cryptographic receipts proving they can decrypt messages.

use base64::prelude::*;
use node::{
    api, node_identity::NodeIdentity, replication, PersistentMailboxStore, PersistentStoreConfig,
};
use reme_encryption::{derive_ack_hash, encrypt_to_mik};
use reme_identity::Identity;
use reme_message::{Content, InnerEnvelope, MessageID, OuterEnvelope, TextContent};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use tokio::net::TcpListener;

/// Response from /api/v1/submit
#[derive(Debug, Deserialize)]
struct SubmitResponse {
    status: String,
    ack_secret: Option<String>,
    signature: Option<String>,
}

/// Create an identity and save it to a temp file
fn create_temp_identity() -> (NodeIdentity, tempfile::TempDir) {
    let dir = tempdir().expect("Failed to create temp dir");
    let path = dir.path().join("node-identity.key");
    let identity = Identity::generate();
    std::fs::write(&path, identity.to_bytes()).expect("Failed to write identity");
    let node_identity = NodeIdentity::load_or_generate(&path).expect("Failed to load identity");
    (node_identity, dir)
}

/// Start a test node with optional signing identity
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

/// Create a properly encrypted envelope destined for the given recipient
#[allow(clippy::cast_possible_truncation)] // Test helper, ms since epoch fits in u64
fn create_encrypted_envelope(
    sender: &Identity,
    recipient_pubkey: &reme_identity::PublicID,
) -> (OuterEnvelope, [u8; 16]) {
    // Create inner envelope
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let inner = InnerEnvelope {
        from: *sender.public_id(),
        created_at_ms: now_ms,
        content: Content::Text(TextContent {
            body: "test message".to_string(),
        }),
        prev_self: None,
        observed_heads: vec![],
        epoch: 0,
        flags: 0,
    };

    // Create message ID
    let message_id = MessageID::new();

    // Encrypt to recipient
    let enc_output = encrypt_to_mik(&inner, recipient_pubkey, &message_id, &sender.to_bytes())
        .expect("Encryption failed");

    // Create outer envelope with the message_id
    let mut envelope = OuterEnvelope::new(
        recipient_pubkey.routing_key(),
        Some(1),
        enc_output.ephemeral_public,
        enc_output.ack_hash,
        enc_output.ciphertext,
    );
    envelope.message_id = message_id;

    (envelope, enc_output.ack_secret)
}

/// Submit envelope to node and parse response
async fn submit_envelope(url: &str, envelope: OuterEnvelope) -> SubmitResponse {
    let client = reqwest::Client::new();
    let wire_payload = reme_message::WirePayload::Message(envelope);
    let body = BASE64_STANDARD.encode(wire_payload.encode());

    let response = client
        .post(format!("{url}/api/v1/submit"))
        .body(body)
        .send()
        .await
        .expect("Submit request failed");

    assert!(response.status().is_success(), "Submit should succeed");
    response.json().await.expect("Failed to parse response")
}

/// Test: Node is the intended recipient → returns valid `ack_secret`
#[tokio::test]
async fn test_recipient_returns_ack_secret() {
    // Create node identity (this will be the recipient)
    let (node_identity, _dir) = create_temp_identity();
    let node_pubkey = *node_identity.public_id();

    // Start node with this identity
    let (url, _handle) = start_test_node(Some(Arc::new(node_identity))).await;

    // Create sender and encrypt message TO the node
    let sender = Identity::generate();
    let (envelope, expected_ack_secret) = create_encrypted_envelope(&sender, &node_pubkey);
    let ack_hash = envelope.ack_hash;
    let message_id = envelope.message_id;

    // Submit to node
    let response = submit_envelope(&url, envelope).await;

    // Should have ack_secret
    assert_eq!(response.status, "ok");
    assert!(
        response.ack_secret.is_some(),
        "Node should return ack_secret when it's the recipient"
    );

    // Verify ack_secret is correct
    let returned_ack_secret_b64 = response.ack_secret.unwrap();
    let returned_ack_secret: [u8; 16] = BASE64_STANDARD
        .decode(&returned_ack_secret_b64)
        .expect("Invalid base64")
        .try_into()
        .expect("Wrong length");

    assert_eq!(
        returned_ack_secret, expected_ack_secret,
        "Returned ack_secret should match expected"
    );

    // Double-check: hash(ack_secret) should equal ack_hash
    let computed_ack_hash = derive_ack_hash(&returned_ack_secret);
    assert_eq!(
        computed_ack_hash, ack_hash,
        "hash(ack_secret) should equal ack_hash"
    );

    // Should also have signature
    assert!(
        response.signature.is_some(),
        "Node should return signature when it returns ack_secret"
    );

    // Verify signature over domain-separated message
    let signature_b64 = response.signature.unwrap();
    let signature: [u8; 64] = BASE64_STANDARD
        .decode(&signature_b64)
        .expect("Invalid signature base64")
        .try_into()
        .expect("Wrong signature length");

    // Reconstruct signed message with domain separation
    // Format: "reme-receipt-v1:" || signer_pubkey || message_id || ack_secret
    const DOMAIN_SEP: &[u8] = b"reme-receipt-v1:";
    let mut sign_data = Vec::with_capacity(DOMAIN_SEP.len() + 32 + 16 + 16);
    sign_data.extend_from_slice(DOMAIN_SEP);
    sign_data.extend_from_slice(&node_pubkey.to_bytes());
    sign_data.extend_from_slice(message_id.as_bytes());
    sign_data.extend_from_slice(&returned_ack_secret);

    // Verify using node's public key
    assert!(
        node_pubkey.verify_xeddsa(&sign_data, &signature),
        "Signature should verify with node's public key"
    );

    println!("Node correctly returned signed receipt as intended recipient");
}

/// Test: Node is a relay (different `routing_key`) → returns null
#[tokio::test]
async fn test_relay_returns_no_ack_secret() {
    // Create node identity
    let (node_identity, _dir) = create_temp_identity();

    // Start node with this identity
    let (url, _handle) = start_test_node(Some(Arc::new(node_identity))).await;

    // Create sender and DIFFERENT recipient (not the node)
    let sender = Identity::generate();
    let different_recipient = Identity::generate();
    let (envelope, _) = create_encrypted_envelope(&sender, different_recipient.public_id());

    // Submit to node (node is acting as relay)
    let response = submit_envelope(&url, envelope).await;

    // Should NOT have ack_secret or signature (node is not the recipient)
    assert_eq!(response.status, "ok");
    assert!(
        response.ack_secret.is_none(),
        "Node should NOT return ack_secret when it's just a relay"
    );
    assert!(
        response.signature.is_none(),
        "Node should NOT return signature when it's just a relay"
    );

    println!("Node correctly returned no receipt as relay");
}

/// Test: Node without identity → returns null
#[tokio::test]
async fn test_no_identity_returns_no_ack_secret() {
    // Start node WITHOUT identity
    let (url, _handle) = start_test_node(None).await;

    // Create any envelope
    let sender = Identity::generate();
    let recipient = Identity::generate();
    let (envelope, _) = create_encrypted_envelope(&sender, recipient.public_id());

    // Submit to node
    let response = submit_envelope(&url, envelope).await;

    // Should NOT have ack_secret or signature (node has no identity)
    assert_eq!(response.status, "ok");
    assert!(
        response.ack_secret.is_none(),
        "Node without identity should NOT return ack_secret"
    );
    assert!(
        response.signature.is_none(),
        "Node without identity should NOT return signature"
    );

    println!("Node without identity correctly returned no receipt");
}

/// Test: Duplicate message submission also returns no `ack_secret` (idempotent)
#[tokio::test]
async fn test_duplicate_returns_no_ack_secret() {
    // Create node identity (this will be the recipient)
    let (node_identity, _dir) = create_temp_identity();
    let node_pubkey = *node_identity.public_id();

    // Start node with this identity
    let (url, _handle) = start_test_node(Some(Arc::new(node_identity))).await;

    // Create sender and encrypt message TO the node
    let sender = Identity::generate();
    let (envelope, _) = create_encrypted_envelope(&sender, &node_pubkey);

    // First submission - should have ack_secret and signature
    let response1 = submit_envelope(&url, envelope.clone()).await;
    assert_eq!(response1.status, "ok");
    assert!(
        response1.ack_secret.is_some(),
        "First submit should return ack_secret"
    );
    assert!(
        response1.signature.is_some(),
        "First submit should return signature"
    );

    // Second submission (duplicate) - should NOT have ack_secret or signature
    let response2 = submit_envelope(&url, envelope).await;
    assert_eq!(response2.status, "ok");
    assert!(
        response2.ack_secret.is_none(),
        "Duplicate submit should NOT return ack_secret"
    );
    assert!(
        response2.signature.is_none(),
        "Duplicate submit should NOT return signature"
    );

    println!("Duplicate submission correctly returned no receipt");
}

/// Test: Malformed ephemeral key (low-order point) → returns no `ack_secret`
#[tokio::test]
async fn test_low_order_ephemeral_key_returns_no_ack_secret() {
    // Create node identity (this will be the recipient)
    let (node_identity, _dir) = create_temp_identity();
    let node_pubkey = *node_identity.public_id();

    // Start node with this identity
    let (url, _handle) = start_test_node(Some(Arc::new(node_identity))).await;

    // Create an envelope with a low-order ephemeral key (attack attempt)
    // This is one of the 12 low-order points on Curve25519
    let low_order_ephemeral_key = [0u8; 32]; // All zeros is a low-order point

    let mut envelope = OuterEnvelope::new(
        node_pubkey.routing_key(),
        Some(1),
        low_order_ephemeral_key,
        [0u8; 16],        // dummy ack_hash
        vec![1, 2, 3, 4], // dummy ciphertext
    );
    envelope.message_id = MessageID::new();

    // Submit to node
    let response = submit_envelope(&url, envelope).await;

    // Should accept the message (node stores it) but NOT return ack_secret or signature
    // (ECDH with low-order point would produce weak/predictable shared secret)
    assert_eq!(response.status, "ok");
    assert!(
        response.ack_secret.is_none(),
        "Low-order ephemeral key should NOT produce ack_secret"
    );
    assert!(
        response.signature.is_none(),
        "Low-order ephemeral key should NOT produce signature"
    );

    println!("Low-order ephemeral key correctly returned no receipt");
}
