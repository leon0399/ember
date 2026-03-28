//! Integration tests for `ack_secret` receipt on submit
//!
//! Tests that nodes return cryptographic receipts proving they can decrypt messages.

use base64::prelude::*;
use node::{
    api, node_identity::NodeIdentity, replication, PersistentMailboxStore, PersistentStoreConfig,
};
use reme_encryption::{derive_ack_hash, encrypt_to_mik, RECEIPT_DOMAIN_SEP};
use reme_identity::Identity;
use reme_message::{Content, InnerEnvelope, MessageID, OuterEnvelope, TextContent};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use tokio::net::TcpListener;

/// Response from /api/v1/submit (batch format)
#[derive(Debug, Deserialize)]
struct SubmitResponse {
    results: Vec<FrameResult>,
}

#[derive(Debug, Deserialize)]
struct FrameResult {
    status: String,
    ack_secret: Option<String>,
    signature: Option<String>,
    #[allow(dead_code)]
    error: Option<String>,
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
async fn submit_envelope(url: &str, envelope: OuterEnvelope) -> FrameResult {
    let client = reqwest::Client::new();
    let wire_payload = reme_message::WirePayload::Message(envelope);
    let wire_bytes = wire_payload.encode().unwrap();
    let bundle_body = reme_bundle::encode_body(&[&wire_bytes]);

    let response = client
        .post(format!("{url}/api/v1/submit"))
        .header("Content-Type", "application/vnd.reme.bundle")
        .body(bundle_body)
        .send()
        .await
        .expect("Submit request failed");

    assert!(response.status().is_success(), "Submit should succeed");
    let submit_response: SubmitResponse = response.json().await.expect("Failed to parse response");
    assert_eq!(
        submit_response.results.len(),
        1,
        "Single submit should return 1 result"
    );
    submit_response.results.into_iter().next().unwrap()
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
        "Node should return signature when it's the recipient"
    );

    // Verify signature over domain-separated message
    let signature_b64 = response.signature.unwrap();
    let signature: [u8; 64] = BASE64_STANDARD
        .decode(&signature_b64)
        .expect("Invalid signature base64")
        .try_into()
        .expect("Wrong signature length");

    // Reconstruct signed message with domain separation
    // Format: "reme-receipt-v1:" || signer_pubkey || message_id (NO ack_secret)
    let mut sign_data = Vec::with_capacity(RECEIPT_DOMAIN_SEP.len() + 32 + 16);
    sign_data.extend_from_slice(RECEIPT_DOMAIN_SEP);
    sign_data.extend_from_slice(&node_pubkey.to_bytes());
    sign_data.extend_from_slice(message_id.as_bytes());

    // Verify using node's public key
    assert!(
        node_pubkey.verify_xeddsa(&sign_data, &signature),
        "Signature should verify with node's public key"
    );

    println!("Node correctly returned signed receipt as intended recipient");
}

/// Test: Node is a relay (different `routing_key`) → returns signature but no `ack_secret`
#[tokio::test]
async fn test_relay_returns_signature_but_no_ack_secret() {
    // Create node identity
    let (node_identity, _dir) = create_temp_identity();
    let node_pubkey = *node_identity.public_id();

    // Start node with this identity
    let (url, _handle) = start_test_node(Some(Arc::new(node_identity))).await;

    // Create sender and DIFFERENT recipient (not the node)
    let sender = Identity::generate();
    let different_recipient = Identity::generate();
    let (envelope, _) = create_encrypted_envelope(&sender, different_recipient.public_id());
    let message_id = envelope.message_id;

    // Submit to node (node is acting as relay)
    let response = submit_envelope(&url, envelope).await;

    // Should NOT have ack_secret (node cannot decrypt - different routing key)
    assert_eq!(response.status, "ok");
    assert!(
        response.ack_secret.is_none(),
        "Node should NOT return ack_secret when it's just a relay"
    );

    // Should still have signature (proves node received the message)
    assert!(
        response.signature.is_some(),
        "Node should return signature even as relay"
    );

    // Verify signature
    let signature_b64 = response.signature.unwrap();
    let signature: [u8; 64] = BASE64_STANDARD
        .decode(&signature_b64)
        .expect("Invalid signature base64")
        .try_into()
        .expect("Wrong signature length");

    // Format: "reme-receipt-v1:" || signer_pubkey || message_id (NO ack_secret)
    let mut sign_data = Vec::with_capacity(RECEIPT_DOMAIN_SEP.len() + 32 + 16);
    sign_data.extend_from_slice(RECEIPT_DOMAIN_SEP);
    sign_data.extend_from_slice(&node_pubkey.to_bytes());
    sign_data.extend_from_slice(message_id.as_bytes());

    assert!(
        node_pubkey.verify_xeddsa(&sign_data, &signature),
        "Signature should verify with node's public key"
    );

    println!("Node correctly returned signature-only receipt as relay");
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

/// Test: Malformed ephemeral key (low-order point) → returns signature but no `ack_secret`
#[tokio::test]
async fn test_low_order_ephemeral_key_returns_signature_but_no_ack_secret() {
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
    let message_id = envelope.message_id;

    // Submit to node
    let response = submit_envelope(&url, envelope).await;

    // Should accept the message (node stores it) but NOT return ack_secret
    // (ECDH with low-order point would produce weak/predictable shared secret)
    assert_eq!(response.status, "ok");
    assert!(
        response.ack_secret.is_none(),
        "Low-order ephemeral key should NOT produce ack_secret"
    );

    // Should still return signature (signature doesn't depend on ack_secret)
    assert!(
        response.signature.is_some(),
        "Should still return signature even with low-order ephemeral key"
    );

    // Verify signature
    let signature_b64 = response.signature.unwrap();
    let signature: [u8; 64] = BASE64_STANDARD
        .decode(&signature_b64)
        .expect("Invalid signature base64")
        .try_into()
        .expect("Wrong signature length");

    // Format: "reme-receipt-v1:" || signer_pubkey || message_id (NO ack_secret)
    let mut sign_data = Vec::with_capacity(RECEIPT_DOMAIN_SEP.len() + 32 + 16);
    sign_data.extend_from_slice(RECEIPT_DOMAIN_SEP);
    sign_data.extend_from_slice(&node_pubkey.to_bytes());
    sign_data.extend_from_slice(message_id.as_bytes());

    assert!(
        node_pubkey.verify_xeddsa(&sign_data, &signature),
        "Signature should verify with node's public key"
    );

    println!("Low-order ephemeral key correctly returned signature-only receipt");
}

/// Test: Batch submit with multiple messages returns per-frame results
#[tokio::test]
async fn test_batch_submit_multiple_messages() {
    // Create node identity (this will be the recipient)
    let (node_identity, _dir) = create_temp_identity();
    let node_pubkey = *node_identity.public_id();

    // Start node with this identity
    let (url, _handle) = start_test_node(Some(Arc::new(node_identity))).await;

    // Create 3 different senders and encrypt messages TO the node
    let sender1 = Identity::generate();
    let sender2 = Identity::generate();
    let sender3 = Identity::generate();

    let (envelope1, _) = create_encrypted_envelope(&sender1, &node_pubkey);
    let (envelope2, _) = create_encrypted_envelope(&sender2, &node_pubkey);
    let (envelope3, _) = create_encrypted_envelope(&sender3, &node_pubkey);

    // Encode all 3 as a single bundle
    let wire1 = reme_message::WirePayload::Message(envelope1.clone())
        .encode()
        .unwrap();
    let wire2 = reme_message::WirePayload::Message(envelope2.clone())
        .encode()
        .unwrap();
    let wire3 = reme_message::WirePayload::Message(envelope3.clone())
        .encode()
        .unwrap();

    let bundle_body = reme_bundle::encode_body(&[&wire1, &wire2, &wire3]);

    // Submit batch
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{url}/api/v1/submit"))
        .header("Content-Type", "application/vnd.reme.bundle")
        .body(bundle_body)
        .send()
        .await
        .expect("Batch submit request failed");

    assert!(
        response.status().is_success(),
        "Batch submit should succeed"
    );
    let submit_response: SubmitResponse = response.json().await.expect("Failed to parse response");

    // Should have 3 results, all status: "ok"
    assert_eq!(
        submit_response.results.len(),
        3,
        "Batch submit should return 3 results"
    );
    for (i, result) in submit_response.results.iter().enumerate() {
        assert_eq!(result.status, "ok", "Result {i} should be ok");
        assert!(
            result.ack_secret.is_some(),
            "Result {i} should have ack_secret (node is recipient)"
        );
        assert!(
            result.signature.is_some(),
            "Result {i} should have signature"
        );
    }

    // Verify all 3 messages are fetchable
    let transport =
        reme_transport::pool::TransportPool::<reme_transport::http_target::HttpTarget>::single(
            &url,
        )
        .unwrap();
    let messages = transport
        .fetch_once(&node_pubkey.routing_key())
        .await
        .expect("fetch_once failed");
    assert_eq!(
        messages.len(),
        3,
        "All 3 messages should be stored and fetchable"
    );

    println!("Batch submit of 3 messages succeeded with correct per-frame results");
}
