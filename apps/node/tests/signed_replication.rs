//! Integration tests for signed node-to-node replication
//!
//! Tests cryptographic identity and signature verification between nodes.

use node::{api, node_identity::NodeIdentity, replication, PersistentMailboxStore, PersistentStoreConfig};
use reme_identity::Identity;
use reme_message::OuterEnvelope;
use reme_transport::http_target::HttpTarget;
use reme_transport::pool::TransportPool;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::TcpListener;

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
/// Returns (url, handle) where url includes the dynamically assigned port
async fn start_test_node(
    identity: Option<Arc<NodeIdentity>>,
    peer_urls: Vec<String>,
    use_public_host: bool, // If true, sets public_host to the actual bound address
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind");
    let addr = listener.local_addr().expect("Failed to get local addr");
    let url = format!("http://{}", addr);
    let host = addr.to_string(); // "127.0.0.1:PORT"

    let config = PersistentStoreConfig {
        max_messages_per_mailbox: 1000,
        default_ttl_secs: 3600,
    };
    let store = Arc::new(
        PersistentMailboxStore::open(":memory:", config)
            .expect("Failed to create store"),
    );

    let node_id = identity
        .as_ref()
        .map(|i| i.node_id().to_string())
        .unwrap_or_else(|| "test-node".to_string());

    let replication = Arc::new(replication::ReplicationClient::with_identity(
        node_id,
        peer_urls,
        identity.clone(),
    ));

    // Set public_host to actual bound address if requested
    let public_host = if use_public_host { Some(host) } else { None };

    let state = Arc::new(api::AppState {
        store,
        replication,
        auth: None,
        submit_key_limiter: None,
        mqtt_bridge: None,
        identity,
        public_host,
        additional_hosts: vec![],
        require_outer_signature: false,
    });
    let app = api::router(state, None);

    let url_clone = url.clone();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("Server failed");
    });

    // Wait for server readiness with retry loop instead of fixed delay
    let health_url = format!("{}/api/v1/health", url_clone);
    let client = reqwest::Client::new();
    let mut server_ready = false;
    for _ in 0..50 {
        // 50 * 10ms = 500ms max wait
        if client.get(&health_url).send().await.is_ok() {
            server_ready = true;
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    assert!(
        server_ready,
        "Test server failed to start within 500ms at {}",
        url_clone
    );

    (url, handle)
}

/// Test that signed replication works between two nodes with identities
#[tokio::test]
async fn test_signed_replication_between_nodes() {
    // Create identities for both nodes
    let (identity1, _dir1) = create_temp_identity();
    let (identity2, _dir2) = create_temp_identity();

    // Start node 2 first to get its URL (with public_host for signature verification)
    let (url2, _handle2) = start_test_node(
        Some(Arc::new(identity2)),
        vec![], // No peers
        true,   // Use public_host
    )
    .await;

    // Start node 1 with node 2 as peer
    let (url1, _handle1) = start_test_node(
        Some(Arc::new(identity1)),
        vec![url2.clone()],
        true,   // Use public_host
    )
    .await;

    println!("Node 1: {}", url1);
    println!("Node 2: {}", url2);

    // Create transports
    let transport1 = TransportPool::<HttpTarget>::single(&url1).unwrap();
    let transport2 = TransportPool::<HttpTarget>::single(&url2).unwrap();

    // Create test envelope
    let identity = Identity::generate();
    let routing_key = identity.public_id().routing_key();
    let ephemeral_key = [42u8; 32];
    let test_envelope = OuterEnvelope::new(routing_key, Some(1), ephemeral_key, vec![1, 2, 3, 4]);

    // Send to node 1
    transport1
        .submit_message(test_envelope)
        .await
        .expect("submit_message to node1 failed");
    println!("Sent message to node 1");

    // Wait for replication
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Verify message arrived at node 2 via signed replication
    let messages = transport2
        .fetch_once(&routing_key)
        .await
        .expect("fetch_once from node2 failed");

    assert_eq!(messages.len(), 1, "Message should have replicated to node 2");
    assert_eq!(messages[0].inner_ciphertext, vec![1, 2, 3, 4]);
    println!("Message replicated to node 2 via signed replication: OK");

    println!("\n✓ Signed replication test passed!");
}

/// Test that unsigned (legacy) replication still works for backward compatibility
#[tokio::test]
async fn test_unsigned_replication_fallback() {
    // Start node 2 without identity (accepts unsigned requests)
    let (url2, _handle2) = start_test_node(
        None,    // No identity
        vec![],  // No peers
        false,   // No public_host (accepts any destination)
    )
    .await;

    // Start node 1 without identity
    let (url1, _handle1) = start_test_node(
        None,
        vec![url2.clone()],
        false,   // No public_host
    )
    .await;

    println!("Node 1 (unsigned): {}", url1);
    println!("Node 2 (unsigned): {}", url2);

    let transport1 = TransportPool::<HttpTarget>::single(&url1).unwrap();
    let transport2 = TransportPool::<HttpTarget>::single(&url2).unwrap();

    // Create test envelope
    let identity = Identity::generate();
    let routing_key = identity.public_id().routing_key();
    let ephemeral_key = [99u8; 32];
    let test_envelope = OuterEnvelope::new(routing_key, Some(1), ephemeral_key, vec![5, 6, 7, 8]);

    // Send to node 1
    transport1
        .submit_message(test_envelope)
        .await
        .expect("submit_message to node1 failed");
    println!("Sent message to node 1 (unsigned)");

    // Wait for replication
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Verify message arrived at node 2
    let messages = transport2
        .fetch_once(&routing_key)
        .await
        .expect("fetch_once from node2 failed");

    assert_eq!(messages.len(), 1, "Message should have replicated via unsigned replication");
    assert_eq!(messages[0].inner_ciphertext, vec![5, 6, 7, 8]);
    println!("Message replicated via legacy unsigned replication: OK");

    println!("\n✓ Unsigned replication fallback test passed!");
}

/// Test mixed cluster: signed node sends to unsigned node
#[tokio::test]
async fn test_mixed_cluster_replication() {
    let (identity1, _dir1) = create_temp_identity();

    // Node 2: unsigned (accepts all requests)
    let (url2, _handle2) = start_test_node(
        None,    // No identity
        vec![],
        false,   // No public_host (insecure mode)
    )
    .await;

    // Node 1: signed (sends signed requests)
    let (url1, _handle1) = start_test_node(
        Some(Arc::new(identity1)),
        vec![url2.clone()],
        true,    // Use public_host
    )
    .await;

    println!("Node 1 (signed): {}", url1);
    println!("Node 2 (unsigned): {}", url2);

    let transport1 = TransportPool::<HttpTarget>::single(&url1).unwrap();
    let transport2 = TransportPool::<HttpTarget>::single(&url2).unwrap();

    // Create test envelope
    let identity = Identity::generate();
    let routing_key = identity.public_id().routing_key();
    let ephemeral_key = [11u8; 32];
    let test_envelope = OuterEnvelope::new(routing_key, Some(1), ephemeral_key, vec![9, 10, 11, 12]);

    // Send to node 1 (signed)
    transport1
        .submit_message(test_envelope)
        .await
        .expect("submit_message to node1 failed");
    println!("Sent message to signed node 1");

    // Wait for replication
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Verify message arrived at unsigned node 2
    let messages = transport2
        .fetch_once(&routing_key)
        .await
        .expect("fetch_once from node2 failed");

    assert_eq!(messages.len(), 1, "Signed node should be able to replicate to unsigned node");
    assert_eq!(messages[0].inner_ciphertext, vec![9, 10, 11, 12]);
    println!("Signed node replicated to unsigned node: OK");

    println!("\n✓ Mixed cluster replication test passed!");
}

/// Test that node identity persists across restarts
#[tokio::test]
async fn test_node_identity_persistence() {
    let dir = tempdir().expect("Failed to create temp dir");
    let identity_path = dir.path().join("node-identity.key");

    // First load should generate new identity
    let identity1 = NodeIdentity::load_or_generate(&identity_path).expect("First load failed");
    let node_id1 = identity1.node_id().to_string();
    let pubkey1 = identity1.public_id().to_bytes();
    println!("Generated node ID: {}", node_id1);

    // Drop and reload - should have same identity
    drop(identity1);
    let identity2 = NodeIdentity::load_or_generate(&identity_path).expect("Second load failed");
    let node_id2 = identity2.node_id().to_string();
    let pubkey2 = identity2.public_id().to_bytes();

    assert_eq!(node_id1, node_id2, "Node ID should persist across restarts");
    assert_eq!(pubkey1, pubkey2, "Public key should persist across restarts");
    println!("Identity persisted correctly: {}", node_id2);

    println!("\n✓ Node identity persistence test passed!");
}
