//! Integration test: Two clients exchanging messages through the node
//!
//! These tests spin up an in-process node server for self-contained testing.
//! Uses MIK-only stateless encryption (no session establishment, no prekeys).

use reme_core::Client;
use reme_encryption::{decrypt_with_mik, encrypt_to_mik};
use reme_identity::Identity;
use reme_message::{
    Content, InnerEnvelope, MessageID, OuterEnvelope, TextContent, TombstoneStatus, CURRENT_VERSION,
};
use reme_outbox::{DeliveryState, OutboxConfig};
use reme_storage::Storage;
use reme_transport::http::HttpTransport;
use reme_transport::{MessageReceiver, ReceiverConfig, Transport, TransportEvent};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// Test server handle - keeps the server running while in scope
struct TestServer {
    url: String,
    _handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    /// Start a test server on a random available port
    async fn start() -> Self {
        use node::{api, persistent_store, replication};

        // Bind to port 0 to get a random available port
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind");
        let addr = listener.local_addr().expect("Failed to get local addr");
        let url = format!("http://{}", addr);

        // Create minimal node components (in-memory SQLite for testing)
        let config = persistent_store::PersistentStoreConfig {
            max_messages_per_mailbox: 1000,
            default_ttl_secs: 3600,
        };
        let store = Arc::new(persistent_store::PersistentMailboxStore::open(":memory:", config).unwrap());
        let replication = Arc::new(replication::ReplicationClient::new(
            "test-node".to_string(),
            vec![], // No peers for testing
        ));
        let state = Arc::new(api::AppState { store, replication, auth: None, submit_key_limiter: None, mqtt_bridge: None });
        let app = api::router(state, None);

        // Spawn server in background
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("Server failed");
        });

        // Small delay to ensure server is ready
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        TestServer { url, _handle: handle }
    }

    fn url(&self) -> &str {
        &self.url
    }
}

/// Test that the transport layer works correctly by sending raw encrypted data
#[tokio::test]
async fn test_transport_roundtrip() {
    let server = TestServer::start().await;
    let transport = HttpTransport::new(server.url());

    // Create a test identity
    let identity = Identity::generate();
    let routing_key = identity.public_id().routing_key();

    // Create and submit a test envelope with ephemeral key.
    // NOTE: This test validates transport mechanics only, not cryptographic properties.
    // Actual encryption/decryption is tested in test_e2e_encryption_mik_only.
    let ephemeral_key = [42u8; 32];
    let test_envelope = OuterEnvelope::new(routing_key, Some(1), ephemeral_key, vec![1, 2, 3, 4]); // 1 hour TTL
    transport
        .submit_message(test_envelope)
        .await
        .expect("submit_message failed");

    // Fetch messages (one-shot for testing)
    let messages = transport
        .fetch_once(&routing_key)
        .await
        .expect("fetch_once failed");

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].inner_ciphertext, vec![1, 2, 3, 4]);
    assert_eq!(messages[0].ephemeral_key, ephemeral_key);
    println!("Message roundtrip: OK");

    println!("✓ Transport roundtrip test passed!");
}

/// Test end-to-end encryption using MIK-only stateless encryption
#[tokio::test]
async fn test_e2e_encryption_mik_only() {
    let server = TestServer::start().await;
    let transport = Arc::new(HttpTransport::new(server.url()));

    // Create Alice and Bob identities
    let alice = Identity::generate();
    let bob = Identity::generate();

    println!("Alice ID: {}", hex::encode(alice.public_id().to_bytes()));
    println!("Bob ID: {}", hex::encode(bob.public_id().to_bytes()));

    // Bob's routing key
    let bob_routing_key = bob.public_id().routing_key();

    // Alice creates and encrypts a message to Bob's MIK (stateless)
    let message_id = MessageID::new();
    let mut inner = InnerEnvelope {
        from: *alice.public_id(),
        created_at_ms: 1234567890,
        content: Content::Text(TextContent {
            body: "Hello Bob! This is Alice.".to_string(),
        }),
        signature: None,
        prev_self: None,
        observed_heads: Vec::new(),
        epoch: 0,
        flags: 0,
    };

    // Sign the message with Alice's private key (including message_id in signable bytes)
    let signable = inner.signable_bytes(&message_id);
    inner.signature = Some(InnerEnvelope::sign(&signable, &alice.to_bytes()));

    // Encrypt to Bob's MIK (returns ephemeral_key and ciphertext)
    let (ephemeral_key, ciphertext) = encrypt_to_mik(&inner, bob.public_id(), &message_id)
        .expect("encrypt_to_mik failed");
    println!("Alice encrypted message to Bob's MIK");

    // Alice sends the message
    let outer = OuterEnvelope {
        version: CURRENT_VERSION,
        routing_key: bob_routing_key,
        timestamp_hours: reme_message::now_hours(),
        ttl_hours: Some(1), // 1 hour TTL
        message_id,
        ephemeral_key,
        inner_ciphertext: ciphertext,
    };

    transport
        .submit_message(outer)
        .await
        .expect("submit_message failed");
    println!("Alice sent encrypted message");

    // Bob fetches messages (one-shot for testing)
    let messages = transport
        .fetch_once(&bob_routing_key)
        .await
        .expect("fetch_once failed");

    assert_eq!(messages.len(), 1);
    println!("Bob fetched {} message(s)", messages.len());

    // Bob decrypts using his MIK private key (stateless)
    let bob_private = bob.to_bytes();
    let decrypted = decrypt_with_mik(
        &messages[0].ephemeral_key,
        &messages[0].inner_ciphertext,
        &bob_private,
        &messages[0].message_id,
    )
    .expect("decrypt_with_mik failed");

    // Verify sender signature (authentication) - must pass message_id for triple binding
    assert!(
        decrypted.verify_signature(&messages[0].message_id),
        "Sender signature verification failed"
    );
    println!("Bob verified Alice's signature: OK");

    match decrypted.content {
        Content::Text(t) => {
            assert_eq!(t.body, "Hello Bob! This is Alice.");
            println!("Bob decrypted message: \"{}\"", t.body);
        }
        _ => panic!("Expected text content"),
    }

    println!("\n✓ End-to-end MIK-only encryption test passed!");
}

/// Test two clients exchanging messages using the full Client API (MIK-only)
#[tokio::test]
async fn test_two_client_messaging() {
    let server = TestServer::start().await;
    let transport = Arc::new(HttpTransport::new(server.url()));

    // Create Alice's client (no prekey initialization needed!)
    let alice_identity = Identity::generate();
    let alice_storage = Storage::in_memory().unwrap();
    let alice = Client::new(alice_identity, transport.clone(), alice_storage);

    // Create Bob's client (no prekey initialization needed!)
    let bob_identity = Identity::generate();
    let bob_storage = Storage::in_memory().unwrap();
    let bob = Client::new(bob_identity, transport.clone(), bob_storage);

    println!("Alice ID: {}", hex::encode(alice.public_id().to_bytes()));
    println!("Bob ID: {}", hex::encode(bob.public_id().to_bytes()));

    // Alice adds Bob as a contact
    alice
        .add_contact(bob.public_id(), Some("Bob"))
        .expect("Alice add_contact failed");
    println!("Alice added Bob as contact");

    // Alice sends a message to Bob (no session establishment needed!)
    let msg_id = alice
        .send_text(bob.public_id(), "Hello Bob! This is Alice.")
        .await
        .expect("Alice send_text failed");
    println!("Alice sent message: {:?}", msg_id);

    // Bob receives messages using push-based MessageReceiver
    let receiver = MessageReceiver::new(transport.clone());
    let config = ReceiverConfig::with_poll_interval(Duration::from_millis(50));
    let (mut events, _handle) = receiver.subscribe(bob.routing_key(), config);

    // Wait for Bob's message
    let received = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(event) = events.recv().await {
            if let TransportEvent::Message(envelope) = event {
                return bob.process_message(&envelope).await.ok();
            }
        }
        None
    })
    .await
    .expect("Timeout waiting for message")
    .expect("No message received");

    assert_eq!(received.from, *alice.public_id());
    match &received.content {
        Content::Text(text) => {
            assert_eq!(text.body, "Hello Bob! This is Alice.");
            println!("Bob received: \"{}\"", text.body);
        }
        _ => panic!("Expected text message"),
    }

    // Bob replies to Alice (no session establishment needed!)
    // Note: Alice is auto-added as contact during process_message
    let reply_id = bob
        .send_text(alice.public_id(), "Hi Alice! Got your message.")
        .await
        .expect("Bob send_text failed");
    println!("Bob sent reply: {:?}", reply_id);

    // Alice receives messages using push-based MessageReceiver
    let (mut alice_events, _alice_handle) = receiver.subscribe(alice.routing_key(), config);

    // Wait for Alice's message
    let alice_received = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(event) = alice_events.recv().await {
            if let TransportEvent::Message(envelope) = event {
                return alice.process_message(&envelope).await.ok();
            }
        }
        None
    })
    .await
    .expect("Timeout waiting for reply")
    .expect("No reply received");

    assert_eq!(alice_received.from, *bob.public_id());
    match &alice_received.content {
        Content::Text(text) => {
            assert_eq!(text.body, "Hi Alice! Got your message.");
            println!("Alice received: \"{}\"", text.body);
        }
        _ => panic!("Expected text message"),
    }

    println!("\n✓ Two-client messaging test passed!");
}

/// Test tombstone flow: message → receive → tombstone acknowledgment
#[tokio::test]
#[ignore = "Tombstones temporarily disabled pending refactor"]
async fn test_tombstone_flow() {
    let server = TestServer::start().await;
    let transport = Arc::new(HttpTransport::new(server.url()));

    // Create Alice and Bob (no prekey initialization needed!)
    let alice_identity = Identity::generate();
    let alice_storage = Storage::in_memory().unwrap();
    let alice = Client::new(alice_identity, transport.clone(), alice_storage);

    let bob_identity = Identity::generate();
    let bob_storage = Storage::in_memory().unwrap();
    let bob = Client::new(bob_identity, transport.clone(), bob_storage);

    println!("Alice ID: {}", hex::encode(alice.public_id().to_bytes()));
    println!("Bob ID: {}", hex::encode(bob.public_id().to_bytes()));

    // Alice adds Bob as contact and sends a message
    alice
        .add_contact(bob.public_id(), Some("Bob"))
        .expect("Alice add_contact failed");

    let msg_id = alice
        .send_text(bob.public_id(), "Hello Bob!")
        .await
        .expect("Alice send_text failed");
    println!("Alice sent message: {:?}", msg_id);

    // Bob receives the message using push-based MessageReceiver
    let receiver = MessageReceiver::new(transport.clone());
    let config = ReceiverConfig::with_poll_interval(Duration::from_millis(50));
    let (mut events, _handle) = receiver.subscribe(bob.routing_key(), config);

    let received = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(event) = events.recv().await {
            if let TransportEvent::Message(envelope) = event {
                return bob.process_message(&envelope).await.ok();
            }
        }
        None
    })
    .await
    .expect("Timeout waiting for message")
    .expect("No message received");
    println!("Bob received message from Alice");

    // Bob sends a delivery tombstone
    bob.send_delivery_tombstone(&received)
        .await
        .expect("Bob send_delivery_tombstone failed");
    println!("Bob sent delivery tombstone for message {:?}", received.message_id);

    // Bob sends a read tombstone
    bob.send_read_tombstone(&received)
        .await
        .expect("Bob send_read_tombstone failed");
    println!("Bob sent read tombstone for message {:?}", received.message_id);

    println!("\n✓ Tombstone flow test passed!");
}

/// Test tombstone with different status options
#[tokio::test]
#[ignore = "Tombstones temporarily disabled pending refactor"]
async fn test_tombstone_with_status() {
    let server = TestServer::start().await;
    let transport = Arc::new(HttpTransport::new(server.url()));

    let identity = Identity::generate();
    let storage = Storage::in_memory().unwrap();
    let client = Client::new(identity, transport.clone(), storage);

    // Create a fake "received" message for testing tombstone creation
    let fake_received = reme_core::ReceivedMessage {
        message_id: MessageID::new(),
        from: *client.public_id(),
        content: Content::Text(TextContent {
            body: "Test message".to_string(),
        }),
        created_at_ms: 1234567890,
        content_id: [0u8; 8], // Dummy content_id for testing
        has_gaps: false,
        sender_state_reset: false,
        local_state_behind: false,
    };

    // Test each tombstone status
    client
        .send_tombstone(&fake_received, TombstoneStatus::Delivered)
        .await
        .expect("Delivered tombstone failed");
    println!("Sent Delivered tombstone");

    client
        .send_tombstone(&fake_received, TombstoneStatus::Read)
        .await
        .expect("Read tombstone failed");
    println!("Sent Read tombstone");

    client
        .send_tombstone(&fake_received, TombstoneStatus::Deleted)
        .await
        .expect("Deleted tombstone failed");
    println!("Sent Deleted tombstone");

    println!("\n✓ Tombstone status test passed!");
}

/// Test multi-node replication: messages sent to one node replicate to peers
#[tokio::test]
async fn test_multi_node_replication() {
    use node::{api, persistent_store, replication};

    // Start two nodes
    let listener1 = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind node1");
    let addr1 = listener1.local_addr().expect("Failed to get local addr");
    let url1 = format!("http://{}", addr1);

    let listener2 = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind node2");
    let addr2 = listener2.local_addr().expect("Failed to get local addr");
    let url2 = format!("http://{}", addr2);

    println!("Node 1: {}", url1);
    println!("Node 2: {}", url2);

    // Create store config for both nodes (in-memory SQLite for testing)
    let config = persistent_store::PersistentStoreConfig {
        max_messages_per_mailbox: 1000,
        default_ttl_secs: 3600,
    };

    // Create node 1 with node 2 as peer
    let store1 = Arc::new(persistent_store::PersistentMailboxStore::open(":memory:", config.clone()).unwrap());
    let replication1 = Arc::new(replication::ReplicationClient::new(
        "node-1".to_string(),
        vec![url2.clone()],
    ));
    let state1 = Arc::new(api::AppState { store: store1, replication: replication1, auth: None, submit_key_limiter: None, mqtt_bridge: None });
    let app1 = api::router(state1, None);

    // Create node 2 with node 1 as peer
    let store2 = Arc::new(persistent_store::PersistentMailboxStore::open(":memory:", config).unwrap());
    let replication2 = Arc::new(replication::ReplicationClient::new(
        "node-2".to_string(),
        vec![url1.clone()],
    ));
    let state2 = Arc::new(api::AppState { store: store2, replication: replication2, auth: None, submit_key_limiter: None, mqtt_bridge: None });
    let app2 = api::router(state2, None);

    // Spawn both servers
    let _handle1 = tokio::spawn(async move {
        axum::serve(listener1, app1).await.expect("Server 1 failed");
    });
    let _handle2 = tokio::spawn(async move {
        axum::serve(listener2, app2).await.expect("Server 2 failed");
    });

    // Wait for servers to be ready
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Create transports for both nodes
    let transport1 = HttpTransport::new(&url1);
    let transport2 = HttpTransport::new(&url2);

    // Create a test identity
    let identity = Identity::generate();
    let routing_key = identity.public_id().routing_key();

    // Send a message to node 1.
    // NOTE: Using fake ephemeral key - this test validates replication, not crypto.
    let ephemeral_key = [99u8; 32];
    let test_envelope = OuterEnvelope::new(routing_key, Some(1), ephemeral_key, vec![42, 43, 44, 45]);
    transport1
        .submit_message(test_envelope)
        .await
        .expect("submit_message to node1 failed");
    println!("Sent message to node 1");

    // Wait for replication
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Fetch message from node 2 (one-shot for testing)
    let messages_from_node2 = transport2
        .fetch_once(&routing_key)
        .await
        .expect("fetch_once from node2 failed");
    assert_eq!(messages_from_node2.len(), 1);
    assert_eq!(messages_from_node2[0].inner_ciphertext, vec![42, 43, 44, 45]);
    assert_eq!(messages_from_node2[0].ephemeral_key, ephemeral_key);
    println!("Message replicated to node 2: OK");

    println!("\n✓ Multi-node replication test passed!");
}

/// Test that tombstone sequence numbers are monotonically increasing
#[tokio::test]
#[ignore = "Tombstones temporarily disabled pending refactor"]
async fn test_tombstone_sequence() {
    let server = TestServer::start().await;
    let transport = Arc::new(HttpTransport::new(server.url()));

    let identity = Identity::generate();
    let storage = Storage::in_memory().unwrap();
    let client = Client::new(identity, transport.clone(), storage);

    // Check initial sequence
    let initial_seq = client.tombstone_sequence();
    assert!(initial_seq >= 1, "Sequence should start at 1 or higher");
    println!("Initial sequence: {}", initial_seq);

    // Create fake message
    let fake_received = reme_core::ReceivedMessage {
        message_id: MessageID::new(),
        from: *client.public_id(),
        content: Content::Text(TextContent {
            body: "Test".to_string(),
        }),
        created_at_ms: 1234567890,
        content_id: [0u8; 8], // Dummy content_id for testing
        has_gaps: false,
        sender_state_reset: false,
        local_state_behind: false,
    };

    // Send multiple tombstones
    for i in 0..3 {
        client
            .send_delivery_tombstone(&fake_received)
            .await
            .expect("tombstone failed");
        let seq = client.tombstone_sequence();
        println!("After tombstone {}: sequence = {}", i + 1, seq);
        assert_eq!(seq, initial_seq + i as u64 + 1, "Sequence should increment");
    }

    println!("\n✓ Tombstone sequence test passed!");
}

// ============================================
// Outbox Integration Tests
// ============================================

/// Test that sending a message queues it in the outbox
#[tokio::test]
async fn test_outbox_message_queuing() {
    let server = TestServer::start().await;
    let transport = Arc::new(HttpTransport::new(server.url()));

    let alice_identity = Identity::generate();
    let alice_storage = Storage::in_memory().unwrap();
    let alice = Client::new(alice_identity, transport.clone(), alice_storage);

    let bob_identity = Identity::generate();

    // Alice adds Bob as contact
    alice
        .add_contact(bob_identity.public_id(), Some("Bob"))
        .expect("Alice add_contact failed");

    // Check outbox is empty
    let pending_before = alice.get_pending_messages().expect("get_pending failed");
    assert_eq!(pending_before.len(), 0);

    // Alice sends a message
    let _msg_id = alice
        .send_text(bob_identity.public_id(), "Hello Bob!")
        .await
        .expect("Alice send_text failed");

    // Check that message is tracked in outbox (should be InFlight or Pending after successful send)
    let pending_for_bob = alice
        .get_pending_for(bob_identity.public_id())
        .expect("get_pending_for failed");

    // After successful send, the message should have an attempt recorded
    // It will be in InFlight state briefly, then AwaitingRetry (waiting for DAG confirmation)
    assert_eq!(pending_for_bob.len(), 1);
    println!("Message queued in outbox for Bob: {:?}", pending_for_bob[0].content_id);

    println!("\n✓ Outbox message queuing test passed!");
}

/// Test DAG-based delivery confirmation: Bob's reply confirms Alice's message
#[tokio::test]
async fn test_outbox_dag_confirmation() {
    let server = TestServer::start().await;
    let transport = Arc::new(HttpTransport::new(server.url()));

    // Create Alice
    let alice_identity = Identity::generate();
    let alice_storage = Storage::in_memory().unwrap();
    let alice = Client::new(alice_identity, transport.clone(), alice_storage);

    // Create Bob
    let bob_identity = Identity::generate();
    let bob_storage = Storage::in_memory().unwrap();
    let bob = Client::new(bob_identity, transport.clone(), bob_storage);

    // Alice adds Bob as contact
    alice
        .add_contact(bob.public_id(), Some("Bob"))
        .expect("Alice add_contact failed");

    // Alice sends a message to Bob
    let _msg_id = alice
        .send_text(bob.public_id(), "Hello Bob!")
        .await
        .expect("Alice send_text failed");

    // Get Alice's pending message
    let alice_pending = alice
        .get_pending_for(bob.public_id())
        .expect("get_pending_for failed");
    assert_eq!(alice_pending.len(), 1);
    let alice_entry_id = alice_pending[0].id;
    println!("Alice's message is pending, entry_id: {}", alice_entry_id);

    // Bob receives the message using push-based MessageReceiver
    let receiver = MessageReceiver::new(transport.clone());
    let config = ReceiverConfig::with_poll_interval(Duration::from_millis(50));
    let (mut events, _handle) = receiver.subscribe(bob.routing_key(), config);

    let _received = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(event) = events.recv().await {
            if let TransportEvent::Message(envelope) = event {
                return bob.process_message(&envelope).await.ok();
            }
        }
        None
    })
    .await
    .expect("Timeout waiting for message")
    .expect("No message received");
    println!("Bob received Alice's message");

    // Bob replies to Alice (this will include observed_heads with Alice's content_id)
    let _reply_id = bob
        .send_text(alice.public_id(), "Hi Alice!")
        .await
        .expect("Bob send_text failed");
    println!("Bob sent reply to Alice");

    // Alice receives Bob's reply
    let (mut alice_events, _alice_handle) = receiver.subscribe(alice.routing_key(), config);

    let _alice_received = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(event) = alice_events.recv().await {
            if let TransportEvent::Message(envelope) = event {
                return alice.process_message(&envelope).await.ok();
            }
        }
        None
    })
    .await
    .expect("Timeout waiting for reply")
    .expect("No reply received");
    println!("Alice received Bob's reply");

    // Check that Alice's original message is now confirmed via DAG
    let alice_state = alice
        .get_delivery_state(alice_entry_id)
        .expect("get_delivery_state failed")
        .expect("entry not found");

    assert_eq!(
        alice_state,
        DeliveryState::Confirmed,
        "Alice's message should be confirmed after Bob's reply with observed_heads"
    );
    println!("Alice's message confirmed via DAG acknowledgment");

    println!("\n✓ Outbox DAG confirmation test passed!");
}

/// Test that outbox cleanup removes old confirmed entries
#[tokio::test]
async fn test_outbox_cleanup() {
    let server = TestServer::start().await;
    let transport = Arc::new(HttpTransport::new(server.url()));

    // Use custom config with cleanup_after_ms: 0 so cleanup happens immediately
    let alice_config = OutboxConfig {
        cleanup_after_ms: 0,
        ..OutboxConfig::default()
    };

    let alice_identity = Identity::generate();
    let alice_storage = Storage::in_memory().unwrap();
    let alice = Client::with_config(alice_identity, transport.clone(), alice_storage, alice_config);

    // Bob uses default config
    let bob_identity = Identity::generate();
    let bob_storage = Storage::in_memory().unwrap();
    let bob = Client::new(bob_identity, transport.clone(), bob_storage);

    // Both add each other as contacts
    alice
        .add_contact(bob.public_id(), Some("Bob"))
        .expect("Alice add_contact failed");
    bob.add_contact(alice.public_id(), Some("Alice"))
        .expect("Bob add_contact failed");

    alice
        .send_text(bob.public_id(), "Test message")
        .await
        .expect("Alice send_text failed");

    // Get entry_id to track state
    let alice_pending = alice
        .get_pending_for(bob.public_id())
        .expect("get_pending_for failed");
    assert_eq!(alice_pending.len(), 1);
    let entry_id = alice_pending[0].id;
    println!("Alice's message is pending, entry_id: {}", entry_id);

    // Bob receives and replies (confirms Alice's message)
    let receiver = MessageReceiver::new(transport.clone());
    let config = ReceiverConfig::with_poll_interval(Duration::from_millis(50));
    let (mut events, _handle) = receiver.subscribe(bob.routing_key(), config);

    let _bob_received = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(event) = events.recv().await {
            if let TransportEvent::Message(envelope) = event {
                return bob.process_message(&envelope).await.ok();
            }
        }
        None
    })
    .await
    .expect("Timeout waiting for Bob to receive")
    .expect("Bob didn't receive message");
    println!("Bob received Alice's message");

    // Bob replies (this will include observed_heads with Alice's content_id)
    bob.send_text(alice.public_id(), "Got it!")
        .await
        .expect("Bob reply failed");
    println!("Bob sent reply to Alice");

    // Alice receives reply (triggers confirmation via DAG)
    let (mut alice_events, _alice_handle) = receiver.subscribe(alice.routing_key(), config);
    let _alice_received = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(event) = alice_events.recv().await {
            if let TransportEvent::Message(envelope) = event {
                return alice.process_message(&envelope).await.ok();
            }
        }
        None
    })
    .await
    .expect("Timeout waiting for Alice to receive reply")
    .expect("Alice didn't receive reply");
    println!("Alice received Bob's reply");

    // Verify message is confirmed before cleanup
    let state = alice
        .get_delivery_state(entry_id)
        .expect("get_delivery_state failed")
        .expect("entry not found");
    assert_eq!(state, DeliveryState::Confirmed, "Message should be confirmed via DAG");
    println!("Message confirmed, entry_id: {}", entry_id);

    // Cleanup should remove confirmed entries (cleanup_after_ms=0 means immediate cleanup)
    let cleaned = alice.outbox_cleanup().expect("cleanup failed");
    println!("Cleaned {} old confirmed entries", cleaned);
    assert_eq!(cleaned, 1, "Should have cleaned exactly 1 confirmed entry");

    println!("\n✓ Outbox cleanup test passed!");
}

/// Test that retry mechanism works for pending messages
#[tokio::test]
async fn test_outbox_retry_mechanism() {
    let server = TestServer::start().await;
    let transport = Arc::new(HttpTransport::new(server.url()));

    let alice_identity = Identity::generate();
    let alice_storage = Storage::in_memory().unwrap();
    let alice = Client::new(alice_identity, transport.clone(), alice_storage);

    let bob_identity = Identity::generate();

    // Alice adds Bob as contact
    alice
        .add_contact(bob_identity.public_id(), Some("Bob"))
        .expect("Alice add_contact failed");

    // Alice sends a message
    let _msg_id = alice
        .send_text(bob_identity.public_id(), "Hello Bob!")
        .await
        .expect("Alice send_text failed");

    // Get pending messages - should have one
    let pending = alice.get_pending_messages().expect("get_pending failed");
    assert_eq!(pending.len(), 1);
    let entry_id = pending[0].id;
    println!("Message is pending with entry_id: {}", entry_id);

    // Verify the message state after send (should have at least one attempt)
    assert!(!pending[0].attempts.is_empty(), "Should have recorded an attempt");
    println!("Message has {} attempts", pending[0].attempts.len());

    // Schedule immediate retry for this entry
    alice
        .schedule_retry(entry_id)
        .expect("schedule_retry failed");
    println!("Scheduled immediate retry for entry {}", entry_id);

    // Get messages due for retry
    let due_for_retry = alice.get_ready_for_retry().expect("get_due failed");
    assert!(
        due_for_retry.iter().any(|m| m.id == entry_id),
        "Entry should be due for retry after scheduling"
    );
    println!("Entry is due for retry");

    // Attempt delivery again using attempt_delivery
    let result = alice
        .attempt_delivery(entry_id)
        .await
        .expect("attempt_delivery failed");
    println!("Retry attempt result: {:?}", result);

    // Should have recorded another attempt
    let updated = alice
        .get_pending_for(bob_identity.public_id())
        .expect("get_pending_for failed");
    assert_eq!(updated.len(), 1);
    assert!(
        updated[0].attempts.len() >= 2,
        "Should have at least 2 attempts after retry"
    );
    println!("Message now has {} attempts", updated[0].attempts.len());

    println!("\n✓ Outbox retry mechanism test passed!");
}
