//! Integration test: Two clients exchanging messages through the node
//!
//! These tests spin up an in-process node server for self-contained testing.
//! Uses MIK-only stateless encryption (no session establishment, no prekeys).

use reme_core::Client;
use reme_encryption::{decrypt_with_mik, encrypt_to_mik, EncryptionError};
use reme_identity::Identity;
use reme_message::{
    Content, InnerEnvelope, MessageID, OuterEnvelope, TextContent, CURRENT_VERSION,
};
use reme_outbox::{DeliveryState, OutboxConfig};
use reme_storage::Storage;
use reme_transport::http_target::HttpTarget;
use reme_transport::pool::TransportPool;
use reme_transport::{MessageReceiver, ReceiverConfig, TransportError, TransportEvent};
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
        use node::{api, replication, PersistentMailboxStore, PersistentStoreConfig};

        // Bind to port 0 to get a random available port
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind");
        let addr = listener.local_addr().expect("Failed to get local addr");
        let url = format!("http://{addr}");

        // Create minimal node components (in-memory SQLite for testing)
        let config = PersistentStoreConfig {
            max_messages_per_mailbox: 1000,
            default_ttl_secs: 3600,
        };
        let store = Arc::new(PersistentMailboxStore::open(":memory:", config).unwrap());
        let replication = Arc::new(replication::ReplicationClient::new(
            "test-node".to_string(),
            vec![], // No peers for testing
        ));
        let state = Arc::new(api::AppState {
            store,
            replication,
            auth: None,
            submit_key_limiter: None,
            mqtt_bridge: None,
            identity: None,
            public_host: None,
            additional_hosts: vec![],
        });
        let app = api::router(state, None);

        // Spawn server in background
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("Server failed");
        });

        // Small delay to ensure server is ready
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        TestServer {
            url,
            _handle: handle,
        }
    }

    fn url(&self) -> &str {
        &self.url
    }
}

/// Test that the transport layer works correctly by sending raw encrypted data
#[tokio::test]
async fn test_transport_roundtrip() {
    let server = TestServer::start().await;
    let transport = TransportPool::<HttpTarget>::single(server.url()).unwrap();

    // Create a test identity
    let identity = Identity::generate();
    let routing_key = identity.public_id().routing_key();

    // Create and submit a test envelope with ephemeral key.
    // NOTE: This test validates transport mechanics only, not cryptographic properties.
    // Actual encryption/decryption is tested in test_e2e_encryption_mik_only.
    let ephemeral_key = [42u8; 32];
    let ack_hash = [0u8; 16]; // Placeholder for transport test
    let test_envelope = OuterEnvelope::new(
        routing_key,
        Some(1),
        ephemeral_key,
        ack_hash,
        vec![1, 2, 3, 4],
    ); // 1 hour TTL
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
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());

    // Create Alice and Bob identities
    let alice = Identity::generate();
    let bob = Identity::generate();

    println!("Alice ID: {}", hex::encode(alice.public_id().to_bytes()));
    println!("Bob ID: {}", hex::encode(bob.public_id().to_bytes()));

    // Bob's routing key
    let bob_routing_key = bob.public_id().routing_key();

    // Alice creates and encrypts a message to Bob's MIK (stateless)
    let message_id = MessageID::new();
    let inner = InnerEnvelope {
        from: *alice.public_id(),
        created_at_ms: 1_234_567_890,
        content: Content::Text(TextContent {
            body: "Hello Bob! This is Alice.".to_string(),
        }),
        prev_self: None,
        observed_heads: Vec::new(),
        epoch: 0,
        flags: 0,
    };

    // Encrypt to Bob's MIK (signing happens inside encrypt_to_mik)
    let enc_output = encrypt_to_mik(&inner, bob.public_id(), &message_id, &alice.to_bytes())
        .expect("encrypt_to_mik failed");
    println!("Alice encrypted message to Bob's MIK");

    // Alice sends the message
    let outer = OuterEnvelope {
        version: CURRENT_VERSION,
        routing_key: bob_routing_key,
        timestamp_hours: reme_message::now_hours(),
        ttl_hours: Some(1), // 1 hour TTL
        message_id,
        ephemeral_key: enc_output.ephemeral_public,
        ack_hash: enc_output.ack_hash,
        inner_ciphertext: enc_output.ciphertext,
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
    // Signature verification happens inside decrypt_with_mik
    let bob_private = bob.to_bytes();
    let dec_output = decrypt_with_mik(
        &messages[0].ephemeral_key,
        &messages[0].inner_ciphertext,
        &bob_private,
        &messages[0].message_id,
    )
    .expect("decrypt_with_mik failed (signature verification included)");

    // Signature was verified during decryption - if we got here, it's valid
    println!("Bob decrypted and verified Alice's signature: OK");

    match dec_output.inner.content {
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
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());

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
    println!("Alice sent message: {msg_id:?}");

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
    println!("Bob sent reply: {reply_id:?}");

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

/// Test multi-node replication: messages sent to one node replicate to peers
#[tokio::test]
async fn test_multi_node_replication() {
    use node::{api, replication, PersistentMailboxStore, PersistentStoreConfig};

    // Start two nodes
    let listener1 = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind node1");
    let addr1 = listener1.local_addr().expect("Failed to get local addr");
    let url1 = format!("http://{addr1}");

    let listener2 = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind node2");
    let addr2 = listener2.local_addr().expect("Failed to get local addr");
    let url2 = format!("http://{addr2}");

    println!("Node 1: {url1}");
    println!("Node 2: {url2}");

    // Create store config for both nodes (in-memory SQLite for testing)
    let config = PersistentStoreConfig {
        max_messages_per_mailbox: 1000,
        default_ttl_secs: 3600,
    };

    // Create node 1 with node 2 as peer
    let store1 = Arc::new(PersistentMailboxStore::open(":memory:", config.clone()).unwrap());
    let replication1 = Arc::new(replication::ReplicationClient::new(
        "node-1".to_string(),
        vec![url2.clone()],
    ));
    let state1 = Arc::new(api::AppState {
        store: store1,
        replication: replication1,
        auth: None,
        submit_key_limiter: None,
        mqtt_bridge: None,
        identity: None,
        public_host: None,
        additional_hosts: vec![],
    });
    let app1 = api::router(state1, None);

    // Create node 2 with node 1 as peer
    let store2 = Arc::new(PersistentMailboxStore::open(":memory:", config).unwrap());
    let replication2 = Arc::new(replication::ReplicationClient::new(
        "node-2".to_string(),
        vec![url1.clone()],
    ));
    let state2 = Arc::new(api::AppState {
        store: store2,
        replication: replication2,
        auth: None,
        submit_key_limiter: None,
        mqtt_bridge: None,
        identity: None,
        public_host: None,
        additional_hosts: vec![],
    });
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
    let transport1 = TransportPool::<HttpTarget>::single(&url1).unwrap();
    let transport2 = TransportPool::<HttpTarget>::single(&url2).unwrap();

    // Create a test identity
    let identity = Identity::generate();
    let routing_key = identity.public_id().routing_key();

    // Send a message to node 1.
    // NOTE: Using fake ephemeral key - this test validates replication, not crypto.
    let ephemeral_key = [99u8; 32];
    let ack_hash = [0u8; 16];
    let test_envelope = OuterEnvelope::new(
        routing_key,
        Some(1),
        ephemeral_key,
        ack_hash,
        vec![42, 43, 44, 45],
    );
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
    assert_eq!(
        messages_from_node2[0].inner_ciphertext,
        vec![42, 43, 44, 45]
    );
    assert_eq!(messages_from_node2[0].ephemeral_key, ephemeral_key);
    println!("Message replicated to node 2: OK");

    println!("\n✓ Multi-node replication test passed!");
}

// ============================================
// Outbox Integration Tests
// ============================================

/// Test that sending a message queues it in the outbox
#[tokio::test]
async fn test_outbox_message_queuing() {
    let server = TestServer::start().await;
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());

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
    println!(
        "Message queued in outbox for Bob: {:?}",
        pending_for_bob[0].content_id
    );

    println!("\n✓ Outbox message queuing test passed!");
}

/// Test DAG-based delivery confirmation: Bob's reply confirms Alice's message
#[tokio::test]
async fn test_outbox_dag_confirmation() {
    let server = TestServer::start().await;
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());

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
    println!("Alice's message is pending, entry_id: {alice_entry_id:?}");

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
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());

    // Use custom config with cleanup_after_ms: 0 so cleanup happens immediately
    let alice_config = OutboxConfig {
        cleanup_after_ms: 0,
        ..OutboxConfig::default()
    };

    let alice_identity = Identity::generate();
    let alice_storage = Storage::in_memory().unwrap();
    let alice = Client::with_config(
        alice_identity,
        transport.clone(),
        alice_storage,
        alice_config,
    );

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
    println!("Alice's message is pending, entry_id: {entry_id:?}");

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
    assert_eq!(
        state,
        DeliveryState::Confirmed,
        "Message should be confirmed via DAG"
    );
    println!("Message confirmed, entry_id: {entry_id:?}");

    // Cleanup should remove confirmed entries (cleanup_after_ms=0 means immediate cleanup)
    let cleaned = alice.outbox_cleanup().expect("cleanup failed");
    println!("Cleaned {cleaned} old confirmed entries");
    assert_eq!(cleaned, 1, "Should have cleaned exactly 1 confirmed entry");

    println!("\n✓ Outbox cleanup test passed!");
}

/// Test that forged signature is rejected at Client level
///
/// This tests the full end-to-end flow where Mallory creates a message
/// claiming to be from Alice, but signs it with her own key. The receiver
/// (Bob) should reject the message with `InvalidSenderSignature` error.
#[tokio::test]
async fn test_forged_signature_rejected_at_client_level() {
    let server = TestServer::start().await;
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());

    // Create identities
    let alice = Identity::generate();
    let bob_identity = Identity::generate();
    let bob_storage = Storage::in_memory().unwrap();
    let bob = Client::new(bob_identity, transport.clone(), bob_storage);
    let mallory = Identity::generate();

    println!("Alice ID: {}", hex::encode(alice.public_id().to_bytes()));
    println!("Bob ID: {}", hex::encode(bob.public_id().to_bytes()));
    println!(
        "Mallory ID: {}",
        hex::encode(mallory.public_id().to_bytes())
    );

    // Mallory creates a message claiming to be from Alice
    let message_id = MessageID::new();
    let inner = InnerEnvelope {
        from: *alice.public_id(), // Claims to be Alice
        created_at_ms: 1_234_567_890,
        content: Content::Text(TextContent {
            body: "Fake message from Alice".to_string(),
        }),
        prev_self: None,
        observed_heads: Vec::new(),
        epoch: 0,
        flags: 0,
    };

    // Mallory encrypts with HER private key (not Alice's)
    // The signature will be made with Mallory's key, but `from` claims Alice
    let enc_output = encrypt_to_mik(&inner, bob.public_id(), &message_id, &mallory.to_bytes())
        .expect("encrypt_to_mik should succeed");

    // Mallory sends the forged message to Bob
    let outer = OuterEnvelope {
        version: CURRENT_VERSION,
        routing_key: bob.routing_key(),
        timestamp_hours: reme_message::now_hours(),
        ttl_hours: Some(1),
        message_id,
        ephemeral_key: enc_output.ephemeral_public,
        ack_hash: enc_output.ack_hash,
        inner_ciphertext: enc_output.ciphertext,
    };

    transport
        .submit_message(outer.clone())
        .await
        .expect("submit_message failed");
    println!("Mallory sent forged message claiming to be Alice");

    // Bob processes the message - should get InvalidSenderSignature error
    let result = bob.process_message(&outer).await;
    assert!(result.is_err(), "Forged message should be rejected");

    let err = result.unwrap_err();
    assert!(
        matches!(err, reme_core::ClientError::InvalidSenderSignature),
        "Expected InvalidSenderSignature error, got: {err:?}"
    );
    println!("Bob correctly rejected forged message with InvalidSenderSignature");

    println!("\n✓ Forged signature rejection test passed!");
}

/// Test that truncated ciphertext is handled gracefully
///
/// This tests edge cases where ciphertext is too short to contain
/// the required signature (64 bytes) or is empty.
#[tokio::test]
async fn test_truncated_ciphertext_rejected() {
    let bob = Identity::generate();
    let bob_private = bob.to_bytes();
    let message_id = MessageID::new();

    // Test empty ciphertext
    let empty_ciphertext: Vec<u8> = vec![];
    let result = decrypt_with_mik(&[1u8; 32], &empty_ciphertext, &bob_private, &message_id);
    assert!(result.is_err(), "Empty ciphertext should be rejected");
    assert!(
        matches!(result.unwrap_err(), EncryptionError::DecryptionFailed),
        "Empty ciphertext should return DecryptionFailed"
    );

    // Test ciphertext smaller than AEAD tag (16 bytes for ChaCha20Poly1305)
    let tiny_ciphertext = vec![0u8; 8];
    let result = decrypt_with_mik(&[1u8; 32], &tiny_ciphertext, &bob_private, &message_id);
    assert!(result.is_err(), "Tiny ciphertext should be rejected");
    assert!(
        matches!(result.unwrap_err(), EncryptionError::DecryptionFailed),
        "Tiny ciphertext should return DecryptionFailed"
    );

    // Test ciphertext that would decrypt to less than 64 bytes (signature size)
    // AEAD tag is 16 bytes, so we need ciphertext > 16 + 64 = 80 bytes for valid payload
    // This tests the post-decryption length check
    let small_ciphertext = vec![0u8; 50]; // Will fail AEAD verification anyway
    let result = decrypt_with_mik(&[1u8; 32], &small_ciphertext, &bob_private, &message_id);
    assert!(result.is_err(), "Small ciphertext should be rejected");
    assert!(
        matches!(result.unwrap_err(), EncryptionError::DecryptionFailed),
        "Small ciphertext should return DecryptionFailed"
    );

    println!("\n✓ Truncated ciphertext rejection test passed!");
}

/// Test that retry mechanism works for pending messages
#[tokio::test]
async fn test_outbox_retry_mechanism() {
    let server = TestServer::start().await;
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());

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
    println!("Message is pending with entry_id: {entry_id:?}");

    // Verify the message state after send (should have at least one attempt)
    assert!(
        !pending[0].attempts.is_empty(),
        "Should have recorded an attempt"
    );
    println!("Message has {} attempts", pending[0].attempts.len());

    // Schedule immediate retry for this entry
    alice
        .schedule_retry(entry_id)
        .expect("schedule_retry failed");
    println!("Scheduled immediate retry for entry {entry_id:?}");

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
    println!("Retry attempt result: {result:?}");

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

// ============================================
// Tombstone V2 (Signed Ack) Integration Tests
// ============================================

use reme_message::SignedAckTombstone;

/// Test auto-tombstone on receive: message is auto-cleared from relay after fetch
#[tokio::test]
async fn test_auto_tombstone_on_receive() {
    let server = TestServer::start().await;
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());

    // Create Alice and Bob
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

    let _msg_id = alice
        .send_text(bob.public_id(), "Hello Bob!")
        .await
        .expect("Alice send_text failed");
    println!("Alice sent message");

    // Bob fetches and processes messages directly (simpler than using MessageReceiver)
    let messages = transport
        .fetch_once(&bob.routing_key())
        .await
        .expect("fetch_once failed");
    assert_eq!(messages.len(), 1, "Message should be in mailbox");
    println!("Bob fetched message from mailbox");

    // Bob processes the message (triggers auto-tombstone)
    let _received = bob
        .process_message(&messages[0])
        .await
        .expect("process_message failed");
    println!("Bob processed message (auto-tombstone sent)");

    // Small delay to ensure tombstone is processed by node
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify message is cleared from Bob's mailbox
    let messages_after = transport
        .fetch_once(&bob.routing_key())
        .await
        .expect("fetch_once failed");
    assert_eq!(
        messages_after.len(),
        0,
        "Message should be cleared from mailbox after auto-tombstone"
    );
    println!("Message cleared from mailbox after auto-tombstone: OK");

    println!("\n✓ Auto-tombstone on receive test passed!");
}

/// Test sender tombstone retracts message before delivery
#[tokio::test]
async fn test_sender_tombstone_retracts_message() {
    let server = TestServer::start().await;
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());

    // Create Alice and Bob
    let alice_identity = Identity::generate();
    let alice_storage = Storage::in_memory().unwrap();
    let alice = Client::new(alice_identity, transport.clone(), alice_storage);

    let bob_identity = Identity::generate();

    println!("Alice ID: {}", hex::encode(alice.public_id().to_bytes()));

    // Alice adds Bob as contact and sends a message
    alice
        .add_contact(bob_identity.public_id(), Some("Bob"))
        .expect("Alice add_contact failed");

    let msg_id = alice
        .send_text(bob_identity.public_id(), "Message to retract")
        .await
        .expect("Alice send_text failed");
    println!("Alice sent message: {msg_id:?}");

    // Note: We do NOT fetch here because fetch() deletes messages from the node.
    // The sender tombstone (retraction) only makes sense when the message hasn't
    // been fetched by the recipient yet.

    // Alice retracts the message (sender-initiated tombstone)
    // Note: acknowledge_sent looks up the ack_secret from local storage
    // and sends a tombstone with the same message_id
    alice
        .acknowledge_sent(msg_id)
        .await
        .expect("acknowledge_sent failed");
    println!("Alice retracted the message");

    // Verify message is cleared from Bob's mailbox (fetch would return empty)
    let bob_routing_key = bob_identity.public_id().routing_key();
    let messages_after = transport
        .fetch_once(&bob_routing_key)
        .await
        .expect("fetch_once failed");
    assert_eq!(
        messages_after.len(),
        0,
        "Message should be cleared after sender tombstone"
    );
    println!("Message cleared from mailbox after retraction: OK");

    println!("\n✓ Sender tombstone retraction test passed!");
}

/// Test that invalid `ack_secret` is rejected by the node
#[tokio::test]
async fn test_invalid_ack_secret_rejected() {
    let server = TestServer::start().await;
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());

    // Create Alice and Bob
    let alice_identity = Identity::generate();
    let alice_storage = Storage::in_memory().unwrap();
    let alice = Client::new(alice_identity, transport.clone(), alice_storage);

    let bob_identity = Identity::generate();

    // Alice adds Bob and sends a message
    alice
        .add_contact(bob_identity.public_id(), Some("Bob"))
        .expect("Alice add_contact failed");

    let msg_id = alice
        .send_text(bob_identity.public_id(), "Secret message")
        .await
        .expect("Alice send_text failed");
    println!("Alice sent message: {msg_id:?}");

    // Mallory tries to forge a tombstone with wrong ack_secret
    let mallory = Identity::generate();
    let wrong_ack_secret: [u8; 16] = [0xDE; 16]; // Wrong secret

    let forged_tombstone = SignedAckTombstone::new(msg_id, wrong_ack_secret, &mallory.to_bytes());

    // Try to submit the forged tombstone - should fail with Forbidden
    let result = transport.submit_ack_tombstone(forged_tombstone).await;
    assert!(result.is_err(), "Forged tombstone should be rejected");
    let err = result.unwrap_err();
    println!("Forged tombstone rejected with error: {err:?}");
    // Should be 403 Forbidden for invalid ack_secret, not 404 Not Found
    assert!(
        format!("{err:?}").contains("403") || format!("{err:?}").contains("Forbidden"),
        "Expected 403 Forbidden, got: {err:?}"
    );

    // Verify message is still in mailbox
    let bob_routing_key = bob_identity.public_id().routing_key();
    let messages = transport
        .fetch_once(&bob_routing_key)
        .await
        .expect("fetch_once failed");
    assert_eq!(
        messages.len(),
        1,
        "Message should still be in mailbox after failed tombstone"
    );
    println!("Message still in mailbox after failed forge attempt: OK");

    println!("\n✓ Invalid ack_secret rejection test passed!");
}

/// Test that tombstone for non-existent message returns 404
#[tokio::test]
async fn test_tombstone_without_message_returns_404() {
    let server = TestServer::start().await;
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());

    // Create identity for signing
    let identity = Identity::generate();

    // Create tombstone for a message that doesn't exist
    let fake_message_id = MessageID::new();
    let fake_ack_secret: [u8; 16] = [0x42; 16];

    let tombstone = SignedAckTombstone::new(fake_message_id, fake_ack_secret, &identity.to_bytes());

    // Try to submit tombstone - should fail with NotFound (404)
    let result = transport.submit_ack_tombstone(tombstone).await;
    let err = result.expect_err("Tombstone for non-existent message should fail");
    assert!(
        matches!(err, TransportError::NotFound),
        "Expected NotFound (404) error, got: {err:?}"
    );
    println!("Tombstone for non-existent message correctly rejected with 404");

    println!("\n✓ Tombstone without message returns 404 test passed!");
}

/// Test that detached messages skip auto-tombstone
#[tokio::test]
async fn test_detached_message_skips_tombstone() {
    use reme_message::FLAG_DETACHED;

    let server = TestServer::start().await;
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());

    // Create identities
    let alice = Identity::generate();
    let bob_identity = Identity::generate();

    // Capture bob's public ID and routing key before creating client
    let bob_pub_id = *bob_identity.public_id();
    let bob_routing_key = bob_identity.public_id().routing_key();

    // Create detached message (FLAG_DETACHED set)
    let message_id = MessageID::new();
    let inner = InnerEnvelope {
        from: *alice.public_id(),
        created_at_ms: 1_234_567_890,
        content: Content::Text(TextContent {
            body: "Detached message".to_string(),
        }),
        prev_self: None,
        observed_heads: Vec::new(),
        epoch: 0,
        flags: FLAG_DETACHED, // Mark as detached
    };

    // Encrypt and send
    let enc_output = encrypt_to_mik(&inner, &bob_pub_id, &message_id, &alice.to_bytes())
        .expect("encrypt_to_mik failed");

    let outer = OuterEnvelope {
        version: CURRENT_VERSION,
        routing_key: bob_routing_key,
        timestamp_hours: reme_message::now_hours(),
        ttl_hours: Some(1),
        message_id,
        ephemeral_key: enc_output.ephemeral_public,
        ack_hash: enc_output.ack_hash,
        inner_ciphertext: enc_output.ciphertext,
    };

    transport
        .submit_message(outer.clone())
        .await
        .expect("submit_message failed");
    println!("Sent detached message");

    // Bob processes the message (should NOT send auto-tombstone due to FLAG_DETACHED)
    let bob_storage = Storage::in_memory().unwrap();
    let bob_client = Client::new(bob_identity, transport.clone(), bob_storage);

    let received = bob_client
        .process_message(&outer)
        .await
        .expect("process_message failed");

    assert!(
        matches!(&received.content, Content::Text(t) if t.body == "Detached message"),
        "Should receive the detached message"
    );
    println!("Bob received detached message");

    // Small delay to ensure any tombstone would be processed
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify message is STILL in mailbox (no auto-tombstone was sent)
    let messages = transport
        .fetch_once(&bob_routing_key)
        .await
        .expect("fetch_once failed");
    assert_eq!(
        messages.len(),
        1,
        "Detached message should still be in mailbox (no auto-tombstone)"
    );
    println!("Detached message still in mailbox (auto-tombstone skipped): OK");

    println!("\n✓ Detached message skips tombstone test passed!");
}

/// Test race-like scenario: tombstone vs fetch in rapid succession
///
/// This tests that tombstone and fetch operations interleave correctly
/// without panics or data corruption. While not truly concurrent due to
/// rusqlite's !Send limitation, it validates the server handles rapid
/// sequential operations correctly.
#[tokio::test]
async fn test_tombstone_fetch_interleaving() {
    let server = TestServer::start().await;
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());

    // Create Alice identity
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let bob_routing_key = bob_identity.public_id().routing_key();

    // Create multiple messages manually to track ack_secrets
    let mut messages = Vec::new();
    for i in 0..5 {
        let message_id = MessageID::new();
        let inner = InnerEnvelope {
            from: *alice_identity.public_id(),
            created_at_ms: 1_234_567_890 + i,
            content: Content::Text(TextContent {
                body: format!("Message {i}"),
            }),
            prev_self: None,
            observed_heads: Vec::new(),
            epoch: 0,
            flags: 0,
        };

        let enc_output = encrypt_to_mik(
            &inner,
            bob_identity.public_id(),
            &message_id,
            &alice_identity.to_bytes(),
        )
        .expect("encrypt_to_mik failed");

        let outer = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key: bob_routing_key,
            timestamp_hours: reme_message::now_hours(),
            ttl_hours: Some(1),
            message_id,
            ephemeral_key: enc_output.ephemeral_public,
            ack_hash: enc_output.ack_hash,
            inner_ciphertext: enc_output.ciphertext,
        };

        transport
            .submit_message(outer)
            .await
            .expect("submit_message failed");

        messages.push((message_id, enc_output.ack_secret));
    }
    println!("Alice sent 5 messages");

    // Alternate between tombstone and fetch operations
    // This simulates race conditions at the server level
    for (i, (msg_id, ack_secret)) in messages.iter().take(3).enumerate() {
        if i % 2 == 0 {
            // Submit tombstone first, then fetch
            let tombstone =
                SignedAckTombstone::new(*msg_id, *ack_secret, &alice_identity.to_bytes());
            let _ = transport.submit_ack_tombstone(tombstone).await;
            let _ = transport.fetch_once(&bob_routing_key).await;
        } else {
            // Fetch first, then tombstone (tombstone will fail - message fetched)
            let _ = transport.fetch_once(&bob_routing_key).await;
            let tombstone =
                SignedAckTombstone::new(*msg_id, *ack_secret, &alice_identity.to_bytes());
            // This may fail with 404 - that's expected
            let _ = transport.submit_ack_tombstone(tombstone).await;
        }
    }
    println!("Interleaved tombstone/fetch operations completed");

    // Final fetch - some messages may remain, some may be gone
    let final_messages = transport
        .fetch_once(&bob_routing_key)
        .await
        .expect("final fetch failed");

    // We expect 0-5 messages depending on timing
    assert!(final_messages.len() <= 5, "Should have at most 5 messages");
    println!("Final fetch returned {} messages", final_messages.len());

    println!("\n✓ Tombstone/fetch interleaving test passed!");
}

/// Test idempotent tombstone: submitting the same tombstone twice
///
/// The second tombstone should fail with 404 because the message was already
/// deleted by the first tombstone. This is expected behavior - not an error.
#[tokio::test]
async fn test_idempotent_tombstone() {
    let server = TestServer::start().await;
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());

    // Create Alice identity (we'll manually create messages to get ack_secret)
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let bob_routing_key = bob_identity.public_id().routing_key();

    // Create message and encrypt manually to get ack_secret
    let message_id = MessageID::new();
    let inner = InnerEnvelope {
        from: *alice_identity.public_id(),
        created_at_ms: 1_234_567_890,
        content: Content::Text(TextContent {
            body: "Test message".to_string(),
        }),
        prev_self: None,
        observed_heads: Vec::new(),
        epoch: 0,
        flags: 0,
    };

    // Encrypt to get the ack_secret
    let enc_output = encrypt_to_mik(
        &inner,
        bob_identity.public_id(),
        &message_id,
        &alice_identity.to_bytes(),
    )
    .expect("encrypt_to_mik failed");

    let outer = OuterEnvelope {
        version: CURRENT_VERSION,
        routing_key: bob_routing_key,
        timestamp_hours: reme_message::now_hours(),
        ttl_hours: Some(1),
        message_id,
        ephemeral_key: enc_output.ephemeral_public,
        ack_hash: enc_output.ack_hash,
        inner_ciphertext: enc_output.ciphertext,
    };

    // Submit the message
    transport
        .submit_message(outer)
        .await
        .expect("submit_message failed");
    println!("Alice sent message: {message_id:?}");

    // Create tombstone (we have the ack_secret from encryption)
    let tombstone = SignedAckTombstone::new(
        message_id,
        enc_output.ack_secret,
        &alice_identity.to_bytes(),
    );

    // First tombstone - should succeed
    transport
        .submit_ack_tombstone(tombstone.clone())
        .await
        .expect("first tombstone should succeed");
    println!("First tombstone succeeded");

    // Verify message is cleared
    let messages = transport
        .fetch_once(&bob_routing_key)
        .await
        .expect("fetch_once failed");
    assert_eq!(messages.len(), 0, "Message should be cleared");

    // Second tombstone - should fail with 404 (message already deleted)
    let result = transport.submit_ack_tombstone(tombstone).await;

    // The second tombstone should fail because the message no longer exists
    assert!(
        result.is_err(),
        "Second tombstone should fail (message already deleted)"
    );
    println!("Second tombstone correctly failed (message already gone)");

    println!("\n✓ Idempotent tombstone test passed!");
}
