//! Integration test: Two clients exchanging messages through the node
//!
//! These tests spin up an in-process node server for self-contained testing.

use reme_core::Client;
use reme_encryption::{decrypt_inner_envelope, encrypt_inner_envelope};
use reme_identity::Identity;
use reme_message::{
    Content, InnerEnvelope, MessageID, OuterEnvelope, TextContent, TombstoneStatus, CURRENT_VERSION,
};
use reme_prekeys::generate_prekey_bundle;
use reme_session::derive_session_as_initiator;
use reme_storage::Storage;
use reme_transport::http::HttpTransport;
use reme_transport::Transport;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Test server handle - keeps the server running while in scope
struct TestServer {
    url: String,
    _handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    /// Start a test server on a random available port
    async fn start() -> Self {
        use node::{api, store, replication};

        // Bind to port 0 to get a random available port
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind");
        let addr = listener.local_addr().expect("Failed to get local addr");
        let url = format!("http://{}", addr);

        // Create minimal node components
        let store = Arc::new(store::MailboxStore::new(1000, 3600));
        let replication = Arc::new(replication::ReplicationClient::new(
            "test-node".to_string(),
            vec![], // No peers for testing
        ));
        let state = Arc::new(api::AppState { store, replication });
        let app = api::router(state);

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

    // Create a test identity and upload prekeys
    let identity = Identity::generate();
    let routing_key = identity.public_id().routing_key();

    let (_, bundle) = generate_prekey_bundle(&identity, 5);

    // Upload prekeys
    transport
        .upload_prekeys(routing_key, bundle.clone())
        .await
        .expect("upload_prekeys failed");

    // Fetch prekeys back
    let fetched_bundle = transport
        .fetch_prekeys(routing_key)
        .await
        .expect("fetch_prekeys failed");

    assert_eq!(fetched_bundle.id_pub(), bundle.id_pub());
    println!("Prekey roundtrip: OK");

    // Create and submit a test envelope
    let test_envelope = OuterEnvelope::new(routing_key, vec![1, 2, 3, 4], Some(3600));
    transport
        .submit_message(test_envelope)
        .await
        .expect("submit_message failed");

    // Fetch messages
    let messages = transport
        .fetch_messages(routing_key)
        .await
        .expect("fetch_messages failed");

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].inner_ciphertext, vec![1, 2, 3, 4]);
    println!("Message roundtrip: OK");

    println!("✓ Transport roundtrip test passed!");
}

/// Test end-to-end encryption using proper X3DH session derivation
#[tokio::test]
async fn test_e2e_encryption_manual() {
    let server = TestServer::start().await;
    let transport = Arc::new(HttpTransport::new(server.url()));

    // Create Alice and Bob identities
    let alice = Identity::generate();
    let bob = Identity::generate();

    println!("Alice ID: {}", hex::encode(alice.public_id().to_bytes()));
    println!("Bob ID: {}", hex::encode(bob.public_id().to_bytes()));

    // Bob generates and uploads prekeys
    let bob_routing_key = bob.public_id().routing_key();
    let (bob_secrets, bob_bundle) = generate_prekey_bundle(&bob, 5);

    transport
        .upload_prekeys(bob_routing_key, bob_bundle.clone())
        .await
        .expect("Bob upload_prekeys failed");
    println!("Bob's prekeys uploaded");

    // Alice fetches Bob's prekeys and establishes session
    let fetched_bundle = transport
        .fetch_prekeys(bob_routing_key)
        .await
        .expect("fetch Bob's prekeys failed");

    let alice_session = derive_session_as_initiator(&alice, &fetched_bundle, true)
        .expect("Alice derive_session failed");
    println!("Alice established session with Bob");

    // Alice creates and encrypts a message
    let message_id = MessageID::new();
    let inner = InnerEnvelope {
        version: CURRENT_VERSION,
        from: *alice.public_id(),
        to: *bob.public_id(),
        created_at_ms: 1234567890,
        outer_message_id: message_id,
        content: Content::Text(TextContent {
            body: "Hello Bob! This is Alice.".to_string(),
        }),
    };

    let ciphertext = encrypt_inner_envelope(&inner, alice_session.send_key(), &message_id)
        .expect("encrypt failed");

    // Alice sends the message
    let outer = OuterEnvelope {
        version: CURRENT_VERSION,
        flags: 0,
        routing_key: bob_routing_key,
        created_at_ms: Some(1234567890),
        ttl: Some(3600),
        message_id,
        session_init: None,
        inner_ciphertext: ciphertext,
    };

    transport
        .submit_message(outer)
        .await
        .expect("submit_message failed");
    println!("Alice sent encrypted message");

    // Bob fetches messages
    let messages = transport
        .fetch_messages(bob_routing_key)
        .await
        .expect("fetch_messages failed");

    assert_eq!(messages.len(), 1);
    println!("Bob fetched {} message(s)", messages.len());

    // Bob derives the session as responder
    let bob_session = reme_session::derive_session_as_responder(
        &bob,
        &bob_secrets,
        alice.public_id(),
        alice_session.ephemeral_public(),
        alice_session.used_one_time_prekey_id(),
    )
    .expect("Bob derive_session failed");

    // Verify the keys match
    assert_eq!(alice_session.send_key(), bob_session.recv_key());
    assert_eq!(alice_session.recv_key(), bob_session.send_key());
    println!("Session keys verified: Alice.send == Bob.recv, Alice.recv == Bob.send");

    // Bob decrypts the message
    let decrypted = decrypt_inner_envelope(
        &messages[0].inner_ciphertext,
        bob_session.recv_key(),
        &messages[0].message_id,
    )
    .expect("decrypt failed");

    match decrypted.content {
        Content::Text(t) => {
            assert_eq!(t.body, "Hello Bob! This is Alice.");
            println!("Bob decrypted message: \"{}\"", t.body);
        }
        _ => panic!("Expected text content"),
    }

    println!("\n✓ End-to-end encryption test passed!");
}

/// Test two clients exchanging messages using the full Client API
#[tokio::test]
async fn test_two_client_messaging() {
    let server = TestServer::start().await;
    let transport = Arc::new(HttpTransport::new(server.url()));

    // Create Alice's client
    let alice_identity = Identity::generate();
    let alice_storage = Storage::in_memory().unwrap();
    let alice = Client::new(alice_identity, transport.clone(), alice_storage);

    // Create Bob's client
    let bob_identity = Identity::generate();
    let bob_storage = Storage::in_memory().unwrap();
    let bob = Client::new(bob_identity, transport.clone(), bob_storage);

    println!("Alice ID: {}", hex::encode(alice.public_id().to_bytes()));
    println!("Bob ID: {}", hex::encode(bob.public_id().to_bytes()));

    // Both clients initialize prekeys
    alice.init_prekeys(5).await.expect("Alice init_prekeys failed");
    bob.init_prekeys(5).await.expect("Bob init_prekeys failed");
    println!("Both clients initialized prekeys");

    // Alice adds Bob as a contact
    alice
        .add_contact(bob.public_id(), Some("Bob"))
        .expect("Alice add_contact failed");
    println!("Alice added Bob as contact");

    // Alice sends a message to Bob
    let msg_id = alice
        .send_text(bob.public_id(), "Hello Bob! This is Alice.")
        .await
        .expect("Alice send_text failed");
    println!("Alice sent message: {:?}", msg_id);

    // Bob fetches messages
    let messages = bob.fetch_messages().await.expect("Bob fetch_messages failed");
    assert_eq!(messages.len(), 1, "Bob should receive 1 message");

    let received = &messages[0];
    assert_eq!(received.from, *alice.public_id());
    match &received.content {
        Content::Text(text) => {
            assert_eq!(text.body, "Hello Bob! This is Alice.");
            println!("Bob received: \"{}\"", text.body);
        }
        _ => panic!("Expected text message"),
    }

    // Bob replies to Alice
    let reply_id = bob
        .send_text(alice.public_id(), "Hi Alice! Got your message.")
        .await
        .expect("Bob send_text failed");
    println!("Bob sent reply: {:?}", reply_id);

    // Alice fetches messages
    let alice_messages = alice.fetch_messages().await.expect("Alice fetch_messages failed");
    assert_eq!(alice_messages.len(), 1, "Alice should receive 1 message");

    let alice_received = &alice_messages[0];
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
async fn test_tombstone_flow() {
    let server = TestServer::start().await;
    let transport = Arc::new(HttpTransport::new(server.url()));

    // Create Alice and Bob
    let alice_identity = Identity::generate();
    let alice_storage = Storage::in_memory().unwrap();
    let alice = Client::new(alice_identity, transport.clone(), alice_storage);

    let bob_identity = Identity::generate();
    let bob_storage = Storage::in_memory().unwrap();
    let bob = Client::new(bob_identity, transport.clone(), bob_storage);

    println!("Alice ID: {}", hex::encode(alice.public_id().to_bytes()));
    println!("Bob ID: {}", hex::encode(bob.public_id().to_bytes()));

    // Initialize prekeys
    alice.init_prekeys(5).await.expect("Alice init_prekeys failed");
    bob.init_prekeys(5).await.expect("Bob init_prekeys failed");
    println!("Both clients initialized prekeys");

    // Alice adds Bob as contact and sends a message
    alice
        .add_contact(bob.public_id(), Some("Bob"))
        .expect("Alice add_contact failed");

    let msg_id = alice
        .send_text(bob.public_id(), "Hello Bob!")
        .await
        .expect("Alice send_text failed");
    println!("Alice sent message: {:?}", msg_id);

    // Bob fetches the message
    let messages = bob.fetch_messages().await.expect("Bob fetch_messages failed");
    assert_eq!(messages.len(), 1, "Bob should receive 1 message");
    println!("Bob received message from Alice");

    let received = &messages[0];

    // Bob sends a delivery tombstone
    bob.send_delivery_tombstone(received)
        .await
        .expect("Bob send_delivery_tombstone failed");
    println!("Bob sent delivery tombstone for message {:?}", received.message_id);

    // Bob sends a read tombstone
    bob.send_read_tombstone(received)
        .await
        .expect("Bob send_read_tombstone failed");
    println!("Bob sent read tombstone for message {:?}", received.message_id);

    println!("\n✓ Tombstone flow test passed!");
}

/// Test tombstone with different status options
#[tokio::test]
async fn test_tombstone_with_status() {
    let server = TestServer::start().await;
    let transport = Arc::new(HttpTransport::new(server.url()));

    let identity = Identity::generate();
    let storage = Storage::in_memory().unwrap();
    let client = Client::new(identity, transport.clone(), storage);

    client.init_prekeys(5).await.expect("init_prekeys failed");

    // Create a fake "received" message for testing tombstone creation
    let fake_received = reme_core::ReceivedMessage {
        message_id: MessageID::new(),
        from: *client.public_id(),
        content: Content::Text(TextContent {
            body: "Test message".to_string(),
        }),
        created_at_ms: 1234567890,
    };

    // Test each tombstone status
    client
        .send_tombstone(&fake_received, TombstoneStatus::Delivered, false)
        .await
        .expect("Delivered tombstone failed");
    println!("Sent Delivered tombstone");

    client
        .send_tombstone(&fake_received, TombstoneStatus::Read, false)
        .await
        .expect("Read tombstone failed");
    println!("Sent Read tombstone");

    client
        .send_tombstone(&fake_received, TombstoneStatus::Deleted, false)
        .await
        .expect("Deleted tombstone failed");
    println!("Sent Deleted tombstone");

    println!("\n✓ Tombstone status test passed!");
}

/// Test multi-node replication: messages sent to one node replicate to peers
#[tokio::test]
async fn test_multi_node_replication() {
    use node::{api, store, replication};

    // Start two nodes
    let listener1 = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind node1");
    let addr1 = listener1.local_addr().expect("Failed to get local addr");
    let url1 = format!("http://{}", addr1);

    let listener2 = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind node2");
    let addr2 = listener2.local_addr().expect("Failed to get local addr");
    let url2 = format!("http://{}", addr2);

    println!("Node 1: {}", url1);
    println!("Node 2: {}", url2);

    // Create node 1 with node 2 as peer
    let store1 = Arc::new(store::MailboxStore::new(1000, 3600));
    let replication1 = Arc::new(replication::ReplicationClient::new(
        "node-1".to_string(),
        vec![url2.clone()],
    ));
    let state1 = Arc::new(api::AppState { store: store1, replication: replication1 });
    let app1 = api::router(state1);

    // Create node 2 with node 1 as peer
    let store2 = Arc::new(store::MailboxStore::new(1000, 3600));
    let replication2 = Arc::new(replication::ReplicationClient::new(
        "node-2".to_string(),
        vec![url1.clone()],
    ));
    let state2 = Arc::new(api::AppState { store: store2, replication: replication2 });
    let app2 = api::router(state2);

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

    // Upload prekeys to node 1
    let (_, bundle) = generate_prekey_bundle(&identity, 5);
    transport1
        .upload_prekeys(routing_key, bundle.clone())
        .await
        .expect("upload_prekeys to node1 failed");
    println!("Uploaded prekeys to node 1");

    // Wait for replication
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Verify prekeys are available on node 2
    let fetched_from_node2 = transport2
        .fetch_prekeys(routing_key)
        .await
        .expect("fetch_prekeys from node2 failed");
    assert_eq!(fetched_from_node2.id_pub(), bundle.id_pub());
    println!("Prekeys replicated to node 2: OK");

    // Send a message to node 1
    let test_envelope = OuterEnvelope::new(routing_key, vec![42, 43, 44, 45], Some(3600));
    transport1
        .submit_message(test_envelope)
        .await
        .expect("submit_message to node1 failed");
    println!("Sent message to node 1");

    // Wait for replication
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Fetch message from node 2
    let messages_from_node2 = transport2
        .fetch_messages(routing_key)
        .await
        .expect("fetch_messages from node2 failed");
    assert_eq!(messages_from_node2.len(), 1);
    assert_eq!(messages_from_node2[0].inner_ciphertext, vec![42, 43, 44, 45]);
    println!("Message replicated to node 2: OK");

    println!("\n✓ Multi-node replication test passed!");
}

/// Test that tombstone sequence numbers are monotonically increasing
#[tokio::test]
async fn test_tombstone_sequence() {
    let server = TestServer::start().await;
    let transport = Arc::new(HttpTransport::new(server.url()));

    let identity = Identity::generate();
    let storage = Storage::in_memory().unwrap();
    let client = Client::new(identity, transport.clone(), storage);

    client.init_prekeys(5).await.expect("init_prekeys failed");

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
