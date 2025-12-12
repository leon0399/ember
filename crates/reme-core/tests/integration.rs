//! Integration test: Two clients exchanging messages through the node
//!
//! Requires node to be running at localhost:23003

use reme_core::Client;
use reme_encryption::{decrypt_inner_envelope, encrypt_inner_envelope};
use reme_identity::Identity;
use reme_message::{Content, InnerEnvelope, MessageID, OuterEnvelope, TextContent, CURRENT_VERSION};
use reme_prekeys::generate_prekey_bundle;
use reme_session::derive_session_as_initiator;
use reme_storage::Storage;
use reme_transport::http::HttpTransport;
use reme_transport::Transport;
use std::sync::Arc;

const NODE_URL: &str = "http://localhost:23003";

/// Test that the transport layer works correctly by sending raw encrypted data
#[tokio::test]
async fn test_transport_roundtrip() {
    let transport = HttpTransport::new(NODE_URL);

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

    println!("Transport roundtrip test passed!");
}

/// Test end-to-end encryption using proper X3DH session derivation
/// This demonstrates how the full protocol should work
#[tokio::test]
async fn test_e2e_encryption_manual() {
    let transport = Arc::new(HttpTransport::new(NODE_URL));

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
    // NOTE: In real implementation, Alice's ephemeral_public and used_one_time_prekey_id
    // would be included in the message header
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

    println!("\nEnd-to-end encryption test passed!");
}

/// Test two clients exchanging messages using the full Client API
/// This tests the complete flow including automatic session establishment
#[tokio::test]
async fn test_two_client_messaging() {
    // Create shared transport (both clients connect to same node)
    let transport = Arc::new(HttpTransport::new(NODE_URL));

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
    // This will automatically:
    // 1. Fetch Bob's prekeys
    // 2. Establish X3DH session
    // 3. Send message with session_init data
    let msg_id = alice
        .send_text(bob.public_id(), "Hello Bob! This is Alice.")
        .await
        .expect("Alice send_text failed");
    println!("Alice sent message: {:?}", msg_id);

    // Bob fetches messages
    // This will automatically:
    // 1. Receive message with session_init
    // 2. Derive session as responder
    // 3. Decrypt and return message
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

    // Now Bob can reply to Alice
    // Bob should now have Alice as a contact (auto-added from incoming message)
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

    // Send another message from Alice (should NOT include session_init this time)
    let msg2_id = alice
        .send_text(bob.public_id(), "Second message!")
        .await
        .expect("Alice second send_text failed");
    println!("Alice sent second message: {:?}", msg2_id);

    let bob_messages2 = bob.fetch_messages().await.expect("Bob second fetch failed");
    assert_eq!(bob_messages2.len(), 1, "Bob should receive 1 message");
    match &bob_messages2[0].content {
        Content::Text(text) => {
            assert_eq!(text.body, "Second message!");
            println!("Bob received second message: \"{}\"", text.body);
        }
        _ => panic!("Expected text message"),
    }

    println!("\n✓ Two-client messaging test passed!");
}
