#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Sneakernet round-trip integration tests (GH issue #161)
//!
//! Tests the offline workflow: Alice prepares messages offline, exports to a bundle,
//! the bundle is imported into a node, and Bob fetches + decrypts from the node.

use ember_bundle::{BundleReader, BundleWriter};
use ember_core::{Client, ReceivedMessage};
use ember_identity::{Identity, PublicID};
use ember_message::wire::WirePayload;
use ember_message::{Content, OuterEnvelope, TextContent};
use ember_node_core::{MailboxStore, PersistentMailboxStore, PersistentStoreConfig};
use ember_outbox::PendingMessage;
use ember_storage::Storage;
use ember_transport::http_target::HttpTarget;
use ember_transport::pool::TransportPool;
use ember_transport::{
    CoordinatorConfig, Transport, TransportCoordinator, TransportError, TransportEvent,
};
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

/// A no-op transport for offline clients that never actually send.
struct NoopTransport;

#[async_trait::async_trait]
impl Transport for NoopTransport {
    async fn submit_message(&self, _: OuterEnvelope) -> Result<(), TransportError> {
        Ok(())
    }

    async fn submit_ack_tombstone(
        &self,
        _: ember_message::SignedAckTombstone,
    ) -> Result<(), TransportError> {
        Ok(())
    }
}

/// Test server that exposes its mailbox store for direct import.
struct TestServerWithStore {
    url: String,
    store: Arc<PersistentMailboxStore>,
    _handle: tokio::task::JoinHandle<()>,
}

impl TestServerWithStore {
    /// Start a test server on a random available port, keeping a handle to the store.
    async fn start() -> Self {
        use node::{api, replication};

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind");
        let addr = listener.local_addr().expect("Failed to get local addr");
        let url = format!("http://{addr}");

        let config = PersistentStoreConfig {
            max_messages_per_mailbox: 1000,
            default_ttl_secs: 3600,
        };
        let store = Arc::new(PersistentMailboxStore::open(":memory:", config).unwrap());
        let replication = Arc::new(replication::ReplicationClient::new(
            "test-node".to_string(),
            vec![],
        ));
        let state = Arc::new(api::AppState {
            store: store.clone(),
            replication,
            auth: None,
            submit_key_limiter: None,
            mqtt_bridge: None,
            identity: None,
            public_host: None,
            additional_hosts: vec![],
            config: node::config::NodeConfig::default(),
        });
        let app = api::router(state, None);

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("Server failed");
        });

        let mut server_ready = false;
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                server_ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(server_ready, "Test server failed to start within 500ms");

        Self {
            url,
            store,
            _handle: handle,
        }
    }

    fn url(&self) -> &str {
        &self.url
    }
}

/// Create a `TransportCoordinator` wired to the given HTTP pool with fast polling for tests.
fn test_coordinator(transport: &Arc<TransportPool<HttpTarget>>) -> TransportCoordinator {
    let mut coordinator = TransportCoordinator::new(CoordinatorConfig {
        poll_interval: Duration::from_millis(50),
        ..CoordinatorConfig::default()
    });
    coordinator.set_http_pool_arc(transport.clone());
    coordinator
}

/// Create an offline client with a `NoopTransport`, pre-configured with a contact.
fn offline_client(
    identity: Identity,
    contact: &PublicID,
    contact_name: &str,
) -> Client<NoopTransport> {
    let client = Client::new(
        identity,
        Arc::new(NoopTransport),
        Arc::new(Storage::in_memory().unwrap()),
    );
    client.add_contact(contact, Some(contact_name)).unwrap();
    client
}

/// Create a client connected to a test server, pre-configured with a contact.
fn online_client(
    identity: Identity,
    transport: Arc<TransportPool<HttpTarget>>,
    contact: &PublicID,
    contact_name: &str,
) -> Client<TransportPool<HttpTarget>> {
    let client = Client::new(identity, transport, Arc::new(Storage::in_memory().unwrap()));
    client.add_contact(contact, Some(contact_name)).unwrap();
    client
}

/// Prepare a single text message from client to recipient.
fn prepare_text(
    client: &Client<NoopTransport>,
    to: &PublicID,
    body: &str,
) -> ember_core::PreparedMessage {
    client
        .prepare_message(
            to,
            Content::Text(TextContent {
                body: body.to_string(),
            }),
            false,
        )
        .unwrap()
}

/// Create a bundle from pending outbox messages.
fn export_to_bundle(messages: &[PendingMessage]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = BundleWriter::new(&mut buf);
    for msg in messages {
        let envelope: OuterEnvelope = postcard::from_bytes(&msg.envelope_bytes)
            .expect("Failed to deserialize envelope from outbox");
        let wire = WirePayload::Message(envelope);
        let frame = wire.encode().expect("Failed to encode WirePayload");
        writer.write_frame(&frame).expect("Failed to write frame");
    }
    writer.finish().expect("Failed to finish bundle");
    buf
}

/// Import bundle frames into a node's mailbox store.
fn import_to_node(store: &PersistentMailboxStore, bundle_bytes: &[u8]) {
    let reader = BundleReader::open(Cursor::new(bundle_bytes)).expect("Failed to open bundle");
    let frames = reader.read_all_verified().expect("Bundle checksum failed");
    for frame in &frames {
        let payload = WirePayload::decode(frame).expect("Failed to decode frame");
        if let WirePayload::Message(envelope) = payload {
            store
                .enqueue(envelope.routing_key, envelope)
                .expect("Failed to enqueue");
        }
    }
}

/// Receive up to `count` messages from a coordinator subscription, with a timeout.
async fn recv_messages(
    bob: &Client<TransportPool<HttpTarget>>,
    transport: &Arc<TransportPool<HttpTarget>>,
    count: usize,
    timeout: Duration,
) -> Vec<ReceivedMessage> {
    let coordinator = test_coordinator(transport);
    let (mut events, _handle) = coordinator.subscribe(bob.routing_key());

    let mut received = Vec::with_capacity(count);
    let mut errors: Vec<String> = Vec::new();
    let result = tokio::time::timeout(timeout, async {
        while received.len() < count {
            match events.recv().await {
                Some(TransportEvent::Message(envelope)) => {
                    match bob.process_message(&envelope).await {
                        Ok(msg) => received.push(msg),
                        Err(e) => errors.push(format!("process_message failed: {e}")),
                    }
                }
                Some(TransportEvent::Error(e)) => {
                    errors.push(format!("transport error: {e}"));
                }
                None => break,
            }
        }
    })
    .await;
    assert!(errors.is_empty(), "Errors during receive: {errors:?}");
    assert!(
        result.is_ok(),
        "Timeout: received {}/{count} messages",
        received.len()
    );
    received
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Full sneakernet round-trip: Alice offline -> export bundle -> import to node -> Bob fetches.
#[tokio::test]
async fn test_sneakernet_happy_path() {
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let alice_pub = *alice_identity.public_id();
    let bob_pub = *bob_identity.public_id();

    let alice = offline_client(alice_identity, &bob_pub, "Bob");
    let prepared = prepare_text(&alice, &bob_pub, "Hello from sneakernet!");

    let pending = alice.get_pending_messages().unwrap();
    assert_eq!(pending.len(), 1);
    let bundle_bytes = export_to_bundle(&pending);

    let server = TestServerWithStore::start().await;
    import_to_node(&server.store, &bundle_bytes);

    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());
    let bob = online_client(bob_identity, transport.clone(), &alice_pub, "Alice");

    let received = recv_messages(&bob, &transport, 1, Duration::from_secs(5)).await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].message_id, prepared.outer.message_id);
    #[allow(clippy::wildcard_enum_match_arm)] // Content is #[non_exhaustive]
    match &received[0].content {
        Content::Text(text) => assert_eq!(text.body, "Hello from sneakernet!"),
        _ => panic!("Expected Text, got {:?}", received[0].content),
    }
}

/// Alice sends 5 messages; all arrive via sneakernet.
#[tokio::test]
async fn test_sneakernet_multiple_messages() {
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let alice_pub = *alice_identity.public_id();
    let bob_pub = *bob_identity.public_id();

    let alice = offline_client(alice_identity, &bob_pub, "Bob");
    for i in 0..5 {
        prepare_text(&alice, &bob_pub, &format!("Message {i}"));
    }

    let pending = alice.get_pending_messages().unwrap();
    assert_eq!(pending.len(), 5);
    let bundle_bytes = export_to_bundle(&pending);

    let server = TestServerWithStore::start().await;
    import_to_node(&server.store, &bundle_bytes);

    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());
    let bob = online_client(bob_identity, transport.clone(), &alice_pub, "Alice");

    let received = recv_messages(&bob, &transport, 5, Duration::from_secs(5)).await;

    let mut received_bodies: Vec<String> = received
        .iter()
        .filter_map(|msg| {
            #[allow(clippy::wildcard_enum_match_arm)] // Content is #[non_exhaustive]
            match &msg.content {
                Content::Text(text) => Some(text.body.clone()),
                _ => None,
            }
        })
        .collect();
    received_bodies.sort();

    let mut expected: Vec<String> = (0..5).map(|i| format!("Message {i}")).collect();
    expected.sort();
    assert_eq!(received_bodies, expected);
}

/// Importing the same bundle twice -- Bob still receives valid messages with the same ID.
#[tokio::test]
async fn test_sneakernet_duplicate_import_idempotent() {
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let alice_pub = *alice_identity.public_id();
    let bob_pub = *bob_identity.public_id();

    let alice = offline_client(alice_identity, &bob_pub, "Bob");
    prepare_text(&alice, &bob_pub, "Dedup test");

    let pending = alice.get_pending_messages().unwrap();
    let bundle_bytes = export_to_bundle(&pending);

    let server = TestServerWithStore::start().await;
    import_to_node(&server.store, &bundle_bytes);
    import_to_node(&server.store, &bundle_bytes); // second import

    // Verify store-level dedup: only 1 envelope despite 2 imports
    let routing_key = bob_pub.routing_key();
    let store_messages = server.store.fetch(&routing_key).unwrap();
    assert_eq!(
        store_messages.len(),
        1,
        "Node should deduplicate: 1 envelope in store, not 2"
    );

    // Bob receives exactly 1 message
    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());
    let bob = online_client(bob_identity, transport.clone(), &alice_pub, "Alice");
    let received = recv_messages(&bob, &transport, 1, Duration::from_secs(3)).await;
    assert_eq!(received.len(), 1, "Bob should receive exactly 1 message");
}

/// A message destined for Charlie cannot be fetched by Bob (routing key isolation).
#[tokio::test]
async fn test_sneakernet_wrong_recipient_not_decryptable() {
    let alice_identity = Identity::generate();
    let charlie_identity = Identity::generate();
    let bob_pub = *Identity::generate().public_id();
    let charlie_pub = *charlie_identity.public_id();

    let alice = offline_client(alice_identity, &charlie_pub, "Charlie");
    prepare_text(&alice, &charlie_pub, "For Charlie only");

    let pending = alice.get_pending_messages().unwrap();
    let bundle_bytes = export_to_bundle(&pending);

    let server = TestServerWithStore::start().await;
    import_to_node(&server.store, &bundle_bytes);

    let charlie_rk = charlie_pub.routing_key();
    let bob_rk = bob_pub.routing_key();

    let charlie_msgs = server.store.fetch(&charlie_rk).unwrap();
    assert_eq!(
        charlie_msgs.len(),
        1,
        "Charlie's mailbox should have 1 message"
    );

    let bob_msgs = server.store.fetch(&bob_rk).unwrap();
    assert!(
        bob_msgs.is_empty(),
        "Bob's mailbox should be empty (routing key isolation)"
    );
}

/// An empty bundle can be created and imported without errors.
#[tokio::test]
async fn test_sneakernet_empty_bundle() {
    let mut buf = Vec::new();
    let writer = BundleWriter::new(&mut buf);
    writer.finish().unwrap();

    let server = TestServerWithStore::start().await;
    import_to_node(&server.store, &buf);

    let stats = server.store.stats().unwrap();
    assert_eq!(stats.total_messages, 0);
}

/// Export -> import preserves frame content (byte-level integrity of encoded envelopes).
#[tokio::test]
async fn test_sneakernet_round_trip_integrity() {
    let alice_identity = Identity::generate();
    let bob_pub = *Identity::generate().public_id();

    let alice = offline_client(alice_identity, &bob_pub, "Bob");
    prepare_text(&alice, &bob_pub, "Integrity check");

    let pending = alice.get_pending_messages().unwrap();
    let bundle_bytes = export_to_bundle(&pending);

    // Read original bundle frames
    let original_frames = BundleReader::open(Cursor::new(&bundle_bytes))
        .and_then(BundleReader::read_all_verified)
        .expect("Original bundle read failed");

    // Import into node
    let server = TestServerWithStore::start().await;
    import_to_node(&server.store, &bundle_bytes);

    // Re-export from node store into a second bundle
    let re_exported_envelopes = server.store.export_messages(None, None, None).unwrap();
    assert_eq!(re_exported_envelopes.len(), 1);

    let mut re_export_buf = Vec::new();
    let mut writer = BundleWriter::new(&mut re_export_buf);
    for env in re_exported_envelopes {
        let frame = WirePayload::Message(env)
            .encode()
            .expect("Failed to encode re-exported frame");
        writer.write_frame(&frame).unwrap();
    }
    writer.finish().unwrap();

    // Read re-exported bundle frames
    let re_exported_frames = BundleReader::open(Cursor::new(&re_export_buf))
        .and_then(BundleReader::read_all_verified)
        .expect("Re-exported bundle read failed");

    // Compare: frame contents should be byte-identical
    assert_eq!(original_frames.len(), re_exported_frames.len());
    for (i, (orig, re_exp)) in original_frames
        .iter()
        .zip(re_exported_frames.iter())
        .enumerate()
    {
        assert_eq!(
            orig, re_exp,
            "Frame {i} differs between original and re-exported bundle"
        );
    }
}

/// 100 messages round-trip through a bundle without loss.
#[tokio::test]
async fn test_sneakernet_large_bundle() {
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let alice_pub = *alice_identity.public_id();
    let bob_pub = *bob_identity.public_id();

    let alice = offline_client(alice_identity, &bob_pub, "Bob");
    for i in 0..100 {
        prepare_text(&alice, &bob_pub, &format!("Msg {i:03}"));
    }

    let pending = alice.get_pending_messages().unwrap();
    assert_eq!(pending.len(), 100);
    let bundle_bytes = export_to_bundle(&pending);

    let server = TestServerWithStore::start().await;
    import_to_node(&server.store, &bundle_bytes);

    let transport = Arc::new(TransportPool::<HttpTarget>::single(server.url()).unwrap());
    let bob = online_client(bob_identity, transport.clone(), &alice_pub, "Alice");

    let received = recv_messages(&bob, &transport, 100, Duration::from_secs(10)).await;
    assert_eq!(received.len(), 100);
}
