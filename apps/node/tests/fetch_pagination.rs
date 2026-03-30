#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Integration tests for paginated mailbox fetch responses.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ember_identity::RoutingKey;
use ember_message::{OuterEnvelope, WirePayload};
use node::{api, replication, MailboxStore, PersistentMailboxStore, PersistentStoreConfig};
use serde_json::Value;
use std::sync::Arc;
use tokio::{net::TcpListener, task::JoinHandle};

fn create_test_envelope(routing_key: RoutingKey, ciphertext_len: usize) -> OuterEnvelope {
    let marker = u8::try_from(ciphertext_len % 256).expect("modulo constrains marker to u8");
    OuterEnvelope::new(
        routing_key,
        Some(1),
        [marker; 32],
        [marker; 16],
        vec![marker; ciphertext_len],
    )
}

async fn start_test_node(store: Arc<PersistentMailboxStore>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().expect("Failed to get local addr");
    let url = format!("http://{addr}");

    let replication = Arc::new(replication::ReplicationClient::new(
        "test-node".to_string(),
        vec![],
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
        config: node::config::NodeConfig::default(),
    });
    let app = api::router(state, None);

    let url_clone = url.clone();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("Server failed");
    });

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

async fn fetch_json(
    url: &str,
    routing_key: &RoutingKey,
    query: &[(&str, &str)],
) -> reqwest::Response {
    let client = reqwest::Client::new();
    client
        .get(format!(
            "{url}/api/v1/fetch/{}",
            URL_SAFE_NO_PAD.encode(routing_key.as_bytes())
        ))
        .query(query)
        .send()
        .await
        .expect("Fetch request failed")
}

fn decode_message_payload(payload: &str) -> OuterEnvelope {
    let decoded = base64::prelude::BASE64_STANDARD
        .decode(payload)
        .expect("payload should decode from base64");
    match WirePayload::decode(&decoded).expect("payload should decode as wire payload") {
        WirePayload::Message(envelope) => envelope,
        WirePayload::AckTombstone(tombstone) => {
            panic!("expected message payload, got {tombstone:?}")
        }
    }
}

#[tokio::test]
async fn test_fetch_limit_returns_continuation_fields() {
    let config = PersistentStoreConfig::default();
    let store = Arc::new(PersistentMailboxStore::open(":memory:", config).unwrap());
    let routing_key = RoutingKey::from_bytes([1u8; 16]);

    store
        .enqueue(routing_key, create_test_envelope(routing_key, 16))
        .unwrap();
    store
        .enqueue(routing_key, create_test_envelope(routing_key, 24))
        .unwrap();

    let (url, _handle) = start_test_node(store).await;
    let response = fetch_json(&url, &routing_key, &[("limit", "1")]).await;

    assert!(response.status().is_success());
    let body: Value = response.json().await.expect("Failed to parse response");

    assert_eq!(
        body["payloads"].as_array().map(Vec::len),
        Some(1),
        "Fetch limit should cap returned payloads"
    );
    assert_eq!(
        body["has_more"].as_bool(),
        Some(true),
        "Limited response should advertise continuation"
    );
    assert!(
        body["next_cursor"].as_str().is_some(),
        "Limited response should include next_cursor"
    );
}

#[tokio::test]
async fn test_fetch_after_cursor_returns_next_page_without_overlap() {
    let config = PersistentStoreConfig::default();
    let store = Arc::new(PersistentMailboxStore::open(":memory:", config).unwrap());
    let routing_key = RoutingKey::from_bytes([5u8; 16]);

    let first_envelope = create_test_envelope(routing_key, 16);
    let second_envelope = create_test_envelope(routing_key, 24);
    let expected_first = first_envelope.clone();
    let expected_second = second_envelope.clone();

    store.enqueue(routing_key, first_envelope).unwrap();
    store.enqueue(routing_key, second_envelope).unwrap();

    let (url, _handle) = start_test_node(store).await;
    let first_response = fetch_json(&url, &routing_key, &[("limit", "1")]).await;
    let first_body: Value = first_response
        .json()
        .await
        .expect("Failed to parse response");
    let cursor = first_body["next_cursor"]
        .as_str()
        .expect("first page should include next_cursor")
        .to_string();

    let first_payload = first_body["payloads"]
        .as_array()
        .and_then(|payloads| payloads.first())
        .and_then(|payload| payload.as_str())
        .expect("first page should contain one payload");
    assert_eq!(decode_message_payload(first_payload), expected_first);

    let second_response =
        fetch_json(&url, &routing_key, &[("limit", "1"), ("after", &cursor)]).await;
    let second_body: Value = second_response
        .json()
        .await
        .expect("Failed to parse response");
    let second_payload = second_body["payloads"]
        .as_array()
        .and_then(|payloads| payloads.first())
        .and_then(|payload| payload.as_str())
        .expect("second page should contain one payload");

    assert_eq!(decode_message_payload(second_payload), expected_second);
    assert_ne!(first_payload, second_payload, "pages should not overlap");
}

#[tokio::test]
async fn test_fetch_rejects_zero_limit() {
    let config = PersistentStoreConfig::default();
    let store = Arc::new(PersistentMailboxStore::open(":memory:", config).unwrap());
    let routing_key = RoutingKey::from_bytes([2u8; 16]);

    store
        .enqueue(routing_key, create_test_envelope(routing_key, 16))
        .unwrap();

    let (url, _handle) = start_test_node(store).await;
    let response = fetch_json(&url, &routing_key, &[("limit", "0")]).await;

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("limit")),
        "Expected limit validation error, got {body:?}"
    );
}

#[tokio::test]
async fn test_fetch_rejects_non_numeric_limit() {
    let config = PersistentStoreConfig::default();
    let store = Arc::new(PersistentMailboxStore::open(":memory:", config).unwrap());
    let routing_key = RoutingKey::from_bytes([6u8; 16]);

    store
        .enqueue(routing_key, create_test_envelope(routing_key, 16))
        .unwrap();

    let (url, _handle) = start_test_node(store).await;
    let response = fetch_json(&url, &routing_key, &[("limit", "bogus")]).await;

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("limit")),
        "Expected limit validation error, got {body:?}"
    );
}

#[tokio::test]
async fn test_fetch_rejects_invalid_after_cursor() {
    let config = PersistentStoreConfig::default();
    let store = Arc::new(PersistentMailboxStore::open(":memory:", config).unwrap());
    let routing_key = RoutingKey::from_bytes([3u8; 16]);

    store
        .enqueue(routing_key, create_test_envelope(routing_key, 16))
        .unwrap();

    let (url, _handle) = start_test_node(store).await;
    let response = fetch_json(&url, &routing_key, &[("after", "not-a-row-id")]).await;

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("after")),
        "Expected cursor validation error, got {body:?}"
    );
}

#[tokio::test]
async fn test_fetch_rejects_non_positive_after_cursor() {
    let config = PersistentStoreConfig::default();
    let store = Arc::new(PersistentMailboxStore::open(":memory:", config).unwrap());
    let routing_key = RoutingKey::from_bytes([7u8; 16]);

    store
        .enqueue(routing_key, create_test_envelope(routing_key, 16))
        .unwrap();

    let (url, _handle) = start_test_node(store).await;
    let response = fetch_json(&url, &routing_key, &[("after", "0")]).await;

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("after")),
        "Expected cursor validation error, got {body:?}"
    );
}

#[tokio::test]
async fn test_fetch_response_truncates_to_byte_budget_and_continues() {
    let config = PersistentStoreConfig::default();
    let store = Arc::new(PersistentMailboxStore::open(":memory:", config).unwrap());
    let routing_key = RoutingKey::from_bytes([8u8; 16]);

    let first_envelope = create_test_envelope(routing_key, 32_000);
    let second_envelope = create_test_envelope(routing_key, 32_000);
    let expected_first = first_envelope.clone();
    let expected_second = second_envelope.clone();

    store.enqueue(routing_key, first_envelope).unwrap();
    store.enqueue(routing_key, second_envelope).unwrap();

    let (url, _handle) = start_test_node(store).await;
    let first_response = fetch_json(&url, &routing_key, &[("limit", "2")]).await;

    assert!(first_response.status().is_success());
    let first_body: Value = first_response
        .json()
        .await
        .expect("Failed to parse response");
    assert_eq!(
        first_body["payloads"].as_array().map(Vec::len),
        Some(1),
        "byte budget should truncate oversized multi-message pages"
    );
    assert_eq!(first_body["has_more"].as_bool(), Some(true));

    let cursor = first_body["next_cursor"]
        .as_str()
        .expect("truncated response should include next_cursor")
        .to_string();
    let first_payload = first_body["payloads"]
        .as_array()
        .and_then(|payloads| payloads.first())
        .and_then(|payload| payload.as_str())
        .expect("first page should contain one payload");
    assert_eq!(decode_message_payload(first_payload), expected_first);

    let second_response =
        fetch_json(&url, &routing_key, &[("limit", "2"), ("after", &cursor)]).await;
    assert!(second_response.status().is_success());
    let second_body: Value = second_response
        .json()
        .await
        .expect("Failed to parse response");
    assert_eq!(second_body["payloads"].as_array().map(Vec::len), Some(1));
    assert_eq!(second_body["has_more"].as_bool(), Some(false));

    let second_payload = second_body["payloads"]
        .as_array()
        .and_then(|payloads| payloads.first())
        .and_then(|payload| payload.as_str())
        .expect("second page should contain one payload");
    assert_eq!(decode_message_payload(second_payload), expected_second);
}

#[tokio::test]
async fn test_fetch_rejects_single_payload_larger_than_byte_budget() {
    let config = PersistentStoreConfig::default();
    let store = Arc::new(PersistentMailboxStore::open(":memory:", config).unwrap());
    let routing_key = RoutingKey::from_bytes([9u8; 16]);

    store
        .enqueue(routing_key, create_test_envelope(routing_key, 50_000))
        .unwrap();

    let (url, _handle) = start_test_node(store).await;
    let response = fetch_json(&url, &routing_key, &[]).await;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    let body: Value = response.json().await.expect("Failed to parse response");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("exceeds maximum response size")),
        "Expected oversized payload error, got {body:?}"
    );
}

#[tokio::test]
async fn test_fetch_response_is_wire_payload_messages() {
    let config = PersistentStoreConfig::default();
    let store = Arc::new(PersistentMailboxStore::open(":memory:", config).unwrap());
    let routing_key = RoutingKey::from_bytes([4u8; 16]);

    let expected_envelope = create_test_envelope(routing_key, 32);
    store
        .enqueue(routing_key, expected_envelope.clone())
        .unwrap();

    let (url, _handle) = start_test_node(store).await;
    let response = fetch_json(&url, &routing_key, &[]).await;

    assert!(response.status().is_success());
    let body: Value = response.json().await.expect("Failed to parse response");
    let payloads = body["payloads"]
        .as_array()
        .expect("payloads should be an array");
    let first_payload = payloads[0]
        .as_str()
        .expect("payload should be a base64 string");
    assert_eq!(decode_message_payload(first_payload), expected_envelope);
}
