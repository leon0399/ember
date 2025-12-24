//! Embedded HTTP server for receiving messages from LAN peers.
//!
//! This server only accepts messages addressed to this client (matching routing_key).
//! Messages for other recipients are rejected with 403 Forbidden.
//!
//! # Security Model
//!
//! - Only accepts messages with matching `routing_key` (derived from our PublicID)
//! - Rejects tombstones (tombstones are for quorum nodes, not P2P)
//! - Body size limited to 256 KiB
//! - No relay support (deferred to future phase)

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use base64::prelude::*;
use reme_message::{RoutingKey, WirePayload};
use reme_node_core::EmbeddedNodeHandle;
use serde::Serialize;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{debug, error, info, warn};

/// Shared state for HTTP handlers.
#[derive(Clone)]
pub struct HttpServerState {
    /// Handle to the embedded node for storing messages.
    pub node_handle: EmbeddedNodeHandle,
    /// Our routing key - only accept messages addressed to us.
    pub our_routing_key: RoutingKey,
}

/// Response for successful submission.
#[derive(Serialize)]
struct SubmitResponse {
    status: &'static str,
}

/// Response for errors.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// POST /api/v1/submit - Accept messages from LAN peers
async fn submit_handler(
    State(state): State<Arc<HttpServerState>>,
    body: String,
) -> Result<Json<SubmitResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Decode base64 payload
    let wire_bytes = BASE64_STANDARD.decode(body.trim()).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid base64: {}", e),
            }),
        )
    })?;

    // Parse WirePayload
    let payload = WirePayload::decode(&wire_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid payload: {}", e),
            }),
        )
    })?;

    // Extract OuterEnvelope (reject tombstones from peers)
    let envelope = match payload {
        WirePayload::Message(env) => env,
        WirePayload::Tombstone(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Tombstones not accepted via direct peer API".to_string(),
                }),
            ));
        }
    };

    // === ROUTING KEY VALIDATION ===
    // Only accept messages addressed to us. Reject messages for other recipients
    // to prevent storage pollution and provide fail-fast behavior.
    if envelope.routing_key != state.our_routing_key {
        warn!(
            expected = %hex::encode(state.our_routing_key.as_bytes()),
            received = %hex::encode(envelope.routing_key.as_bytes()),
            "Rejecting message: routing key mismatch"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Message not intended for this recipient".to_string(),
            }),
        ));
    }

    debug!(message_id = ?envelope.message_id, "Accepted message from LAN peer");

    // Store and notify client
    state.node_handle.notify_message_received(envelope).map_err(|e| {
        error!("Failed to store message: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to store message".to_string(),
            }),
        )
    })?;

    Ok(Json(SubmitResponse { status: "ok" }))
}

/// Health check endpoint
async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

/// Build the Axum router.
pub fn build_router(state: Arc<HttpServerState>) -> Router {
    Router::new()
        .route("/api/v1/submit", post(submit_handler))
        .route("/health", axum::routing::get(health_handler))
        .layer(RequestBodyLimitLayer::new(256 * 1024)) // 256 KiB max
        .with_state(state)
}

/// Start the HTTP server for receiving messages from LAN peers.
///
/// This function blocks until the server is shut down (typically when the
/// client exits). It should be spawned as a background task.
///
/// # Arguments
///
/// * `bind_addr` - Address to bind to (e.g., "0.0.0.0:23004")
/// * `node_handle` - Handle to the embedded node for storing received messages
/// * `our_routing_key` - Our routing key; messages for other recipients are rejected
pub async fn start_server(
    bind_addr: &str,
    node_handle: EmbeddedNodeHandle,
    our_routing_key: RoutingKey,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(HttpServerState {
        node_handle,
        our_routing_key,
    });
    let app = build_router(state);

    let listener = TcpListener::bind(bind_addr).await?;
    info!(addr = %bind_addr, "Embedded HTTP server started for LAN P2P");

    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use reme_message::{MessageID, OuterEnvelope, CURRENT_VERSION};
    use reme_node_core::{EmbeddedNode, PersistentMailboxStore, PersistentStoreConfig};
    use tower::ServiceExt;

    fn create_test_envelope(routing_key: RoutingKey) -> OuterEnvelope {
        OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: 482253,
            ttl_hours: Some(24),
            message_id: MessageID::new(),
            ephemeral_key: [0u8; 32],
            inner_ciphertext: vec![1, 2, 3, 4],
        }
    }

    #[tokio::test]
    async fn test_submit_valid_message() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let (_node, handle, _event_rx) = EmbeddedNode::new(store);

        let our_routing_key = RoutingKey::from_bytes([42u8; 16]);
        let state = Arc::new(HttpServerState {
            node_handle: handle,
            our_routing_key,
        });
        let app = build_router(state);

        // Create envelope for us
        let envelope = create_test_envelope(our_routing_key);
        let wire_payload = WirePayload::Message(envelope);
        let body = BASE64_STANDARD.encode(wire_payload.encode());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/submit")
                    .header("content-type", "text/plain")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_reject_wrong_routing_key() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let (_node, handle, _event_rx) = EmbeddedNode::new(store);

        let our_routing_key = RoutingKey::from_bytes([42u8; 16]);
        let wrong_routing_key = RoutingKey::from_bytes([99u8; 16]);
        let state = Arc::new(HttpServerState {
            node_handle: handle,
            our_routing_key,
        });
        let app = build_router(state);

        // Create envelope for someone else
        let envelope = create_test_envelope(wrong_routing_key);
        let wire_payload = WirePayload::Message(envelope);
        let body = BASE64_STANDARD.encode(wire_payload.encode());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/submit")
                    .header("content-type", "text/plain")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_reject_tombstone() {
        use reme_identity::Identity;
        use reme_message::TombstoneEnvelope;

        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let (_node, handle, _event_rx) = EmbeddedNode::new(store);

        let our_routing_key = RoutingKey::from_bytes([42u8; 16]);
        let state = Arc::new(HttpServerState {
            node_handle: handle,
            our_routing_key,
        });
        let app = build_router(state);

        // Create tombstone
        let recipient = Identity::generate();
        let tombstone = TombstoneEnvelope {
            version: CURRENT_VERSION,
            target_message_id: MessageID::new(),
            routing_key: our_routing_key,
            recipient_id_pub: recipient.public_id().to_bytes(),
            device_id: [1u8; 16],
            timestamp_hours: 482253,
            sequence: 1,
            signature: [0u8; 64],
            encrypted_receipt: None,
        };
        let wire_payload = WirePayload::Tombstone(tombstone);
        let body = BASE64_STANDARD.encode(wire_payload.encode());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/submit")
                    .header("content-type", "text/plain")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let (_node, handle, _event_rx) = EmbeddedNode::new(store);

        let our_routing_key = RoutingKey::from_bytes([42u8; 16]);
        let state = Arc::new(HttpServerState {
            node_handle: handle,
            our_routing_key,
        });
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
