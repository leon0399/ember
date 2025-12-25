//! Embedded HTTP server for receiving messages from LAN peers.
//!
//! This server only accepts messages addressed to this client (matching routing_key).
//! Messages for other recipients are rejected with 403 Forbidden.
//!
//! # Security Model
//!
//! - Only accepts messages with matching `routing_key` (derived from our PublicID)
//! - Rejects tombstones (tombstones are for quorum nodes, not P2P)
//! - Rejects duplicate messages (idempotent operation)
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
use reme_message::{OuterEnvelope, RoutingKey, WirePayload};
use reme_node_core::EmbeddedNodeHandle;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{debug, error, info, warn};

/// Error types for HTTP server operations.
#[derive(Debug, thiserror::Error)]
pub enum HttpServerError {
    #[error("Invalid bind address '{0}': {1}")]
    InvalidBindAddress(String, String),

    #[error("Failed to bind to {0}: {1}")]
    BindFailed(String, std::io::Error),

    #[error("Server error: {0}")]
    ServerError(#[from] std::io::Error),
}

/// Shared state for HTTP handlers.
#[derive(Clone)]
pub struct HttpServerState {
    node_handle: EmbeddedNodeHandle,
    our_routing_key: RoutingKey,
}

impl HttpServerState {
    /// Create new HTTP server state.
    pub fn new(node_handle: EmbeddedNodeHandle, our_routing_key: RoutingKey) -> Self {
        Self {
            node_handle,
            our_routing_key,
        }
    }

    /// Check if a message is addressed to this client.
    pub fn is_for_us(&self, routing_key: &RoutingKey) -> bool {
        *routing_key == self.our_routing_key
    }

    /// Check if a message is a duplicate (already stored).
    pub fn is_duplicate(&self, envelope: &OuterEnvelope) -> bool {
        self.node_handle
            .has_message(&envelope.routing_key, &envelope.message_id)
            .unwrap_or(false)
    }

    /// Store a message and notify the client.
    pub fn store_message(&self, envelope: OuterEnvelope) -> Result<(), reme_node_core::NodeError> {
        self.node_handle.notify_message_received(envelope)
    }

    /// Get our routing key (for logging/diagnostics).
    pub fn our_routing_key(&self) -> &RoutingKey {
        &self.our_routing_key
    }
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

/// Response for health check endpoint.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

/// POST /api/v1/submit - Accept messages from LAN peers
async fn submit_handler(
    State(state): State<Arc<HttpServerState>>,
    body: String,
) -> Result<Json<SubmitResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Decode base64 payload
    let wire_bytes = BASE64_STANDARD.decode(body.trim()).map_err(|e| {
        warn!(error = %e, "Received invalid base64 payload");
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid base64 encoding".to_string(),
            }),
        )
    })?;

    // Parse WirePayload
    let payload = WirePayload::decode(&wire_bytes).map_err(|e| {
        warn!(error = %e, "Received invalid wire payload");
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid message format".to_string(),
            }),
        )
    })?;

    // Extract OuterEnvelope (reject tombstones from peers)
    let envelope = match payload {
        WirePayload::Message(env) => env,
        WirePayload::Tombstone(_) => {
            debug!("Rejected tombstone from LAN peer");
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Tombstones not accepted via direct peer API".to_string(),
                }),
            ));
        }
    };

    let message_id = envelope.message_id;

    // === ROUTING KEY VALIDATION ===
    // Only accept messages addressed to us. Reject messages for other recipients
    // to prevent storage pollution and provide fail-fast behavior.
    if !state.is_for_us(&envelope.routing_key) {
        warn!(
            message_id = ?message_id,
            expected = %hex::encode(state.our_routing_key().as_bytes()),
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

    // === DUPLICATE CHECK ===
    // Idempotent operation: return success if already stored
    if state.is_duplicate(&envelope) {
        debug!(message_id = ?message_id, "Duplicate message, already stored");
        return Ok(Json(SubmitResponse { status: "ok" }));
    }

    // Store and notify client
    state.store_message(envelope).map_err(|e| {
        error!(
            message_id = ?message_id,
            error = %e,
            "Failed to store message from LAN peer"
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to store message".to_string(),
            }),
        )
    })?;

    info!(message_id = ?message_id, "Message from LAN peer stored successfully");
    Ok(Json(SubmitResponse { status: "ok" }))
}

/// Health check endpoint
async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Build the Axum router.
pub fn build_router(state: Arc<HttpServerState>) -> Router {
    Router::new()
        .route("/api/v1/submit", post(submit_handler))
        .route("/health", axum::routing::get(health_handler))
        .layer(RequestBodyLimitLayer::new(256 * 1024)) // 256 KiB max
        .with_state(state)
}

/// Validate and parse a bind address.
fn validate_bind_address(bind_addr: &str) -> Result<SocketAddr, HttpServerError> {
    if bind_addr.is_empty() {
        return Err(HttpServerError::InvalidBindAddress(
            bind_addr.to_string(),
            "address cannot be empty".to_string(),
        ));
    }

    bind_addr.parse::<SocketAddr>().map_err(|e| {
        HttpServerError::InvalidBindAddress(
            bind_addr.to_string(),
            format!("expected format like '0.0.0.0:23004': {}", e),
        )
    })
}

/// Bind the HTTP server and return the listener and router.
///
/// This separates binding from serving, allowing callers to verify the bind
/// succeeded before spawning the server task.
///
/// # Arguments
///
/// * `bind_addr` - Address to bind to (e.g., "0.0.0.0:23004")
/// * `node_handle` - Handle to the embedded node for storing received messages
/// * `our_routing_key` - Our routing key; messages for other recipients are rejected
///
/// # Returns
///
/// A tuple of (TcpListener, Router) ready to be passed to `run_server`.
pub async fn bind_server(
    bind_addr: &str,
    node_handle: EmbeddedNodeHandle,
    our_routing_key: RoutingKey,
) -> Result<(TcpListener, Router), HttpServerError> {
    // Validate address format first for better error messages
    let socket_addr = validate_bind_address(bind_addr)?;

    let state = Arc::new(HttpServerState::new(node_handle, our_routing_key));
    let app = build_router(state);

    let listener = TcpListener::bind(socket_addr).await.map_err(|e| {
        HttpServerError::BindFailed(bind_addr.to_string(), e)
    })?;

    Ok((listener, app))
}

/// Run the HTTP server with a pre-bound listener.
///
/// This function blocks until the server is shut down.
pub async fn run_server(listener: TcpListener, app: Router) -> Result<(), HttpServerError> {
    let local_addr = listener.local_addr()?;
    info!(addr = %local_addr, "Embedded HTTP server listening for LAN P2P");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Start the HTTP server for receiving messages from LAN peers.
///
/// This is a convenience function that combines `bind_server` and `run_server`.
/// For production use, prefer calling them separately to verify binding before
/// spawning the server task.
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
) -> Result<(), HttpServerError> {
    let (listener, app) = bind_server(bind_addr, node_handle, our_routing_key).await?;
    run_server(listener, app).await
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
        let state = Arc::new(HttpServerState::new(handle, our_routing_key));
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
        let state = Arc::new(HttpServerState::new(handle, our_routing_key));
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
        let state = Arc::new(HttpServerState::new(handle, our_routing_key));
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
        let state = Arc::new(HttpServerState::new(handle, our_routing_key));
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

    #[tokio::test]
    async fn test_duplicate_message_idempotent() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let (_node, handle, _event_rx) = EmbeddedNode::new(store);

        let our_routing_key = RoutingKey::from_bytes([42u8; 16]);
        let state = Arc::new(HttpServerState::new(handle, our_routing_key));
        let app = build_router(state);

        // Create envelope for us with a fixed message ID
        let envelope = create_test_envelope(our_routing_key);
        let wire_payload = WirePayload::Message(envelope);
        let body = BASE64_STANDARD.encode(wire_payload.encode());

        // First submission should succeed
        let response1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/submit")
                    .header("content-type", "text/plain")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response1.status(), StatusCode::OK);

        // Second submission of same message should also succeed (idempotent)
        let response2 = app
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
        assert_eq!(response2.status(), StatusCode::OK);
    }

    #[test]
    fn test_validate_bind_address() {
        // Valid addresses
        assert!(validate_bind_address("0.0.0.0:23004").is_ok());
        assert!(validate_bind_address("127.0.0.1:8080").is_ok());
        assert!(validate_bind_address("[::]:23004").is_ok());

        // Invalid addresses
        assert!(validate_bind_address("").is_err());
        assert!(validate_bind_address("not-an-address").is_err());
        assert!(validate_bind_address("127.0.0.1").is_err()); // missing port
    }
}
