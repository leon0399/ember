//! Embedded HTTP server for receiving messages from LAN peers.
//!
//! This server only accepts messages addressed to this client (matching `routing_key`).
//! Messages for other recipients are rejected with 403 Forbidden.
//!
//! # Security Model
//!
//! - Only accepts messages with matching `routing_key` (derived from our `PublicID`)
//! - Rejects tombstones (tombstones are for quorum nodes, not P2P)
//! - Rejects duplicate messages (idempotent operation)
//! - Body size limited to 256 KiB
//! - No relay support (deferred to future phase)

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use base64::prelude::*;
use reme_encryption::derive_ack_secret;
use reme_identity::{is_low_order_point, Identity};
use reme_message::{MessageID, OuterEnvelope, RoutingKey, WirePayload};
use reme_node_core::{EmbeddedNodeHandle, NodeError};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{debug, error, info, warn};
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::Zeroize;

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

/// API error type for HTTP handlers.
///
/// Implements `IntoResponse` for clean error-to-HTTP-response conversion.
#[derive(Debug)]
enum ApiError {
    /// Invalid request format (base64, wire format, etc.)
    BadRequest(String),
    /// Message not intended for this recipient
    Forbidden,
    /// Internal storage or processing error
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Forbidden => (
                StatusCode::FORBIDDEN,
                "Message not intended for this recipient".to_string(),
            ),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        (
            status,
            Json(ErrorResponse {
                error: error_message,
            }),
        )
            .into_response()
    }
}

/// Shared state for HTTP handlers.
#[derive(Clone)]
pub struct HttpServerState {
    node_handle: EmbeddedNodeHandle,
    our_routing_key: RoutingKey,
    identity: Arc<Identity>,
}

impl HttpServerState {
    /// Create new HTTP server state.
    pub fn new(
        node_handle: EmbeddedNodeHandle,
        our_routing_key: RoutingKey,
        identity: Arc<Identity>,
    ) -> Self {
        Self {
            node_handle,
            our_routing_key,
            identity,
        }
    }

    /// Check if a message is addressed to this client.
    pub fn is_for_us(&self, routing_key: &RoutingKey) -> bool {
        *routing_key == self.our_routing_key
    }

    /// Check if a message is a duplicate (already stored).
    ///
    /// Returns `Ok(true)` if already stored, `Ok(false)` if not stored,
    /// or `Err` if the check failed (database error).
    pub fn is_duplicate(&self, envelope: &OuterEnvelope) -> Result<bool, NodeError> {
        self.node_handle
            .has_message(&envelope.routing_key, &envelope.message_id)
    }

    /// Store a message and notify the client.
    pub fn store_message(&self, envelope: OuterEnvelope) -> Result<(), reme_node_core::NodeError> {
        self.node_handle.notify_message_received(envelope)
    }

    /// Get our routing key (for logging/diagnostics).
    pub fn our_routing_key(&self) -> &RoutingKey {
        &self.our_routing_key
    }

    /// Derive a signed receipt for an envelope (embedded node is always the recipient).
    ///
    /// Returns `None` if:
    /// - The ephemeral key is a known low-order point (security check)
    /// - The ECDH result is all-zero (defense-in-depth)
    ///
    /// The receipt includes:
    /// - `ack_secret`: proves the node can decrypt the message
    /// - `signature`: XEdDSA signature over `"reme-receipt-v1:" || signer_pubkey || message_id || ack_secret`
    fn derive_receipt_for_envelope(&self, envelope: &OuterEnvelope) -> Option<Receipt> {
        // Pre-validation: reject known low-order points before ECDH
        if is_low_order_point(&envelope.ephemeral_key) {
            debug!(
                message_id = ?envelope.message_id,
                "Rejected low-order ephemeral key in receipt derivation"
            );
            return None;
        }

        let ephemeral_key = X25519PublicKey::from(envelope.ephemeral_key);
        let shared_secret = self.identity.x25519_secret().diffie_hellman(&ephemeral_key);

        // Defense-in-depth: reject all-zero shared secrets (indicates small-order input)
        // Use constant-time comparison to prevent timing side-channels
        let bytes = shared_secret.as_bytes();
        if bool::from(bytes.ct_eq(&[0u8; 32])) {
            debug!(
                message_id = ?envelope.message_id,
                "Rejected all-zero shared secret in receipt derivation"
            );
            return None;
        }

        let ack_secret = derive_ack_secret(bytes, &envelope.message_id);

        // Sign with domain separation: "reme-receipt-v1:" || signer_pubkey || message_id || ack_secret
        // This prevents cross-protocol signature confusion and binds the signature to the signer
        const DOMAIN_SEP: &[u8] = b"reme-receipt-v1:";
        let signer_pubkey = self.identity.public_id().to_bytes();
        let mut sign_data = Vec::with_capacity(DOMAIN_SEP.len() + 32 + 16 + 16);
        sign_data.extend_from_slice(DOMAIN_SEP);
        sign_data.extend_from_slice(&signer_pubkey);
        sign_data.extend_from_slice(envelope.message_id.as_bytes());
        sign_data.extend_from_slice(&ack_secret);
        let signature = self.identity.sign_xeddsa(&sign_data);

        // Zeroize sensitive intermediate data
        sign_data.zeroize();

        Some(Receipt {
            ack_secret: BASE64_STANDARD.encode(ack_secret),
            signature: BASE64_STANDARD.encode(signature),
        })
    }
}

/// Receipt proving node received and can decrypt a message.
struct Receipt {
    /// Base64-encoded 16-byte ack_secret
    ack_secret: String,
    /// Base64-encoded 64-byte XEdDSA signature over:
    /// "reme-receipt-v1:" || signer_pubkey || message_id || ack_secret
    signature: String,
}

/// Response for successful submission.
#[derive(Serialize)]
struct SubmitResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ack_secret: Option<String>,
    /// XEdDSA signature proving node identity.
    /// Signed data: `"reme-receipt-v1:" || signer_pubkey || message_id || ack_secret`
    /// Present only when ack_secret is present.
    /// Base64-encoded 64-byte signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
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
) -> Result<Json<SubmitResponse>, ApiError> {
    // Decode base64 payload
    let wire_bytes = BASE64_STANDARD.decode(body.trim()).map_err(|e| {
        warn!(error = %e, "Received invalid base64 payload");
        ApiError::BadRequest("Invalid base64 encoding".to_string())
    })?;

    // Parse WirePayload
    let payload = WirePayload::decode(&wire_bytes).map_err(|e| {
        warn!(error = %e, "Received invalid wire payload");
        ApiError::BadRequest("Invalid message format".to_string())
    })?;

    // Extract OuterEnvelope (reject tombstones from peers)
    let envelope = match payload {
        WirePayload::Message(env) => env,
        WirePayload::AckTombstone(_) => {
            debug!("Rejected tombstone from LAN peer");
            return Err(ApiError::BadRequest(
                "Tombstones not accepted via direct peer API".to_string(),
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
        return Err(ApiError::Forbidden);
    }

    // === DUPLICATE CHECK ===
    // Idempotent operation: return success if already stored (but no receipt for duplicates)
    match state.is_duplicate(&envelope) {
        Ok(true) => {
            debug!(message_id = ?message_id, "Duplicate message, already stored");
            return Ok(Json(SubmitResponse {
                status: "ok",
                ack_secret: None, // No ack_secret for duplicates
                signature: None,
            }));
        }
        Ok(false) => {
            // Not a duplicate, proceed to store
        }
        Err(e) => {
            // Database error during duplicate check - log but try to store anyway
            // This handles potential transient issues while maintaining availability
            warn!(
                message_id = ?message_id,
                error = %e,
                "Duplicate check failed, attempting store anyway"
            );
        }
    }

    // Derive signed receipt BEFORE storing (we're the recipient, so we can always derive it)
    // This proves we received and can decrypt the message
    let receipt = state.derive_receipt_for_envelope(&envelope);

    // Store and notify client
    // Handle race condition: if store fails, check if it's now a duplicate
    if let Err(e) = state.store_message(envelope.clone()) {
        // Check if the message was stored by a concurrent request (race condition)
        // If so, treat as success but no receipt (duplicate)
        if is_duplicate_after_store_failure(&state, &message_id, &e) {
            debug!(
                message_id = ?message_id,
                "Store failed but message exists (concurrent insert), treating as success"
            );
            return Ok(Json(SubmitResponse {
                status: "ok",
                ack_secret: None, // No ack_secret for duplicates
                signature: None,
            }));
        }

        error!(
            message_id = ?message_id,
            error = %e,
            "Failed to store message from LAN peer"
        );
        return Err(ApiError::Internal("Failed to store message".to_string()));
    }

    // Extract receipt fields (ack_secret + signature) if present
    let (ack_secret, signature) = receipt.map(|r| (r.ack_secret, r.signature)).unzip();

    info!(message_id = ?message_id, "Message from LAN peer stored successfully");
    Ok(Json(SubmitResponse {
        status: "ok",
        ack_secret,
        signature,
    }))
}

/// Check if a store failure was due to a concurrent duplicate insert (race condition).
///
/// Returns true if the message now exists in storage, indicating another request
/// successfully stored it first. This enables idempotent behavior under concurrent load.
fn is_duplicate_after_store_failure(
    state: &HttpServerState,
    message_id: &MessageID,
    _error: &NodeError,
) -> bool {
    // Re-check if message exists - if a concurrent request stored it, treat as success
    // We create a temporary envelope just for the lookup (only routing_key + message_id matter)
    let check_envelope = OuterEnvelope {
        version: reme_message::CURRENT_VERSION,
        routing_key: *state.our_routing_key(),
        message_id: *message_id,
        timestamp_hours: 0,
        ttl_hours: None,
        ephemeral_key: [0u8; 32],
        ack_hash: [0u8; 16], // Zeroed for lookup-only envelope
        inner_ciphertext: vec![],
    };

    state.is_duplicate(&check_envelope).unwrap_or(false)
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
            format!("expected format like '0.0.0.0:23004': {e}"),
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
/// * `identity` - Client identity for deriving `ack_secret` (proves we can decrypt)
///
/// # Returns
///
/// A tuple of (`TcpListener`, Router) ready to be passed to `run_server`.
pub async fn bind_server(
    bind_addr: &str,
    node_handle: EmbeddedNodeHandle,
    our_routing_key: RoutingKey,
    identity: Arc<Identity>,
) -> Result<(TcpListener, Router), HttpServerError> {
    // Validate address format first for better error messages
    let socket_addr = validate_bind_address(bind_addr)?;

    let state = Arc::new(HttpServerState::new(node_handle, our_routing_key, identity));
    let app = build_router(state);

    let listener = TcpListener::bind(socket_addr)
        .await
        .map_err(|e| HttpServerError::BindFailed(bind_addr.to_string(), e))?;

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
/// * `identity` - Client identity for deriving `ack_secret` (proves we can decrypt)
#[allow(dead_code)] // Convenience API for future use
pub async fn start_server(
    bind_addr: &str,
    node_handle: EmbeddedNodeHandle,
    our_routing_key: RoutingKey,
    identity: Arc<Identity>,
) -> Result<(), HttpServerError> {
    let (listener, app) = bind_server(bind_addr, node_handle, our_routing_key, identity).await?;
    run_server(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use reme_encryption::encrypt_to_mik;
    use reme_message::{
        Content, InnerEnvelope, MessageID, OuterEnvelope, TextContent, CURRENT_VERSION,
    };
    use reme_node_core::{EmbeddedNode, PersistentMailboxStore, PersistentStoreConfig};
    use tower::ServiceExt;

    /// Create a simple test envelope with zeroed ephemeral key (won't validate for `ack_secret`)
    fn create_test_envelope(routing_key: RoutingKey) -> OuterEnvelope {
        OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key,
            timestamp_hours: 482_253,
            ttl_hours: Some(24),
            message_id: MessageID::new(),
            ephemeral_key: [0u8; 32], // Low-order point - ack_secret will be None
            ack_hash: [0u8; 16],
            inner_ciphertext: vec![1, 2, 3, 4],
        }
    }

    /// Create a properly encrypted envelope that can derive `ack_secret`
    #[allow(clippy::cast_possible_truncation)] // Test helper, ms since epoch fits in u64
    fn create_encrypted_envelope(
        sender: &Identity,
        recipient_pubkey: &reme_identity::PublicID,
    ) -> (OuterEnvelope, [u8; 16]) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
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

        let message_id = MessageID::new();
        let enc_output = encrypt_to_mik(&inner, recipient_pubkey, &message_id, &sender.to_bytes())
            .expect("Encryption failed");

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

    #[tokio::test]
    async fn test_submit_valid_message() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let (_node, handle, _event_rx) = EmbeddedNode::new(store);

        // Create identity for the embedded node
        let identity = Identity::generate();
        let our_routing_key = identity.public_id().routing_key();
        let state = Arc::new(HttpServerState::new(
            handle,
            our_routing_key,
            Arc::new(identity),
        ));
        let app = build_router(state);

        // Create envelope for us (with zeroed ephemeral key - no ack_secret)
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

        let identity = Identity::generate();
        let our_routing_key = identity.public_id().routing_key();
        let wrong_routing_key = RoutingKey::from_bytes([99u8; 16]);
        let state = Arc::new(HttpServerState::new(
            handle,
            our_routing_key,
            Arc::new(identity),
        ));
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
        use reme_message::SignedAckTombstone;

        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let (_node, handle, _event_rx) = EmbeddedNode::new(store);

        let identity = Identity::generate();
        let our_routing_key = identity.public_id().routing_key();
        let state = Arc::new(HttpServerState::new(
            handle,
            our_routing_key,
            Arc::new(identity),
        ));
        let app = build_router(state);

        // Create tombstone (V2)
        let signer = Identity::generate();
        let tombstone = SignedAckTombstone::new(
            MessageID::new(),
            [0u8; 16], // ack_secret
            &signer.to_bytes(),
        );
        let wire_payload = WirePayload::AckTombstone(tombstone);
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

        let identity = Identity::generate();
        let our_routing_key = identity.public_id().routing_key();
        let state = Arc::new(HttpServerState::new(
            handle,
            our_routing_key,
            Arc::new(identity),
        ));
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

        let identity = Identity::generate();
        let our_routing_key = identity.public_id().routing_key();
        let state = Arc::new(HttpServerState::new(
            handle,
            our_routing_key,
            Arc::new(identity),
        ));
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

    /// Test: Embedded node returns valid signed receipt for properly encrypted messages
    #[tokio::test]
    async fn test_returns_signed_receipt_for_encrypted_message() {
        use reme_encryption::derive_ack_hash;

        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let (_node, handle, _event_rx) = EmbeddedNode::new(store);

        // Create identity for the embedded node (recipient)
        let recipient_identity = Identity::generate();
        let recipient_pubkey = *recipient_identity.public_id();
        let our_routing_key = recipient_identity.public_id().routing_key();

        let state = Arc::new(HttpServerState::new(
            handle,
            our_routing_key,
            Arc::new(recipient_identity),
        ));
        let app = build_router(state);

        // Create sender and properly encrypted envelope
        let sender = Identity::generate();
        let (envelope, expected_ack_secret) = create_encrypted_envelope(&sender, &recipient_pubkey);
        let ack_hash = envelope.ack_hash;
        let message_id = envelope.message_id;

        let wire_payload = WirePayload::Message(envelope);
        let body = BASE64_STANDARD.encode(wire_payload.encode());

        // Submit message
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

        // Parse response body
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let response_json: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("Invalid JSON response");

        // Should have ack_secret
        assert!(
            response_json.get("ack_secret").is_some(),
            "Response should contain ack_secret"
        );
        let returned_ack_secret_b64 = response_json["ack_secret"].as_str().unwrap();
        let returned_ack_secret: [u8; 16] = BASE64_STANDARD
            .decode(returned_ack_secret_b64)
            .expect("Invalid base64")
            .try_into()
            .expect("Wrong length");

        // Verify ack_secret is correct
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
            response_json.get("signature").is_some(),
            "Response should contain signature"
        );
        let signature_b64 = response_json["signature"].as_str().unwrap();
        let signature: [u8; 64] = BASE64_STANDARD
            .decode(signature_b64)
            .expect("Invalid signature base64")
            .try_into()
            .expect("Wrong signature length");

        // Reconstruct signed message with domain separation
        // Format: "reme-receipt-v1:" || signer_pubkey || message_id || ack_secret
        const DOMAIN_SEP: &[u8] = b"reme-receipt-v1:";
        let mut sign_data = Vec::with_capacity(DOMAIN_SEP.len() + 32 + 16 + 16);
        sign_data.extend_from_slice(DOMAIN_SEP);
        sign_data.extend_from_slice(&recipient_pubkey.to_bytes());
        sign_data.extend_from_slice(message_id.as_bytes());
        sign_data.extend_from_slice(&returned_ack_secret);

        // Verify using recipient's public key
        assert!(
            recipient_pubkey.verify_xeddsa(&sign_data, &signature),
            "Signature should verify with recipient's public key"
        );
    }

    /// Test: Low-order ephemeral key returns no `ack_secret` (security check)
    #[tokio::test]
    async fn test_low_order_ephemeral_key_returns_no_ack_secret() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let (_node, handle, _event_rx) = EmbeddedNode::new(store);

        let identity = Identity::generate();
        let our_routing_key = identity.public_id().routing_key();
        let state = Arc::new(HttpServerState::new(
            handle,
            our_routing_key,
            Arc::new(identity),
        ));
        let app = build_router(state);

        // Create envelope with low-order ephemeral key (zeroed = low-order point)
        let envelope = create_test_envelope(our_routing_key); // Uses [0u8; 32] ephemeral key
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

        // Parse response body
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let response_json: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("Invalid JSON response");

        // Should NOT have ack_secret (low-order point rejected)
        assert!(
            response_json.get("ack_secret").is_none() || response_json["ack_secret"].is_null(),
            "Low-order ephemeral key should NOT produce ack_secret"
        );
    }

    /// Test: Duplicate message returns no `ack_secret`
    #[tokio::test]
    async fn test_duplicate_returns_no_ack_secret() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let (_node, handle, _event_rx) = EmbeddedNode::new(store);

        let recipient_identity = Identity::generate();
        let recipient_pubkey = *recipient_identity.public_id();
        let our_routing_key = recipient_identity.public_id().routing_key();

        let state = Arc::new(HttpServerState::new(
            handle,
            our_routing_key,
            Arc::new(recipient_identity),
        ));
        let app = build_router(state);

        // Create properly encrypted envelope
        let sender = Identity::generate();
        let (envelope, _) = create_encrypted_envelope(&sender, &recipient_pubkey);
        let wire_payload = WirePayload::Message(envelope);
        let body = BASE64_STANDARD.encode(wire_payload.encode());

        // First submission - should have ack_secret
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

        let body_bytes1 = axum::body::to_bytes(response1.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let response_json1: serde_json::Value =
            serde_json::from_slice(&body_bytes1).expect("Invalid JSON");
        assert!(
            response_json1.get("ack_secret").is_some(),
            "First submit should return ack_secret"
        );

        // Second submission (duplicate) - should NOT have ack_secret
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

        let body_bytes2 = axum::body::to_bytes(response2.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let response_json2: serde_json::Value =
            serde_json::from_slice(&body_bytes2).expect("Invalid JSON");
        assert!(
            response_json2.get("ack_secret").is_none() || response_json2["ack_secret"].is_null(),
            "Duplicate submit should NOT return ack_secret"
        );
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
