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
//! - Body size limited to 512 KiB
//! - No relay support (deferred to future phase)
//!
//! # Receipt Signatures
//!
//! On first successful message submission, the server returns a signed receipt:
//! - `signature`: `XEdDSA` signature over `"reme-receipt-v1:" || signer_pubkey || message_id`
//! - `ack_secret`: Only present if ECDH derivation succeeds (proves decryption capability)
//!
//! The signature proves the node received the message, while `ack_secret` proves the node
//! can decrypt it. Both are base64-encoded. Duplicate submissions return neither field.

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use base64::prelude::*;
use reme_bundle::parse_body;
use reme_encryption::{build_identity_sign_data, build_receipt_sign_data, derive_ack_secret};
use reme_identity::{is_low_order_point, Identity};
use reme_message::{MessageID, OuterEnvelope, RoutingKey, WirePayload};
use reme_node_core::{EmbeddedNodeHandle, NodeError};
use serde::{Deserialize, Serialize};
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
#[allow(dead_code)] // Variants kept for API completeness; per-frame errors use FrameResult
enum ApiError {
    /// Invalid request format (bundle format, wire format, etc.)
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

    /// Generate a signed receipt for an envelope.
    ///
    /// The receipt includes:
    /// - `signature`: Always present - `XEdDSA` signature over `"reme-receipt-v1:" || signer_pubkey || message_id`
    /// - `ack_secret`: Only if ECDH derivation succeeds (not a low-order point, not all-zero result)
    ///
    /// Crypto operations (ECDH and `XEdDSA` signing) are offloaded to a blocking thread pool
    /// to avoid blocking the Tokio worker thread.
    ///
    /// Returns `None` if the blocking task panics (graceful degradation).
    async fn generate_receipt(&self, envelope: &OuterEnvelope) -> Option<Receipt> {
        // Capture owned values for spawn_blocking
        let identity = self.identity.clone();
        let ephemeral_key = envelope.ephemeral_key;
        let message_id = envelope.message_id;

        // Offload crypto-intensive operations (ECDH + signing) to thread pool
        tokio::task::spawn_blocking(move || {
            // Try to derive ack_secret (may fail for low-order points or all-zero shared secrets)
            let ack_secret = if is_low_order_point(&ephemeral_key) {
                None
            } else {
                let ephemeral_public = X25519PublicKey::from(ephemeral_key);
                let shared_secret = identity.x25519_secret().diffie_hellman(&ephemeral_public);

                // Defense-in-depth: reject all-zero shared secrets (indicates small-order input)
                // Use constant-time comparison to prevent timing side-channels
                let bytes = shared_secret.as_bytes();
                if bool::from(bytes.ct_eq(&[0u8; 32])) {
                    None
                } else {
                    Some(derive_ack_secret(bytes, &message_id))
                }
            };

            // Sign: "reme-receipt-v1:" || signer_pubkey || message_id
            // Note: signature does NOT include ack_secret (allows signing even when ECDH fails)
            let signer_pubkey = identity.public_id().to_bytes();
            let mut sign_data = build_receipt_sign_data(&signer_pubkey, &message_id);
            let signature = identity.sign_xeddsa(&sign_data);

            // Encode results
            let signature_b64 = BASE64_STANDARD.encode(signature);
            let ack_secret_b64 = ack_secret.map(|mut s| {
                let encoded = BASE64_STANDARD.encode(s);
                s.zeroize();
                encoded
            });

            // Zeroize sensitive intermediate data
            sign_data.zeroize();

            Receipt {
                ack_secret: ack_secret_b64,
                signature: signature_b64,
            }
        })
        .await
        .ok()
    }
}

/// Receipt proving node received a message.
struct Receipt {
    /// Base64-encoded 16-byte `ack_secret` (only if ECDH derivation succeeds)
    ack_secret: Option<String>,
    /// Base64-encoded 64-byte `XEdDSA` signature over:
    /// `"reme-receipt-v1:" || signer_pubkey || message_id`
    signature: String,
}

/// Response for batch submission — one result per frame.
#[derive(Debug, Serialize)]
struct SubmitResponse {
    results: Vec<FrameResult>,
}

/// Per-frame result within a batch submission response.
#[derive(Debug, Serialize)]
struct FrameResult {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ack_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl FrameResult {
    fn ok(ack_secret: Option<String>, signature: Option<String>) -> Self {
        Self {
            status: "ok".to_string(),
            ack_secret,
            signature,
            error: None,
        }
    }

    fn error(msg: impl Into<String>) -> Self {
        Self {
            status: "error".to_string(),
            ack_secret: None,
            signature: None,
            error: Some(msg.into()),
        }
    }
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

/// Response for the identity endpoint.
///
/// Privacy-preserving: returns only the signature, not the node's identity.
/// Clients verify the signature against known contacts' public keys.
#[derive(Debug, Serialize)]
struct IdentityResponse {
    /// Base64-encoded 64-byte `XEdDSA` signature over: `IDENTITY_SIGN_DOMAIN || challenge || node_pubkey`
    signature: String,
}

/// Query parameters for the identity endpoint.
#[derive(Debug, Deserialize)]
struct IdentityQuery {
    /// Base64-encoded 32-byte random challenge
    challenge: String,
}

/// POST /api/v1/submit - Accept messages from LAN peers (binary bundle format)
async fn submit_handler(
    State(state): State<Arc<HttpServerState>>,
    body: Bytes,
) -> Result<Json<SubmitResponse>, ApiError> {
    // Parse the bundle body — max 10 frames for the embedded node
    let frames = parse_body(&body, 10).map_err(|e| {
        warn!(error = %e, "Received invalid bundle body");
        ApiError::BadRequest(format!("Invalid bundle body: {e}"))
    })?;

    let mut results = Vec::with_capacity(frames.len());

    for frame in &frames {
        // Parse WirePayload from frame bytes
        let payload = match WirePayload::decode(frame) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "Frame contains invalid wire payload");
                results.push(FrameResult::error("Invalid message format"));
                continue;
            }
        };

        // Extract OuterEnvelope — tombstones are not accepted via direct peer API
        let envelope = match payload {
            WirePayload::Message(env) => env,
            WirePayload::AckTombstone(_) => {
                debug!("Rejected tombstone from LAN peer");
                results.push(FrameResult::error(
                    "Tombstones not accepted via direct peer API",
                ));
                continue;
            }
        };

        let message_id = envelope.message_id;

        // === ROUTING KEY VALIDATION ===
        // Only accept messages addressed to us.
        if !state.is_for_us(&envelope.routing_key) {
            warn!(
                message_id = ?message_id,
                expected = %hex::encode(state.our_routing_key().as_bytes()),
                received = %hex::encode(envelope.routing_key.as_bytes()),
                "Rejecting frame: routing key mismatch"
            );
            results.push(FrameResult::error("Routing key mismatch"));
            continue;
        }

        // === DUPLICATE CHECK ===
        // Idempotent: return ok with no receipt fields for duplicates.
        match state.is_duplicate(&envelope) {
            Ok(true) => {
                debug!(message_id = ?message_id, "Duplicate message, already stored");
                results.push(FrameResult::ok(None, None));
                continue;
            }
            Ok(false) => {
                // Not a duplicate, proceed to store
            }
            Err(e) => {
                // Database error during duplicate check - log but try to store anyway
                warn!(
                    message_id = ?message_id,
                    error = %e,
                    "Duplicate check failed, attempting store anyway"
                );
            }
        }

        // Generate signed receipt BEFORE storing
        let Some(receipt) = state.generate_receipt(&envelope).await else {
            error!(
                message_id = ?message_id,
                "Failed to generate receipt, crypto task may have panicked"
            );
            results.push(FrameResult::error("Failed to generate receipt"));
            continue;
        };

        // Store and notify client — handle concurrent insert race condition
        if let Err(e) = state.store_message(envelope.clone()) {
            if is_duplicate_after_store_failure(&state, &message_id, &e) {
                debug!(
                    message_id = ?message_id,
                    "Store failed but message exists (concurrent insert), treating as success"
                );
                results.push(FrameResult::ok(None, None));
                continue;
            }

            error!(
                message_id = ?message_id,
                error = %e,
                "Failed to store message from LAN peer"
            );
            results.push(FrameResult::error("Failed to store message"));
            continue;
        }

        info!(message_id = ?message_id, "Message from LAN peer stored successfully");
        results.push(FrameResult::ok(receipt.ack_secret, Some(receipt.signature)));
    }

    Ok(Json(SubmitResponse { results }))
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

/// GET /api/v1/identity - Challenge-response identity verification
///
/// Allows mDNS-discovered peers to verify this node's identity before sending messages.
///
/// ## Query Parameters
///
/// - `challenge`: Base64-encoded 32-byte random challenge
///
/// ## Response
///
/// Returns `IdentityResponse` with:
/// - `signature`: Base64-encoded 64-byte `XEdDSA` signature over `"reme-identity-v1:" || challenge || node_pubkey`
///
/// The node's public key is NOT returned for privacy (prevents identity enumeration).
/// Clients verify the signature against known contacts' public keys.
///
/// ## Errors
///
/// - `400 Bad Request`: Invalid or missing challenge (must be exactly 32 bytes)
async fn get_identity(
    State(state): State<Arc<HttpServerState>>,
    Query(query): Query<IdentityQuery>,
) -> impl IntoResponse {
    // Decode and validate challenge
    let Ok(challenge) = BASE64_STANDARD.decode(&query.challenge) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid base64 encoding for challenge".to_string(),
            }),
        )
            .into_response();
    };

    if challenge.len() != 32 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "Challenge must be exactly 32 bytes, got {}",
                    challenge.len()
                ),
            }),
        )
            .into_response();
    }

    // Clone identity Arc for use in spawn_blocking
    let identity = state.identity.clone();

    // Offload crypto operations (XEdDSA signing) to thread pool
    let challenge: [u8; 32] = challenge.try_into().expect("validated above");
    let result = tokio::task::spawn_blocking(move || {
        // Sign: "reme-identity-v1:" || challenge || node_pubkey
        // Note: node_pubkey is still included in signed data for cryptographic binding,
        // but not returned in response (privacy: prevents identity enumeration)
        let node_pubkey = identity.public_id().to_bytes();
        let sign_data = build_identity_sign_data(&challenge, &node_pubkey);
        let signature = identity.sign_xeddsa(&sign_data);

        IdentityResponse {
            signature: BASE64_STANDARD.encode(signature),
        }
    })
    .await;

    match result {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => {
            error!("Identity signing task failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal error during identity verification".to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Build the Axum router.
pub fn build_router(state: Arc<HttpServerState>) -> Router {
    Router::new()
        .route("/api/v1/submit", post(submit_handler))
        .route("/api/v1/identity", axum::routing::get(get_identity))
        .route("/health", axum::routing::get(health_handler))
        .layer(RequestBodyLimitLayer::new(512 * 1024)) // 512 KiB max
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
        let wire_bytes = wire_payload.encode().unwrap();
        let bundle_body = reme_bundle::encode_body(&[&wire_bytes]);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/submit")
                    .header("content-type", "application/vnd.reme.bundle")
                    .body(Body::from(bundle_body))
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
        let wire_bytes = wire_payload.encode().unwrap();
        let bundle_body = reme_bundle::encode_body(&[&wire_bytes]);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/submit")
                    .header("content-type", "application/vnd.reme.bundle")
                    .body(Body::from(bundle_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        // The handler now returns 200 with per-frame errors in results
        // since routing key mismatch is a per-frame error, not a top-level HTTP error
        // Actually, let me check - the old test expected FORBIDDEN
        // With batch format, wrong routing key is still rejected per-frame but HTTP status is OK
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let response_json: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("Invalid JSON response");
        let results = response_json["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert!(
            results[0]["error"].as_str().is_some(),
            "Wrong routing key should produce an error"
        );
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
        let wire_bytes = wire_payload.encode().unwrap();
        let bundle_body = reme_bundle::encode_body(&[&wire_bytes]);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/submit")
                    .header("content-type", "application/vnd.reme.bundle")
                    .body(Body::from(bundle_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Tombstones are rejected per-frame; HTTP status is still OK with batch format
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let response_json: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("Invalid JSON response");
        let results = response_json["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert!(
            results[0]["error"].as_str().is_some(),
            "Tombstone should produce an error"
        );
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
        let wire_bytes = wire_payload.encode().unwrap();
        let bundle_body = reme_bundle::encode_body(&[&wire_bytes]);

        // First submission should succeed
        let response1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/submit")
                    .header("content-type", "application/vnd.reme.bundle")
                    .body(Body::from(bundle_body.clone()))
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
                    .header("content-type", "application/vnd.reme.bundle")
                    .body(Body::from(bundle_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response2.status(), StatusCode::OK);
    }

    /// Test: Embedded node returns valid signed receipt for properly encrypted messages
    #[tokio::test]
    async fn test_returns_signed_receipt_for_encrypted_message() {
        use reme_encryption::{derive_ack_hash, RECEIPT_DOMAIN_SEP};

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
        let wire_bytes = wire_payload.encode().unwrap();
        let bundle_body = reme_bundle::encode_body(&[&wire_bytes]);

        // Submit message
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/submit")
                    .header("content-type", "application/vnd.reme.bundle")
                    .body(Body::from(bundle_body))
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

        let result = &response_json["results"][0];

        // Should have ack_secret
        assert!(
            result.get("ack_secret").is_some(),
            "Response should contain ack_secret"
        );
        let returned_ack_secret_b64 = result["ack_secret"].as_str().unwrap();
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
            result.get("signature").is_some(),
            "Response should contain signature"
        );
        let signature_b64 = result["signature"].as_str().unwrap();
        let signature: [u8; 64] = BASE64_STANDARD
            .decode(signature_b64)
            .expect("Invalid signature base64")
            .try_into()
            .expect("Wrong signature length");

        // Reconstruct signed message with domain separation
        // Format: "reme-receipt-v1:" || signer_pubkey || message_id (NO ack_secret)
        let mut sign_data = Vec::with_capacity(RECEIPT_DOMAIN_SEP.len() + 32 + 16);
        sign_data.extend_from_slice(RECEIPT_DOMAIN_SEP);
        sign_data.extend_from_slice(&recipient_pubkey.to_bytes());
        sign_data.extend_from_slice(message_id.as_bytes());

        // Verify using recipient's public key
        assert!(
            recipient_pubkey.verify_xeddsa(&sign_data, &signature),
            "Signature should verify with recipient's public key"
        );
    }

    /// Test: Low-order ephemeral key returns no `ack_secret` but still returns signature
    #[tokio::test]
    async fn test_low_order_ephemeral_key_returns_no_ack_secret_but_returns_signature() {
        use reme_encryption::RECEIPT_DOMAIN_SEP;

        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let (_node, handle, _event_rx) = EmbeddedNode::new(store);

        let identity = Identity::generate();
        let identity_pubkey = *identity.public_id();
        let our_routing_key = identity.public_id().routing_key();
        let state = Arc::new(HttpServerState::new(
            handle,
            our_routing_key,
            Arc::new(identity),
        ));
        let app = build_router(state);

        // Create envelope with low-order ephemeral key (zeroed = low-order point)
        let envelope = create_test_envelope(our_routing_key); // Uses [0u8; 32] ephemeral key
        let message_id = envelope.message_id;
        let wire_payload = WirePayload::Message(envelope);
        let wire_bytes = wire_payload.encode().unwrap();
        let bundle_body = reme_bundle::encode_body(&[&wire_bytes]);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/submit")
                    .header("content-type", "application/vnd.reme.bundle")
                    .body(Body::from(bundle_body))
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

        let result = &response_json["results"][0];

        // Should NOT have ack_secret (low-order point rejected)
        assert!(
            result.get("ack_secret").is_none() || result["ack_secret"].is_null(),
            "Low-order ephemeral key should NOT produce ack_secret"
        );

        // Should still have signature (signature is always returned)
        assert!(
            result.get("signature").is_some(),
            "Should still return signature even without ack_secret"
        );
        let signature_b64 = result["signature"].as_str().unwrap();
        let signature: [u8; 64] = BASE64_STANDARD
            .decode(signature_b64)
            .expect("Invalid signature base64")
            .try_into()
            .expect("Wrong signature length");

        // Verify signature over domain-separated message (without ack_secret)
        let mut sign_data = Vec::with_capacity(RECEIPT_DOMAIN_SEP.len() + 32 + 16);
        sign_data.extend_from_slice(RECEIPT_DOMAIN_SEP);
        sign_data.extend_from_slice(&identity_pubkey.to_bytes());
        sign_data.extend_from_slice(message_id.as_bytes());

        assert!(
            identity_pubkey.verify_xeddsa(&sign_data, &signature),
            "Signature should verify with node's public key"
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
        let wire_bytes = wire_payload.encode().unwrap();
        let bundle_body = reme_bundle::encode_body(&[&wire_bytes]);

        // First submission - should have ack_secret
        let response1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/submit")
                    .header("content-type", "application/vnd.reme.bundle")
                    .body(Body::from(bundle_body.clone()))
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
            response_json1["results"][0].get("ack_secret").is_some(),
            "First submit should return ack_secret"
        );

        // Second submission (duplicate) - should NOT have ack_secret
        let response2 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/submit")
                    .header("content-type", "application/vnd.reme.bundle")
                    .body(Body::from(bundle_body))
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
        let result2 = &response_json2["results"][0];
        assert!(
            result2.get("ack_secret").is_none() || result2["ack_secret"].is_null(),
            "Duplicate submit should NOT return ack_secret"
        );
    }

    // ============================================
    // Identity Endpoint Tests
    // ============================================

    /// Test: Valid challenge returns valid response with verifiable signature
    #[tokio::test]
    async fn test_identity_valid_challenge() {
        let config = PersistentStoreConfig::default();
        let store = PersistentMailboxStore::in_memory(config).unwrap();
        let (_node, handle, _event_rx) = EmbeddedNode::new(store);

        let identity = Identity::generate();
        let identity_pubkey = *identity.public_id();
        let our_routing_key = identity.public_id().routing_key();
        let state = Arc::new(HttpServerState::new(
            handle,
            our_routing_key,
            Arc::new(identity),
        ));
        let app = build_router(state);

        // Use a fixed 32-byte challenge for test reproducibility
        let challenge: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let challenge_b64 = BASE64_STANDARD.encode(challenge);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/identity?challenge={challenge_b64}"))
                    .body(Body::empty())
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

        // Response should only contain signature (privacy-preserving)
        assert!(
            response_json.get("node_pubkey").is_none(),
            "Response should not contain node_pubkey"
        );
        assert!(
            response_json.get("routing_keys").is_none(),
            "Response should not contain routing_keys"
        );

        // Verify signature using the known public key
        let signature_b64 = response_json["signature"].as_str().unwrap();
        let signature: [u8; 64] = BASE64_STANDARD
            .decode(signature_b64)
            .expect("Invalid signature base64")
            .try_into()
            .expect("Wrong signature length");

        // Reconstruct signed data using helper and known pubkey
        let node_pubkey = identity_pubkey.to_bytes();
        let sign_data = build_identity_sign_data(&challenge, &node_pubkey);

        assert!(
            identity_pubkey.verify_xeddsa(&sign_data, &signature),
            "Signature should verify with node's public key"
        );
    }

    /// Test: Invalid challenge length returns 400
    #[tokio::test]
    async fn test_identity_invalid_challenge_length() {
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

        // Send a 16-byte challenge (should be 32)
        let short_challenge: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let challenge_b64 = BASE64_STANDARD.encode(short_challenge);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/identity?challenge={challenge_b64}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Verify error message mentions 32 bytes
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let response_json: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("Invalid JSON response");
        let error_msg = response_json["error"].as_str().unwrap();
        assert!(
            error_msg.contains("32 bytes"),
            "Error should mention 32 bytes: {error_msg}"
        );
    }

    /// Test: Invalid base64 returns 400
    #[tokio::test]
    async fn test_identity_invalid_base64() {
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

        // Send invalid base64
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/identity?challenge=not-valid-base64!!!")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Verify error message mentions base64
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let response_json: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("Invalid JSON response");
        let error_msg = response_json["error"].as_str().unwrap();
        assert!(
            error_msg.to_lowercase().contains("base64"),
            "Error should mention base64: {error_msg}"
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
