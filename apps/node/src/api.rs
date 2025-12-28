//! HTTP API for the mailbox node (MIK-only, no prekeys)
//!
//! Provides REST endpoints for:
//! - POST /api/v1/submit - Submit a message (tombstones temporarily disabled)
//! - GET /api/v1/fetch/:routing_key - Fetch messages

use crate::mqtt_bridge::MqttBridge;
use crate::node_identity::NodeIdentity;
use crate::rate_limit::{KeyedLimiter, RateLimiters};
use reme_node_core::{MailboxStore, NodeError, PersistentMailboxStore};
use crate::replication::ReplicationClient;
use crate::signed_headers::{SignatureError, SignatureVerifier, HEADER_NODE_SIGNATURE};
use reme_identity::{is_low_order_point, PublicID};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::*;
use reme_encryption::verify_outer_envelope;
use reme_message::{OuterEnvelope, RoutingKey, WirePayload};
use serde::Serialize;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tracing::{debug, error, warn};
use zeroize::Zeroize;

/// Shared application state
pub struct AppState {
    pub store: Arc<PersistentMailboxStore>,
    pub replication: Arc<ReplicationClient>,
    /// Optional HTTP Basic Auth credentials (username, password)
    /// If Some, all API endpoints require authentication
    pub auth: Option<(String, String)>,
    /// Optional per-routing-key rate limiter for submit endpoint
    pub submit_key_limiter: Option<Arc<KeyedLimiter>>,
    /// Optional MQTT bridge for publishing messages to MQTT brokers
    pub mqtt_bridge: Option<Arc<MqttBridge>>,
    /// Node's cryptographic identity for signing/verifying headers
    pub identity: Option<Arc<NodeIdentity>>,
    /// Canonical public hostname for signature destination verification
    pub public_host: Option<String>,
    /// Additional acceptable hostnames (for multi-homed, dev, migration)
    pub additional_hosts: Vec<String>,
    /// Whether to require outer envelope signatures for message verification
    pub require_outer_signature: bool,
}

/// Maximum request body size (256 KiB)
/// Prevents memory exhaustion from oversized payloads.
/// Typical OuterEnvelope is ~2 KiB; 256 KiB provides ample headroom.
const MAX_BODY_SIZE: usize = 256 * 1024;

/// Create the API router
///
/// Rate limiters are applied per-route if configured:
/// - submit_ip: Per-IP limit on submit endpoint
/// - submit_key: Per-routing-key limit on submit (checked inline in handler)
/// - fetch_ip: Per-IP limit on fetch endpoint
/// - fetch_key: Per-routing-key limit on fetch endpoint
pub fn router(state: Arc<AppState>, rate_limiters: Option<&RateLimiters>) -> Router {
    // Build submit route with optional IP rate limiting
    let submit_route = Router::new().route("/api/v1/submit", post(submit_payload));
    let submit_route = if let Some(limiters) = rate_limiters {
        limiters.apply_submit_ip(submit_route)
    } else {
        submit_route
    };

    // Build fetch route with optional IP and routing-key rate limiting
    let fetch_route = Router::new().route("/api/v1/fetch/{routing_key}", get(fetch_messages));
    let fetch_route = if let Some(limiters) = rate_limiters {
        let route = limiters.apply_fetch_ip(fetch_route);
        limiters.apply_fetch_key(route)
    } else {
        fetch_route
    };

    // Combine routes with shared middleware
    Router::new()
        .merge(submit_route)
        .merge(fetch_route)
        .route("/api/v1/health", get(health_check))
        .route("/api/v1/stats", get(get_stats))
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            check_basic_auth,
        ))
        .with_state(state)
}

/// Middleware to check HTTP Basic Auth if credentials are configured
async fn check_basic_auth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    // If no auth configured, allow all requests
    let Some((expected_user, expected_pass)) = &state.auth else {
        return Ok(next.run(request).await);
    };

    // Get Authorization header
    let Some(auth_header) = headers.get(header::AUTHORIZATION) else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    // Parse "Basic <base64>" header
    let auth_str = auth_header
        .to_str()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !auth_str.starts_with("Basic ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Decode base64 credentials
    let mut decoded = BASE64_STANDARD
        .decode(&auth_str[6..])
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Find separator and split into user/pass bytes, avoiding String allocation
    let Some(separator_pos) = decoded.iter().position(|&b| b == b':') else {
        decoded.zeroize();
        return Err(StatusCode::UNAUTHORIZED);
    };

    let (user_bytes, pass_bytes_with_colon) = decoded.split_at(separator_pos);
    let pass_bytes = &pass_bytes_with_colon[1..];

    // Validate credentials in constant time to prevent timing attacks
    let user_match = user_bytes.ct_eq(expected_user.as_bytes());
    let pass_match = pass_bytes.ct_eq(expected_pass.as_bytes());

    // Securely clear credentials from memory
    decoded.zeroize();

    // Use bitwise AND to avoid short-circuit timing leak
    // (short-circuit && would skip password check if username fails, leaking info)
    if (user_match & pass_match).into() {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

// ============================================
// Source identification
// ============================================

/// Identifies the source of an incoming request
#[derive(Debug, Clone)]
pub enum RequestSource {
    /// Verified node with cryptographic identity
    VerifiedNode(PublicID),
    /// Client (no node headers)
    Client,
}

impl RequestSource {
    /// Check if this source is our own identity (for loop prevention)
    pub fn is_self(&self, our_identity: Option<&NodeIdentity>) -> bool {
        match (self, our_identity) {
            (RequestSource::VerifiedNode(their_pubkey), Some(identity)) => {
                their_pubkey == identity.public_id()
            }
            _ => false,
        }
    }

    /// Get a string representation for logging/replication
    pub fn to_from_node_string(&self) -> Option<String> {
        match self {
            RequestSource::VerifiedNode(pubkey) => {
                Some(crate::node_identity::node_id_hex(pubkey))
            }
            RequestSource::Client => None,
        }
    }
}

// ============================================
// Request/Response types
// ============================================

#[derive(Debug, Serialize)]
pub struct SubmitResponse {
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct FetchResponse {
    /// Base64-encoded WirePayload bytes (includes wire type prefix)
    pub payloads: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub mailbox_count: usize,
    pub total_messages: usize,
    pub backend: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ============================================
// Handlers
// ============================================

/// Identify the source of a request by checking signed headers.
///
/// Returns:
/// - `Ok(VerifiedNode)` if signed headers are present and valid
/// - `Ok(Client)` if no node headers are present
/// - `Err` if signed headers are present but invalid
fn identify_request_source(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<RequestSource, SignatureError> {
    // Check if signed headers are present
    if headers.contains_key(HEADER_NODE_SIGNATURE) {
        // Signed headers present - must verify
        let verifier = SignatureVerifier::new(
            state.public_host.as_deref(),
            &state.additional_hosts,
        );
        let public_id = verifier.verify(headers, method, path, body)?;
        debug!("Verified signed request from node {}", crate::node_identity::node_id_hex(&public_id));
        return Ok(RequestSource::VerifiedNode(public_id));
    }

    // No node headers - treat as client
    Ok(RequestSource::Client)
}

/// Parse wire payload from body (plain text base64 of wire format bytes)
fn parse_wire_payload(body: &Bytes) -> Result<(String, WirePayload), String> {
    let body_str = std::str::from_utf8(body)
        .map_err(|_| "Invalid UTF-8")?
        .trim();

    // Decode base64 to get wire format bytes
    let wire_bytes = BASE64_STANDARD
        .decode(body_str)
        .map_err(|_| "Invalid base64 encoding")?;

    // Decode wire payload (includes type discriminator)
    let payload = WirePayload::decode(&wire_bytes)?;

    Ok((body_str.to_string(), payload))
}

/// Unified submit endpoint for messages
///
/// Accepts base64-encoded wire format: `[type: u8][payload: bincode bytes]`
/// - type 0x00: Message (OuterEnvelope)
/// - type 0x01: Tombstone (TombstoneEnvelope) - TEMPORARILY DISABLED
///
/// ## Authentication
///
/// If `x-node-signature` header is present, verifies XEdDSA signature.
/// Invalid signatures are rejected with 401 Unauthorized.
async fn submit_payload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Identify request source (verify signed headers if present)
    let source = match identify_request_source(&state, &headers, "POST", "/api/v1/submit", &body) {
        Ok(source) => source,
        Err(e) => {
            warn!("Signature verification failed: {}", e);
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: format!("Signature verification failed: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Parse wire payload from body
    let (payload_b64, payload) = match parse_wire_payload(&body) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to parse wire payload: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: e }),
            )
                .into_response();
        }
    };

    // Get from_node string for replication
    let from_node = source.to_from_node_string();

    match payload {
        WirePayload::Message(envelope) => {
            handle_message(state, envelope, payload_b64, from_node, source).await
        }
        WirePayload::Tombstone(_) => {
            // Tombstones temporarily disabled pending refactor
            warn!("Tombstones are temporarily disabled");
            (
                StatusCode::NOT_IMPLEMENTED,
                Json(ErrorResponse {
                    error: "Tombstones temporarily disabled".to_string(),
                }),
            )
                .into_response()
        }
    }
}

async fn handle_message(
    state: Arc<AppState>,
    envelope: OuterEnvelope,
    payload_b64: String,
    from_node: Option<String>,
    source: RequestSource,
) -> axum::response::Response {
    // Check for self-loop (message from ourselves)
    if source.is_self(state.identity.as_deref()) {
        debug!("Rejecting message from ourselves (loop prevention)");
        return (
            StatusCode::OK,
            Json(SubmitResponse { status: "ok".to_string() }),
        )
            .into_response();
    }

    // Verify outer envelope signature if present
    match (&envelope.commitment_pub, &envelope.outer_signature) {
        (Some(commitment_pub), Some(outer_signature)) => {
            // Reject low-order commitment keys (potential attack vector)
            if is_low_order_point(commitment_pub) {
                debug!("Low-order commitment_pub rejected");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Invalid commitment public key".to_string(),
                    }),
                )
                    .into_response();
            }

            // Both present: verify the signature
            let outer_signable = envelope.outer_signable_bytes();
            if !verify_outer_envelope(commitment_pub, &outer_signable, outer_signature) {
                debug!("Invalid outer envelope signature");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Invalid outer envelope signature".to_string(),
                    }),
                )
                    .into_response();
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            // Inconsistent: one present without the other
            debug!("Inconsistent outer signature fields");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Outer signature fields must both be present or both absent".to_string(),
                }),
            )
                .into_response();
        }
        (None, None) => {
            // Neither present: check if signatures are required
            if state.require_outer_signature {
                debug!("Outer signature required but not present");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Outer envelope signature required".to_string(),
                    }),
                )
                    .into_response();
            }
            // Accept unsigned messages for backward compatibility
            debug!("Accepting unsigned message (backward compatibility mode)");
        }
    }

    let routing_key = envelope.routing_key;
    let message_id = envelope.message_id;
    // Clone envelope for MQTT publishing (enqueue takes ownership)
    let envelope_for_mqtt = envelope.clone();

    // Check per-routing-key rate limit (inline, after parsing body)
    if let Some(ref limiter) = state.submit_key_limiter {
        // Use URL-safe base64 of routing key as the rate limit key
        let key = URL_SAFE_NO_PAD.encode(routing_key.as_bytes());
        if limiter.check_key(&key).is_err() {
            debug!("Rate limited submit for routing key {:?}", &routing_key[..4]);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: "Rate limit exceeded for this routing key".to_string(),
                }),
            )
                .into_response();
        }
    }

    // Check for duplicate (idempotent operation)
    match state.store.has_message(&routing_key, &message_id) {
        Ok(true) => {
            debug!("Duplicate message {:?}, skipping", message_id);
            return (StatusCode::OK, Json(SubmitResponse { status: "ok".to_string() }))
                .into_response();
        }
        Ok(false) => {}
        Err(e) => {
            error!("Failed to check message existence: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e.to_string() }),
            )
                .into_response();
        }
    }

    // Enqueue
    match state.store.enqueue(routing_key, envelope) {
        Ok(_) => {
            debug!("Message enqueued for {:?}", &routing_key[..4]);

            // Trigger replication to peers (fire-and-forget)
            state.replication.replicate_payload(payload_b64, from_node);

            // Publish to MQTT brokers if bridge is configured (fire-and-forget)
            if let Some(ref bridge) = state.mqtt_bridge {
                let bridge = bridge.clone();
                tokio::spawn(async move {
                    if let Err(e) = bridge.publish(&envelope_for_mqtt).await {
                        warn!("Failed to publish message to MQTT: {}", e);
                    }
                });
            }

            (StatusCode::OK, Json(SubmitResponse { status: "ok".to_string() })).into_response()
        }
        Err(e) => {
            error!("Failed to enqueue message: {}", e);
            let status = match e {
                NodeError::MailboxFull => StatusCode::INSUFFICIENT_STORAGE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, Json(ErrorResponse { error: e.to_string() })).into_response()
        }
    }
}

async fn fetch_messages(
    State(state): State<Arc<AppState>>,
    Path(routing_key_b64): Path<String>,
) -> impl IntoResponse {
    // Decode routing key (URL-safe base64)
    let routing_key_bytes = match URL_SAFE_NO_PAD.decode(&routing_key_b64) {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to decode routing key: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid routing key encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    if routing_key_bytes.len() != 16 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Routing key must be 16 bytes".to_string(),
            }),
        )
            .into_response();
    }

    let mut routing_key_bytes_arr = [0u8; 16];
    routing_key_bytes_arr.copy_from_slice(&routing_key_bytes);
    let routing_key = RoutingKey::from_bytes(routing_key_bytes_arr);

    // Fetch messages
    match state.store.fetch(&routing_key) {
        Ok(envelopes) => {
            // Encode as WirePayload format (with type discriminator)
            let payloads: Vec<String> = envelopes
                .into_iter()
                .map(|env| {
                    let wire_payload = WirePayload::Message(env);
                    BASE64_STANDARD.encode(wire_payload.encode())
                })
                .collect();

            debug!(
                "Fetched {} payloads for {:?}",
                payloads.len(),
                &routing_key[..4]
            );
            (StatusCode::OK, Json(FetchResponse { payloads })).into_response()
        }
        Err(e) => {
            error!("Failed to fetch messages: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

async fn health_check() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn get_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.store.stats() {
        Ok(stats) => Json(StatsResponse {
            mailbox_count: stats.mailbox_count,
            total_messages: stats.total_messages,
            backend: "sqlite".to_string(),
        })
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}
