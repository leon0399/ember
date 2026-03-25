//! HTTP API for the mailbox node (MIK-only, no prekeys)
//!
//! Provides REST endpoints for:
//!
//! ### Public (unauthenticated)
//! - `GET  /api/v1/identity?challenge=<base64>` — Challenge-response identity verification
//! - `GET  /api/v1/health` — Health check / readiness probe
//!
//! ### Authenticated (HTTP Basic Auth when configured)
//! - `POST /api/v1/submit` — Submit a message or ack-tombstone
//! - `GET  /api/v1/fetch/{routing_key}` — Fetch messages for a routing key
//! - `GET  /api/v1/stats` — Mailbox statistics

use crate::mqtt_bridge::MqttBridge;
use crate::node_identity::NodeIdentity;
use crate::rate_limit::{KeyedLimiter, RateLimiters};
use crate::replication::ReplicationClient;
use crate::signed_headers::{SignatureError, SignatureVerifier, HEADER_NODE_SIGNATURE};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::*;
use reme_encryption::{build_identity_sign_data, build_receipt_sign_data, derive_ack_secret};
use reme_identity::PublicID;
use reme_message::{OuterEnvelope, RoutingKey, WirePayload};
use reme_node_core::{FetchPage, MailboxStore, NodeError, PersistentMailboxStore};
use serde::Deserialize;
use serde::{Serialize, Serializer};
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
}

/// Maximum request body size (256 KiB)
/// Prevents memory exhaustion from oversized payloads.
/// Typical `OuterEnvelope` is ~2 KiB; 256 KiB provides ample headroom.
const MAX_BODY_SIZE: usize = 256 * 1024;
const DEFAULT_FETCH_PAGE_SIZE: usize = 100;
const MAX_FETCH_PAGE_SIZE: usize = 100;
const MAX_FETCH_RESPONSE_BYTES: usize = 64 * 1024;

/// Create the API router
///
/// Rate limiters are applied per-route if configured:
/// - `submit_ip`: Per-IP limit on submit endpoint
/// - `submit_key`: Per-routing-key limit on submit (checked inline in handler)
/// - `fetch_ip`: Per-IP limit on fetch endpoint
/// - `fetch_key`: Per-routing-key limit on fetch endpoint
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

    // Public routes — no authentication required.
    // Identity is needed for LAN discovery verification (unauthenticated peers).
    // Health is needed for monitoring probes.
    let public_routes = Router::new()
        .route("/api/v1/identity", get(get_identity))
        .route("/api/v1/health", get(health_check));

    // Authenticated routes — behind Basic Auth when configured.
    let auth_routes = Router::new()
        .merge(submit_route)
        .merge(fetch_route)
        .route("/api/v1/stats", get(get_stats))
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            check_basic_auth,
        ));

    Router::new()
        .merge(public_routes)
        .merge(auth_routes)
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
    let auth_str = auth_header.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;

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
            RequestSource::VerifiedNode(pubkey) => Some(crate::node_identity::node_id_hex(pubkey)),
            RequestSource::Client => None,
        }
    }
}

// ============================================
// Request/Response types
// ============================================

#[derive(Debug, Serialize)]
pub struct SubmitResponse {
    pub status: &'static str,
    /// Ack secret proving the node can decrypt this message.
    /// Present only if the node is the intended recipient (`routing_key` matches).
    /// Base64-encoded 16-byte secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack_secret: Option<String>,
    /// `XEdDSA` signature proving node received the message.
    /// Signed data: `"reme-receipt-v1:" || signer_pubkey || message_id`
    /// Always present when node has an identity configured.
    /// Base64-encoded 64-byte signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FetchResponse {
    /// Base64-encoded `WirePayload` bytes (includes wire type prefix)
    pub payloads: Vec<String>,
    /// Opaque continuation token for the next page. Encoded mailbox row id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Whether more rows remain for this routing key after the current page.
    pub has_more: bool,
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

/// Response for the identity endpoint.
///
/// Used by clients to verify node identity via challenge-response.
/// Returns only the signature for privacy - clients verify against known contacts.
#[derive(Debug, Serialize)]
pub struct IdentityResponse {
    /// Base64-encoded 64-byte `XEdDSA` signature over: `IDENTITY_SIGN_DOMAIN || challenge || node_pubkey`
    pub signature: String,
}

/// Query parameters for the identity endpoint.
#[derive(Debug, Deserialize)]
pub struct IdentityQuery {
    /// Base64-encoded 32-byte random challenge
    pub challenge: String,
}

#[derive(Debug, Deserialize, Default)]
struct FetchQuery {
    limit: Option<String>,
    after: Option<String>,
}

fn bad_request(message: impl Into<String>) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
        .into_response()
}

fn decode_fetch_routing_key(routing_key_b64: &str) -> Result<RoutingKey, String> {
    let routing_key_bytes = URL_SAFE_NO_PAD.decode(routing_key_b64).map_err(|e| {
        error!("Failed to decode routing key: {}", e);
        "Invalid routing key encoding".to_string()
    })?;

    if routing_key_bytes.len() != 16 {
        return Err("Routing key must be 16 bytes".to_string());
    }

    let mut routing_key_bytes_arr = [0u8; 16];
    routing_key_bytes_arr.copy_from_slice(&routing_key_bytes);
    Ok(RoutingKey::from_bytes(routing_key_bytes_arr))
}

fn parse_fetch_query(query: &FetchQuery) -> Result<(usize, Option<i64>), String> {
    let limit = match query.limit.as_deref() {
        Some(raw_limit) => match raw_limit.parse::<usize>() {
            Ok(0) => return Err("Invalid limit: must be greater than 0".to_string()),
            Ok(parsed) => parsed.min(MAX_FETCH_PAGE_SIZE),
            Err(_) => return Err("Invalid limit: must be an integer".to_string()),
        },
        None => DEFAULT_FETCH_PAGE_SIZE,
    };

    let after = match query.after.as_deref() {
        Some(raw_after) => match raw_after.parse::<i64>() {
            Ok(parsed) if parsed > 0 => Some(parsed),
            Ok(_) => return Err("Invalid after cursor: must be a positive integer".to_string()),
            Err(_) => return Err("Invalid after cursor: must be an integer".to_string()),
        },
        None => None,
    };

    Ok((limit, after))
}

struct FetchResponseRef<'a> {
    payloads: &'a [String],
    next_cursor: Option<&'a str>,
    has_more: bool,
}

impl Serialize for FetchResponseRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;

        let field_count = if self.next_cursor.is_some() { 3 } else { 2 };
        let mut state = serializer.serialize_struct("FetchResponse", field_count)?;
        state.serialize_field("payloads", self.payloads)?;
        if let Some(next_cursor) = self.next_cursor {
            state.serialize_field("next_cursor", next_cursor)?;
        }
        state.serialize_field("has_more", &self.has_more)?;
        state.end()
    }
}

fn fetch_response_size(
    payloads: &[String],
    next_cursor: Option<&str>,
    has_more: bool,
) -> Result<usize, String> {
    serde_json::to_vec(&FetchResponseRef {
        payloads,
        next_cursor,
        has_more,
    })
    .map(|encoded| encoded.len())
    .map_err(|e| format!("Failed to serialize fetch response: {e}"))
}

fn build_fetch_response(page: FetchPage) -> Result<FetchResponse, String> {
    let total_entries = page.entries.len();
    let mut payloads = Vec::with_capacity(total_entries);
    let mut next_cursor = None;
    let mut has_more = page.has_more;

    for (index, entry) in page.entries.into_iter().enumerate() {
        let previous_cursor = next_cursor.clone();
        let wire_payload = WirePayload::Message(entry.envelope);
        let encoded =
            BASE64_STANDARD.encode(wire_payload.encode().map_err(|e| format!("encode: {e}"))?);
        payloads.push(encoded);
        next_cursor = Some(entry.row_id.to_string());
        let candidate_has_more = page.has_more || index + 1 < total_entries;
        let response_bytes =
            fetch_response_size(&payloads, next_cursor.as_deref(), candidate_has_more)?;

        if response_bytes > MAX_FETCH_RESPONSE_BYTES {
            if payloads.len() == 1 {
                return Err(format!(
                    "Single fetch payload exceeds maximum response size of {MAX_FETCH_RESPONSE_BYTES} bytes (actual serialized size: {response_bytes} bytes)"
                ));
            }

            payloads.pop();
            next_cursor = previous_cursor;
            has_more = true;
            break;
        }

        has_more = candidate_has_more;
    }

    Ok(FetchResponse {
        payloads,
        next_cursor,
        has_more,
    })
}

// ============================================
// Receipt Generation (signature + optional ack_secret)
// ============================================

/// Receipt proving node received a message.
struct Receipt {
    /// Base64-encoded 16-byte `ack_secret` (only if node is intended recipient)
    ack_secret: Option<String>,
    /// Base64-encoded 64-byte `XEdDSA` signature over:
    /// `"reme-receipt-v1:" || signer_pubkey || message_id`
    signature: String,
}

/// Generate a signed receipt for a message.
///
/// Returns `Some(Receipt)` if node has an identity configured.
///
/// The receipt includes:
/// - `signature`: Always present - `XEdDSA` signature over `"reme-receipt-v1:" || signer_pubkey || message_id`
/// - `ack_secret`: Only if this node is the intended recipient and can decrypt
///
/// Crypto operations (`XEdDSA` signing, optional ECDH) are offloaded to a blocking thread pool
/// to avoid blocking the Tokio worker thread.
async fn generate_receipt(
    identity: Option<Arc<NodeIdentity>>,
    envelope: &OuterEnvelope,
) -> Option<Receipt> {
    let identity = identity?;

    // Capture owned values for spawn_blocking
    let routing_key = envelope.routing_key;
    let ephemeral_key = envelope.ephemeral_key;
    let message_id = envelope.message_id;

    // Offload crypto operations to thread pool
    tokio::task::spawn_blocking(move || {
        // Try to derive ack_secret only if we're the intended recipient
        let ack_secret = if routing_key == identity.routing_key() {
            identity
                .derive_shared_secret(&ephemeral_key)
                .map(|shared| derive_ack_secret(&shared, &message_id))
        } else {
            None
        };

        // Sign: "reme-receipt-v1:" || signer_pubkey || message_id
        // Note: signature does NOT include ack_secret (allows signing even as relay)
        let signer_pubkey = identity.public_id().to_bytes();
        let mut sign_data = build_receipt_sign_data(&signer_pubkey, &message_id);
        let signature = identity.sign(&sign_data);

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
        let verifier =
            SignatureVerifier::new(state.public_host.as_deref(), &state.additional_hosts);
        let public_id = verifier.verify(headers, method, path, body)?;
        debug!(
            "Verified signed request from node {}",
            crate::node_identity::node_id_hex(&public_id)
        );
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

/// Unified submit endpoint for messages and tombstones
///
/// Accepts base64-encoded wire format: `[type: u8][payload: postcard bytes]`
/// - type 0x00: Message (`OuterEnvelope`)
/// - type 0x02: `AckTombstone` (`SignedAckTombstone`) - Tombstone V2
///
/// ## Authentication
///
/// If `x-node-signature` header is present, verifies `XEdDSA` signature.
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
                    error: format!("Signature verification failed: {e}"),
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
            return (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e })).into_response();
        }
    };

    // Get from_node string for replication
    let from_node = source.to_from_node_string();

    match payload {
        WirePayload::Message(envelope) => {
            handle_message(state, envelope, payload_b64, from_node, source).await
        }
        WirePayload::AckTombstone(tombstone) => {
            // Tombstone V2: ECDH-derived ack verification
            // 1. Look up message by message_id to get its ack_hash
            let ack_hash = match state.store.get_ack_hash(&tombstone.message_id) {
                Ok(Some(hash)) => hash,
                Ok(None) => {
                    debug!(?tombstone.message_id, "AckTombstone for unknown message");
                    return (
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: "Message not found".to_string(),
                        }),
                    )
                        .into_response();
                }
                Err(e) => {
                    error!("Failed to get ack_hash: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Internal error".to_string(),
                        }),
                    )
                        .into_response();
                }
            };

            // 2. Verify authorization: hash(ack_secret) == ack_hash
            if !tombstone.verify_authorization(&ack_hash) {
                debug!(?tombstone.message_id, "AckTombstone authorization failed");
                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Invalid ack_secret".to_string(),
                    }),
                )
                    .into_response();
            }

            // 3. Delete message from mailbox
            match state.store.delete_message(&tombstone.message_id) {
                Ok(true) => {
                    debug!(?tombstone.message_id, "Message deleted via AckTombstone");

                    // Replicate tombstone to peer nodes (fire-and-forget)
                    // This ensures message is deleted across all nodes in the cluster
                    state.replication.replicate_payload(payload_b64, from_node);

                    (
                        StatusCode::OK,
                        Json(SubmitResponse {
                            status: "ok",
                            ack_secret: None,
                            signature: None,
                        }),
                    )
                        .into_response()
                }
                Ok(false) => {
                    // Message was already deleted (race condition, not an error)
                    // Don't replicate - this is likely a replicated tombstone arriving
                    (
                        StatusCode::OK,
                        Json(SubmitResponse {
                            status: "ok",
                            ack_secret: None,
                            signature: None,
                        }),
                    )
                        .into_response()
                }
                Err(e) => {
                    error!("Failed to delete message: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Internal error".to_string(),
                        }),
                    )
                        .into_response()
                }
            }
        }
    }
}

#[allow(clippy::unused_async)] // Async used in spawned task, function signature for consistency
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
            Json(SubmitResponse {
                status: "ok",
                ack_secret: None,
                signature: None,
            }),
        )
            .into_response();
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
            debug!(
                "Rate limited submit for routing key {:?}",
                &routing_key[..4]
            );
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
            return (
                StatusCode::OK,
                Json(SubmitResponse {
                    status: "ok",
                    ack_secret: None,
                    signature: None,
                }),
            )
                .into_response();
        }
        Ok(false) => {}
        Err(e) => {
            error!("Failed to check message existence: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    }

    // Generate signed receipt AFTER duplicate check (avoid crypto work for duplicates)
    // Signature always present when identity exists, ack_secret only if we're the intended recipient
    let receipt = generate_receipt(state.identity.clone(), &envelope).await;

    // Enqueue
    match state.store.enqueue(routing_key, envelope) {
        Ok(()) => {
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

            // Extract receipt fields (signature always present when identity exists, ack_secret only if recipient)
            let (ack_secret, signature) = match receipt {
                Some(r) => (r.ack_secret, Some(r.signature)),
                None => (None, None),
            };

            (
                StatusCode::OK,
                Json(SubmitResponse {
                    status: "ok",
                    ack_secret,
                    signature,
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to enqueue message: {}", e);
            let status = match e {
                NodeError::MailboxFull => StatusCode::INSUFFICIENT_STORAGE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

async fn fetch_messages(
    State(state): State<Arc<AppState>>,
    Path(routing_key_b64): Path<String>,
    Query(query): Query<FetchQuery>,
) -> impl IntoResponse {
    let routing_key = match decode_fetch_routing_key(&routing_key_b64) {
        Ok(routing_key) => routing_key,
        Err(message) => return bad_request(message),
    };
    let (limit, after) = match parse_fetch_query(&query) {
        Ok(params) => params,
        Err(message) => return bad_request(message),
    };

    // Fetch messages
    match state.store.fetch_page(&routing_key, limit, after) {
        Ok(page) => match build_fetch_response(page) {
            Ok(response) => {
                debug!(
                    "Fetched {} payloads for {:?}",
                    response.payloads.len(),
                    &routing_key[..4]
                );
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(e) => {
                error!("Failed to build fetch response: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse { error: e }),
                )
                    .into_response()
            }
        },
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

/// Identity endpoint for challenge-response verification.
///
/// Allows clients (especially mDNS-discovered peers) to verify that a node
/// controls the claimed identity by signing a client-provided challenge.
///
/// ## Request
///
/// `GET /api/v1/identity?challenge=<base64>`
///
/// The challenge must be exactly 32 bytes when decoded from base64.
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
/// - `401 Unauthorized`: Node has no identity configured
async fn get_identity(
    State(state): State<Arc<AppState>>,
    Query(query): Query<IdentityQuery>,
) -> impl IntoResponse {
    // Check if identity is configured
    let Some(identity) = &state.identity else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Node identity not configured".to_string(),
            }),
        )
            .into_response();
    };

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
    let identity = identity.clone();

    // Offload crypto operations (XEdDSA signing) to thread pool
    let challenge: [u8; 32] = challenge.try_into().expect("validated above");
    let result = tokio::task::spawn_blocking(move || {
        // Sign: "reme-identity-v1:" || challenge || node_pubkey
        // Note: node_pubkey is still included in signed data for cryptographic binding,
        // but not returned in response (privacy: prevents identity enumeration)
        let node_pubkey = identity.public_id().to_bytes();
        let mut sign_data = build_identity_sign_data(&challenge, &node_pubkey);
        let signature = identity.sign(&sign_data);
        sign_data.zeroize();

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
