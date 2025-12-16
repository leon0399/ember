//! HTTP API for the mailbox node (MIK-only, no prekeys)
//!
//! Provides REST endpoints for:
//! - POST /api/v1/submit - Submit a message (tombstones temporarily disabled)
//! - GET /api/v1/fetch/:routing_key - Fetch messages

use crate::persistent_store::{PersistentMailboxStore, PersistentStoreError};
use crate::replication::{ReplicationClient, FROM_NODE_HEADER};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::*;
use reme_message::{OuterEnvelope, WirePayload};
use serde::Serialize;
use std::sync::Arc;
use tracing::{debug, error, warn};

/// Shared application state
pub struct AppState {
    pub store: Arc<PersistentMailboxStore>,
    pub replication: Arc<ReplicationClient>,
}

/// Create the API router
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/submit", post(submit_payload))
        .route("/api/v1/fetch/{routing_key}", get(fetch_messages))
        .route("/api/v1/health", get(health_check))
        .route("/api/v1/stats", get(get_stats))
        .with_state(state)
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
async fn submit_payload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
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

    // Extract source node from header (if this came from a peer)
    let from_node = headers
        .get(FROM_NODE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match payload {
        WirePayload::Message(envelope) => {
            handle_message(state, envelope, payload_b64, from_node).await
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
) -> axum::response::Response {
    let routing_key = envelope.routing_key;
    let message_id = envelope.message_id;

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

            (StatusCode::OK, Json(SubmitResponse { status: "ok".to_string() })).into_response()
        }
        Err(e) => {
            error!("Failed to enqueue message: {}", e);
            let status = match e {
                PersistentStoreError::MailboxFull => StatusCode::INSUFFICIENT_STORAGE,
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

    let mut routing_key = [0u8; 16];
    routing_key.copy_from_slice(&routing_key_bytes);

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
