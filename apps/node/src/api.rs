//! HTTP API for the mailbox node
//!
//! Provides REST endpoints for:
//! - POST /api/v1/enqueue - Submit a message
//! - GET /api/v1/fetch/:routing_key - Fetch messages
//! - POST /api/v1/prekeys/:routing_key - Upload prekeys
//! - GET /api/v1/prekeys/:routing_key - Fetch prekeys

use crate::replication::{ReplicationClient, FROM_NODE_HEADER};
use crate::store::{MailboxStore, StoreError};
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
use reme_message::OuterEnvelope;
use reme_prekeys::SignedPrekeyBundle;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info};

/// Shared application state
pub struct AppState {
    pub store: MailboxStore,
    pub replication: Arc<ReplicationClient>,
}

/// Create the API router
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/enqueue", post(enqueue_message))
        .route("/api/v1/fetch/{routing_key}", get(fetch_messages))
        .route("/api/v1/prekeys/{routing_key}", post(upload_prekeys))
        .route("/api/v1/prekeys/{routing_key}", get(fetch_prekeys))
        .route("/api/v1/health", get(health_check))
        .route("/api/v1/stats", get(get_stats))
        .with_state(state)
}

// ============================================
// Request/Response types
// ============================================

#[derive(Debug, Deserialize)]
pub struct EnqueueRequest {
    /// Base64-encoded OuterEnvelope
    pub envelope: String,
}

#[derive(Debug, Serialize)]
pub struct EnqueueResponse {
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct FetchResponse {
    /// Base64-encoded OuterEnvelopes
    pub messages: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UploadPrekeysRequest {
    /// Base64-encoded SignedPrekeyBundle
    pub bundle: String,
}

#[derive(Debug, Serialize)]
pub struct UploadPrekeysResponse {
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct FetchPrekeysResponse {
    /// Base64-encoded SignedPrekeyBundle
    pub bundle: String,
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
    pub prekey_bundles: usize,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ============================================
// Handlers
// ============================================

/// Parse envelope from body (supports both JSON and plain text base64)
fn parse_envelope_body(body: &Bytes) -> Result<(String, OuterEnvelope), String> {
    let body_str = std::str::from_utf8(body).map_err(|_| "Invalid UTF-8")?;

    // Try JSON first, then plain text
    let envelope_b64 = if body_str.starts_with('{') {
        // JSON format
        let req: EnqueueRequest =
            serde_json::from_str(body_str).map_err(|e| format!("Invalid JSON: {}", e))?;
        req.envelope
    } else {
        // Plain text base64
        body_str.trim().to_string()
    };

    // Decode envelope
    let envelope_bytes = BASE64_STANDARD
        .decode(&envelope_b64)
        .map_err(|_| "Invalid base64 encoding")?;

    // Deserialize envelope
    let (envelope, _): (OuterEnvelope, _) =
        bincode::decode_from_slice(&envelope_bytes, bincode::config::standard())
            .map_err(|e| format!("Invalid envelope format: {}", e))?;

    Ok((envelope_b64, envelope))
}

async fn enqueue_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Parse envelope from body
    let (envelope_b64, envelope) = match parse_envelope_body(&body) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to parse envelope: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: e }),
            )
                .into_response();
        }
    };

    let routing_key = envelope.routing_key;
    let message_id = envelope.message_id;

    // Check for duplicate (idempotent operation)
    match state.store.has_message(&routing_key, &message_id) {
        Ok(true) => {
            debug!("Duplicate message {:?}, skipping", message_id);
            return (StatusCode::OK, Json(EnqueueResponse { status: "ok".to_string() }))
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

            // Extract source node from header (if this came from a peer)
            let from_node = headers
                .get(FROM_NODE_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            // Trigger replication to peers (fire-and-forget)
            state.replication.replicate_message(envelope_b64, from_node);

            (StatusCode::OK, Json(EnqueueResponse { status: "ok".to_string() })).into_response()
        }
        Err(e) => {
            error!("Failed to enqueue message: {}", e);
            let status = match e {
                StoreError::MailboxFull => StatusCode::INSUFFICIENT_STORAGE,
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
            let messages: Vec<String> = envelopes
                .iter()
                .filter_map(|env| {
                    bincode::encode_to_vec(env, bincode::config::standard())
                        .ok()
                        .map(|bytes| BASE64_STANDARD.encode(&bytes))
                })
                .collect();

            debug!(
                "Fetched {} messages for {:?}",
                messages.len(),
                &routing_key[..4]
            );
            (StatusCode::OK, Json(FetchResponse { messages })).into_response()
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

/// Parse prekey bundle from body (supports both JSON and plain text base64)
fn parse_prekey_body(body: &Bytes) -> Result<(String, SignedPrekeyBundle), String> {
    let body_str = std::str::from_utf8(body).map_err(|_| "Invalid UTF-8")?;

    // Try JSON first, then plain text
    let bundle_b64 = if body_str.starts_with('{') {
        // JSON format
        let req: UploadPrekeysRequest =
            serde_json::from_str(body_str).map_err(|e| format!("Invalid JSON: {}", e))?;
        req.bundle
    } else {
        // Plain text base64
        body_str.trim().to_string()
    };

    // Decode bundle
    let bundle_bytes = BASE64_STANDARD
        .decode(&bundle_b64)
        .map_err(|_| "Invalid base64 encoding")?;

    // Deserialize bundle
    let (bundle, _): (SignedPrekeyBundle, _) =
        bincode::decode_from_slice(&bundle_bytes, bincode::config::standard())
            .map_err(|e| format!("Invalid bundle format: {}", e))?;

    Ok((bundle_b64, bundle))
}

async fn upload_prekeys(
    State(state): State<Arc<AppState>>,
    Path(routing_key_b64): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Decode routing key (URL-safe base64)
    let routing_key_bytes = match URL_SAFE_NO_PAD.decode(&routing_key_b64) {
        Ok(b) => b,
        Err(_) => {
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

    // Parse bundle from body
    let (bundle_b64, bundle) = match parse_prekey_body(&body) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to parse prekey bundle: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: e }),
            )
                .into_response();
        }
    };

    // Store
    match state.store.store_prekeys(routing_key, bundle) {
        Ok(_) => {
            info!("Prekeys uploaded for {:?}", &routing_key[..4]);

            // Extract source node from header (if this came from a peer)
            let from_node = headers
                .get(FROM_NODE_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            // Trigger replication to peers (fire-and-forget)
            state
                .replication
                .replicate_prekeys(routing_key_b64, bundle_b64, from_node);

            (
                StatusCode::OK,
                Json(UploadPrekeysResponse { status: "ok".to_string() }),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to store prekeys: {}", e);
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

async fn fetch_prekeys(
    State(state): State<Arc<AppState>>,
    Path(routing_key_b64): Path<String>,
) -> impl IntoResponse {
    // Decode routing key (URL-safe base64)
    let routing_key_bytes = match URL_SAFE_NO_PAD.decode(&routing_key_b64) {
        Ok(b) => b,
        Err(_) => {
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

    // Fetch
    match state.store.fetch_prekeys(&routing_key) {
        Ok(bundle) => {
            let bundle_bytes =
                bincode::encode_to_vec(&bundle, bincode::config::standard()).unwrap();
            let bundle_b64 = BASE64_STANDARD.encode(&bundle_bytes);

            debug!("Prekeys fetched for {:?}", &routing_key[..4]);
            (StatusCode::OK, Json(FetchPrekeysResponse { bundle: bundle_b64 })).into_response()
        }
        Err(StoreError::PrekeysNotFound) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Prekeys not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to fetch prekeys: {}", e);
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
    let stats = state.store.stats();
    Json(StatsResponse {
        mailbox_count: stats.mailbox_count,
        total_messages: stats.total_messages,
        prekey_bundles: stats.prekey_bundles,
    })
}
