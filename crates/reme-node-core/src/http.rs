//! HTTP server for the embedded node.
//!
//! Provides REST endpoints for LAN peer communication:
//! - POST /api/v1/submit - Submit a message from a peer
//! - GET /api/v1/fetch/:routing_key - Fetch messages for a routing key
//! - GET /api/v1/health - Health check

use crate::replication::FROM_NODE_HEADER;
use reme_storage::MailboxStorage;
use crate::NodeEvent;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use reme_message::{OuterEnvelope, RoutingKey, WirePayload};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

/// HTTP server state shared across handlers.
pub struct HttpState<S: MailboxStorage> {
    /// Storage backend.
    pub storage: Arc<S>,
    /// Channel to push incoming messages to the client.
    pub event_tx: mpsc::Sender<NodeEvent>,
    /// Routing keys we monitor (push to client when messages arrive).
    pub monitored_keys: Arc<tokio::sync::RwLock<std::collections::HashSet<RoutingKey>>>,
    /// Replication client for forwarding to other peers.
    pub replication: Arc<crate::ReplicationClient>,
}

/// Response types for the API.
#[derive(Debug, Serialize)]
pub struct SubmitResponse {
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct FetchResponse {
    /// Base64-encoded WirePayload bytes.
    pub payloads: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Start the HTTP server for LAN peer communication.
///
/// Returns the bound address if successful.
pub async fn start_http_server<S: MailboxStorage + Send + Sync + 'static>(
    bind_addr: SocketAddr,
    state: Arc<HttpState<S>>,
    cancel_token: CancellationToken,
) -> Result<SocketAddr, std::io::Error> {
    let app = create_router(state);

    let listener = TcpListener::bind(bind_addr).await?;
    let bound_addr = listener.local_addr()?;

    info!("HTTP server listening on {}", bound_addr);

    // Spawn the server task
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                cancel_token.cancelled().await;
                info!("HTTP server shutting down...");
            })
            .await
            .ok();
    });

    Ok(bound_addr)
}

/// Create the router with all endpoints.
fn create_router<S: MailboxStorage + Send + Sync + 'static>(state: Arc<HttpState<S>>) -> Router {
    Router::new()
        .route("/api/v1/submit", post(submit_payload::<S>))
        .route("/api/v1/fetch/{routing_key}", get(fetch_messages::<S>))
        .route("/api/v1/health", get(health_check))
        .with_state(state)
}

/// Parse wire payload from body (plain text base64 of wire format bytes).
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

/// Submit a message from a LAN peer.
async fn submit_payload<S: MailboxStorage + Send + Sync + 'static>(
    State(state): State<Arc<HttpState<S>>>,
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
        WirePayload::Tombstone(tombstone) => {
            handle_tombstone(state, tombstone, payload_b64).await
        }
    }
}

/// Handle an incoming message.
async fn handle_message<S: MailboxStorage + Send + Sync + 'static>(
    state: Arc<HttpState<S>>,
    envelope: OuterEnvelope,
    payload_b64: String,
    from_node: Option<String>,
) -> axum::response::Response {
    let routing_key = envelope.routing_key;
    let message_id = envelope.message_id;

    trace!(?message_id, ?routing_key, "HTTP: Processing message submission");

    // Check for duplicate (idempotent operation)
    match state.storage.mailbox_has_message(&routing_key, &message_id).await {
        Ok(true) => {
            trace!(?message_id, "Duplicate message, skipping");
            return (
                StatusCode::OK,
                Json(SubmitResponse { status: "ok".to_string() }),
            )
                .into_response();
        }
        Ok(false) => {}
        Err(e) => {
            warn!(?message_id, error = %e, "Error checking for duplicate");
            // Continue anyway - worst case we get a duplicate
        }
    }

    // Clone envelope for event notification
    let envelope_for_event = envelope.clone();

    // Store the message
    match state.storage.mailbox_enqueue(routing_key, envelope).await {
        Ok(()) => {
            debug!(?message_id, ?routing_key, "Message stored via HTTP");
        }
        Err(e) => {
            let error_str = e.to_string();
            let status = if error_str.contains("full") || error_str.contains("Full") {
                StatusCode::INSUFFICIENT_STORAGE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return (status, Json(ErrorResponse { error: error_str })).into_response();
        }
    }

    // Replicate to peers (fire-and-forget)
    state.replication.replicate_payload(payload_b64, from_node);

    // If this message is for a monitored routing key, push to client
    let monitored = state.monitored_keys.read().await;
    if monitored.contains(&routing_key) {
        trace!(?message_id, "Pushing message to client via HTTP handler");
        if let Err(e) = state
            .event_tx
            .send(NodeEvent::MessageReceived(envelope_for_event))
            .await
        {
            warn!(?message_id, error = %e, "Failed to push message to client");
        }
    }

    (
        StatusCode::OK,
        Json(SubmitResponse { status: "ok".to_string() }),
    )
        .into_response()
}

/// Handle an incoming tombstone.
async fn handle_tombstone<S: MailboxStorage + Send + Sync + 'static>(
    state: Arc<HttpState<S>>,
    tombstone: reme_message::TombstoneEnvelope,
    payload_b64: String,
) -> axum::response::Response {
    let routing_key = tombstone.routing_key;
    let message_id = tombstone.target_message_id;

    trace!(?message_id, ?routing_key, "HTTP: Processing tombstone");

    // Delete the message if it exists
    match state.storage.mailbox_delete_message(&routing_key, &message_id).await {
        Ok(deleted) => {
            if deleted {
                debug!(?message_id, "Message deleted by tombstone via HTTP");
            } else {
                trace!(?message_id, "Message not found for tombstone");
            }
        }
        Err(e) => {
            warn!(?message_id, error = %e, "Error deleting message");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e.to_string() }),
            )
                .into_response();
        }
    }

    // Replicate tombstone to peers
    state.replication.replicate_payload(payload_b64, None);

    (
        StatusCode::OK,
        Json(SubmitResponse { status: "ok".to_string() }),
    )
        .into_response()
}

/// Fetch messages for a routing key.
async fn fetch_messages<S: MailboxStorage + Send + Sync + 'static>(
    State(state): State<Arc<HttpState<S>>>,
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
    match state.storage.mailbox_fetch(&routing_key).await {
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
                Json(ErrorResponse { error: e.to_string() }),
            )
                .into_response()
        }
    }
}

/// Health check endpoint.
async fn health_check() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wire_payload_invalid_utf8() {
        let body = Bytes::from(vec![0xff, 0xfe]);
        let result = parse_wire_payload(&body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("UTF-8"));
    }

    #[test]
    fn test_parse_wire_payload_invalid_base64() {
        let body = Bytes::from("not valid base64!!!");
        let result = parse_wire_payload(&body);
        assert!(result.is_err());
    }
}
