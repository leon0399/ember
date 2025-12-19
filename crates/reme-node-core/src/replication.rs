//! Node-to-node replication (fire-and-forget HTTP).
//!
//! This module handles replicating payloads (messages/tombstones) to peer nodes.
//! Uses fire-and-forget pattern to avoid blocking the client response.
//!
//! ## Per-Peer Authentication
//!
//! Supports URL-embedded credentials for per-peer authentication:
//! ```text
//! peers = [
//!     "http://user1:pass1@peer1.example:3000",
//!     "http://user2:pass2@peer2.example:3000",
//!     "http://public-peer.example:3000",  // No auth
//! ]
//! ```

use reme_transport::parse_url_with_auth;
use reqwest::Client;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Header name for source node identification.
pub const FROM_NODE_HEADER: &str = "X-From-Node";

/// Client for replicating data to peer nodes.
pub struct ReplicationClient {
    client: Client,
    peer_urls: Vec<String>,
    node_id: String,
}

impl ReplicationClient {
    /// Create a new replication client.
    pub fn new(node_id: String, peer_urls: Vec<String>) -> Self {
        Self {
            client: Client::new(),
            peer_urls,
            node_id,
        }
    }

    /// Get the node ID.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Get the configured peer URLs.
    pub fn peer_urls(&self) -> &[String] {
        &self.peer_urls
    }

    /// Replicate a wire payload (message or tombstone) to all peer nodes (except the source).
    ///
    /// Uses fire-and-forget pattern - spawns tasks and returns immediately.
    /// Supports URL-embedded credentials for per-peer authentication.
    pub fn replicate_payload(self: &Arc<Self>, payload_b64: String, from_node: Option<String>) {
        if self.peer_urls.is_empty() {
            return;
        }

        let this = Arc::clone(self);
        tokio::spawn(async move {
            for peer_url in &this.peer_urls {
                // Skip replicating back to the source node
                if let Some(ref from) = from_node {
                    if peer_url.contains(from) {
                        debug!("Skipping replication to source node: {}", peer_url);
                        continue;
                    }
                }

                // Parse URL and extract credentials if present
                let parsed = match parse_url_with_auth(peer_url) {
                    Ok(p) => p,
                    Err(e) => {
                        // Don't log raw peer_url - it may contain credentials
                        error!("Invalid peer URL (parse error): {}", e);
                        continue;
                    }
                };

                let url = format!("{}/api/v1/submit", parsed.url.trim_end_matches('/'));

                let mut request = this
                    .client
                    .post(&url)
                    .header(FROM_NODE_HEADER, &this.node_id)
                    .header("Content-Type", "text/plain")
                    .body(payload_b64.clone());

                // Add Basic Auth if credentials were embedded in peer URL
                if let Some((username, password)) = parsed.auth {
                    request = request.basic_auth(username, Some(password));
                }

                let result = request.send().await;

                match result {
                    Ok(resp) if resp.status().is_success() => {
                        debug!("Replicated payload to {}", parsed.url);
                    }
                    Ok(resp) if resp.status() == reqwest::StatusCode::UNAUTHORIZED => {
                        error!(
                            "Authentication failed for peer {} - check credentials",
                            parsed.url
                        );
                    }
                    Ok(resp) => {
                        warn!(
                            "Peer {} returned status {} for payload replication",
                            parsed.url,
                            resp.status()
                        );
                    }
                    Err(e) => {
                        error!("Failed to replicate payload to {}: {}", parsed.url, e);
                    }
                }
            }
        });
    }

    /// Log replication configuration on startup.
    ///
    /// Note: Credentials are stripped from URLs before logging for security.
    pub fn log_config(&self) {
        if self.peer_urls.is_empty() {
            info!("Replication: disabled (no peers configured)");
        } else {
            info!("Replication: enabled");
            info!("  Node ID: {}", self.node_id);
            info!("  Peers:");
            for peer in &self.peer_urls {
                // Strip credentials from URL before logging
                let display_url = match parse_url_with_auth(peer) {
                    Ok(parsed) => {
                        if parsed.auth.is_some() {
                            format!("{} (authenticated)", parsed.url)
                        } else {
                            parsed.url
                        }
                    }
                    Err(_) => peer.clone(),
                };
                info!("    - {}", display_url);
            }
        }
    }
}
