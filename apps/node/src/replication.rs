//! Node-to-node replication
//!
//! This module handles replicating payloads (messages/tombstones) and prekeys to peer nodes.
//! Uses fire-and-forget pattern to avoid blocking the client response.

use reqwest::Client;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Header name for source node identification
pub const FROM_NODE_HEADER: &str = "X-From-Node";

/// Client for replicating data to peer nodes
pub struct ReplicationClient {
    client: Client,
    peer_urls: Vec<String>,
    node_id: String,
}

impl ReplicationClient {
    /// Create a new replication client
    pub fn new(node_id: String, peer_urls: Vec<String>) -> Self {
        Self {
            client: Client::new(),
            peer_urls,
            node_id,
        }
    }

    /// Replicate a wire payload (message or tombstone) to all peer nodes (except the source)
    ///
    /// Uses fire-and-forget pattern - spawns tasks and returns immediately.
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

                let url = format!("{}/api/v1/submit", peer_url);
                let result = this
                    .client
                    .post(&url)
                    .header(FROM_NODE_HEADER, &this.node_id)
                    .header("Content-Type", "text/plain")
                    .body(payload_b64.clone())
                    .send()
                    .await;

                match result {
                    Ok(resp) if resp.status().is_success() => {
                        debug!("Replicated payload to {}", peer_url);
                    }
                    Ok(resp) => {
                        warn!(
                            "Peer {} returned status {} for payload replication",
                            peer_url,
                            resp.status()
                        );
                    }
                    Err(e) => {
                        error!("Failed to replicate payload to {}: {}", peer_url, e);
                    }
                }
            }
        });
    }

    /// Replicate prekeys to all peer nodes (except the source)
    ///
    /// Uses fire-and-forget pattern - spawns tasks and returns immediately.
    pub fn replicate_prekeys(
        self: &Arc<Self>,
        routing_key_b64: String,
        bundle_b64: String,
        from_node: Option<String>,
    ) {
        if self.peer_urls.is_empty() {
            return;
        }

        let this = Arc::clone(self);
        tokio::spawn(async move {
            for peer_url in &this.peer_urls {
                // Skip replicating back to the source node
                if let Some(ref from) = from_node {
                    if peer_url.contains(from) {
                        debug!("Skipping prekey replication to source node: {}", peer_url);
                        continue;
                    }
                }

                let url = format!("{}/api/v1/prekeys/{}", peer_url, routing_key_b64);
                let result = this
                    .client
                    .post(&url)
                    .header(FROM_NODE_HEADER, &this.node_id)
                    .header("Content-Type", "text/plain")
                    .body(bundle_b64.clone())
                    .send()
                    .await;

                match result {
                    Ok(resp) if resp.status().is_success() => {
                        debug!("Replicated prekeys to {}", peer_url);
                    }
                    Ok(resp) => {
                        warn!(
                            "Peer {} returned status {} for prekey replication",
                            peer_url,
                            resp.status()
                        );
                    }
                    Err(e) => {
                        error!("Failed to replicate prekeys to {}: {}", peer_url, e);
                    }
                }
            }
        });
    }

    /// Log replication configuration on startup
    pub fn log_config(&self) {
        if self.peer_urls.is_empty() {
            info!("Replication: disabled (no peers configured)");
        } else {
            info!("Replication: enabled");
            info!("  Node ID: {}", self.node_id);
            info!("  Peers:");
            for peer in &self.peer_urls {
                info!("    - {}", peer);
            }
        }
    }
}
