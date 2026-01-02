//! Node-to-node replication (MIK-only, no prekeys)
//!
//! This module handles replicating payloads (messages/tombstones) to peer nodes.
//! Uses fire-and-forget pattern to avoid blocking the client response.
//!
//! ## Signed Requests
//!
//! When a node identity is configured, outgoing requests are signed with `XEdDSA`
//! signatures. Peer nodes verify these signatures to authenticate the source.
//!
//! ## Per-Peer Authentication
//!
//! Supports URL-embedded credentials for per-peer authentication:
//! ```text
//! peers = [
//!     "http://user1:pass1@peer1.example:3000",
//!     "http://user2:pass2@peer2.example:3000",
//!     "http://public-peer.example:3000",  # No auth
//! ]
//! ```

use crate::node_identity::NodeIdentity;
use crate::signed_headers::SignedHeaders;
use reme_transport::parse_url_with_auth;
use reqwest::Client;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Client for replicating data to peer nodes
pub struct ReplicationClient {
    client: Client,
    peer_urls: Vec<String>,
    node_id: String,
    /// Optional node identity for signing requests
    identity: Option<Arc<NodeIdentity>>,
}

impl ReplicationClient {
    /// Create a new replication client
    #[allow(dead_code)] // API for future replication without signing
    pub fn new(node_id: String, peer_urls: Vec<String>) -> Self {
        Self {
            client: Client::new(),
            peer_urls,
            node_id,
            identity: None,
        }
    }

    /// Create a new replication client with signing identity
    pub fn with_identity(
        node_id: String,
        peer_urls: Vec<String>,
        identity: Option<Arc<NodeIdentity>>,
    ) -> Self {
        Self {
            client: Client::new(),
            peer_urls,
            node_id,
            identity,
        }
    }

    /// Replicate a wire payload (message or tombstone) to all peer nodes (except the source)
    ///
    /// Uses fire-and-forget pattern - spawns tasks and returns immediately.
    /// Signs requests with `XEdDSA` if node identity is configured.
    /// Supports URL-embedded credentials for per-peer authentication.
    pub fn replicate_payload(self: &Arc<Self>, payload_b64: String, from_node: Option<String>) {
        if self.peer_urls.is_empty() {
            return;
        }

        let this = Arc::clone(self);
        tokio::spawn(async move {
            for peer_url in &this.peer_urls {
                // Skip replicating back to the source node (legacy string matching)
                // Note: Cryptographic loop prevention is done by the receiving node
                // by checking if the verified source identity matches their own.
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

                let submit_url = format!("{}/api/v1/submit", parsed.url.trim_end_matches('/'));
                let path = "/api/v1/submit";

                // Extract destination host for signature binding
                let dest_host = extract_host_from_url(&parsed.url);

                let mut request = this.client.post(&submit_url);

                // Sign request if identity and destination are available
                match (&this.identity, &dest_host) {
                    (Some(ref identity), Some(ref dest)) => {
                        let signed = SignedHeaders::sign(
                            identity,
                            "POST",
                            path,
                            payload_b64.as_bytes(),
                            dest,
                        );
                        for (header_name, header_value) in signed.to_headers() {
                            request = request.header(header_name, header_value);
                        }
                        debug!("Signed replication request to {}", dest);
                    }
                    (None, _) => {
                        // No identity configured - request will be unsigned
                        // This is logged once at startup, so only debug here
                        debug!("Sending unsigned replication request (no identity configured)");
                    }
                    (Some(_), None) => {
                        // Identity available but couldn't extract host from URL
                        // This is a configuration error that should be visible
                        warn!(
                            "Cannot sign replication request: failed to extract host from peer URL. \
                             Request will be sent unsigned."
                        );
                    }
                }

                request = request
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
                            "Authentication failed for peer {} - check credentials or signature",
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

    /// Log replication configuration on startup
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

/// Extract host:port from a URL for signature destination binding.
///
/// Returns `Some("host:port")` or `Some("host")` if no explicit port.
/// Uses the `url` crate for robust parsing of all URL formats including IPv6.
fn extract_host_from_url(url_str: &str) -> Option<String> {
    let parsed = url::Url::parse(url_str).ok()?;
    let host = parsed.host_str()?;

    match parsed.port() {
        Some(port) => Some(format!("{host}:{port}")),
        None => Some(host.to_string()),
    }
}
