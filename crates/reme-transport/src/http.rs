use std::collections::HashMap;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::*;
use futures::future::join_all;
use reme_message::{MessageID, OuterEnvelope, RoutingKey, TombstoneEnvelope, WirePayload};
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::{Transport, TransportError};

/// HTTP transport client for communicating with mailbox nodes (MIK-only, no prekeys)
///
/// Supports multiple nodes for redundancy. When multiple nodes are configured:
/// - Payloads (messages/tombstones) are sent to ALL nodes (broadcast)
/// - Messages are fetched from ALL nodes and deduplicated
pub struct HttpTransport {
    base_urls: Vec<String>,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct SubmitResponse {
    #[allow(dead_code)]
    status: String,
}

#[derive(Debug, Deserialize)]
struct FetchResponse {
    payloads: Vec<String>,
}

impl HttpTransport {
    /// Create a new HTTP transport with a single node URL
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_urls: vec![base_url.into()],
            client: Client::new(),
        }
    }

    /// Create a new HTTP transport with multiple node URLs for redundancy
    pub fn with_nodes(base_urls: Vec<String>) -> Self {
        assert!(!base_urls.is_empty(), "At least one node URL is required");
        Self {
            base_urls,
            client: Client::new(),
        }
    }

    /// Create with a custom reqwest client and single node
    pub fn with_client(base_url: impl Into<String>, client: Client) -> Self {
        Self {
            base_urls: vec![base_url.into()],
            client,
        }
    }

    /// Create with a custom reqwest client and multiple nodes
    pub fn with_nodes_and_client(base_urls: Vec<String>, client: Client) -> Self {
        assert!(!base_urls.is_empty(), "At least one node URL is required");
        Self { base_urls, client }
    }

    /// Get the configured node URLs
    pub fn node_urls(&self) -> &[String] {
        &self.base_urls
    }

    /// Submit wire payload to a single node
    async fn submit_to_node(
        &self,
        base_url: &str,
        payload_b64: &str,
    ) -> Result<(), TransportError> {
        let url = format!("{}/api/v1/submit", base_url);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "text/plain")
            .body(payload_b64.to_string())
            .send()
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown error".to_string());
            return Err(TransportError::ServerError(format!(
                "HTTP {}: {}",
                status, body
            )));
        }

        let _result: SubmitResponse = response
            .json()
            .await
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        Ok(())
    }

    /// Fetch messages from a single node
    async fn fetch_from_node(
        &self,
        base_url: &str,
        routing_key_b64: &str,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        let url = format!("{}/api/v1/fetch/{}", base_url, routing_key_b64);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown error".to_string());
            return Err(TransportError::ServerError(format!(
                "HTTP {}: {}",
                status, body
            )));
        }

        let result: FetchResponse = response
            .json()
            .await
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        // Decode and deserialize each wire payload
        let mut envelopes = Vec::new();
        for blob in result.payloads {
            let wire_bytes = BASE64_STANDARD
                .decode(&blob)
                .map_err(|e| TransportError::Serialization(format!("base64 decode: {}", e)))?;

            let payload = WirePayload::decode(&wire_bytes)
                .map_err(|e| TransportError::Serialization(format!("wire decode: {}", e)))?;

            // Only extract messages (tombstones are handled separately)
            if let WirePayload::Message(envelope) = payload {
                envelopes.push(envelope);
            }
        }

        Ok(envelopes)
    }

    /// Fetch messages once from all configured nodes and deduplicate
    ///
    /// This method performs a single fetch operation, useful for:
    /// - Testing scenarios
    /// - One-shot message retrieval
    /// - Initial sync before starting push-based receiving
    ///
    /// For continuous message receiving, use `MessageReceiver` instead.
    pub async fn fetch_once(
        &self,
        routing_key: &RoutingKey,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        let routing_key_b64 = URL_SAFE_NO_PAD.encode(routing_key);

        // Fetch from all nodes in parallel
        let futures: Vec<_> = self
            .base_urls
            .iter()
            .map(|url| self.fetch_from_node(url, &routing_key_b64))
            .collect();

        let results = join_all(futures).await;

        // Aggregate and deduplicate by message_id
        let mut messages_by_id: HashMap<MessageID, OuterEnvelope> = HashMap::new();
        let mut last_error = None;
        let mut success_count = 0;

        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(messages) => {
                    debug!(
                        "Fetched {} messages from node {}",
                        messages.len(),
                        self.base_urls[i]
                    );
                    success_count += 1;
                    for msg in messages {
                        messages_by_id.insert(msg.message_id, msg);
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch from node {}: {}", self.base_urls[i], e);
                    last_error = Some(e);
                }
            }
        }

        // If we got messages from at least one node, return them
        if success_count > 0 {
            let messages: Vec<_> = messages_by_id.into_values().collect();
            debug!(
                "Fetched {} unique messages from {}/{} nodes",
                messages.len(),
                success_count,
                self.base_urls.len()
            );
            Ok(messages)
        } else {
            Err(last_error.unwrap_or(TransportError::Network("All nodes failed".to_string())))
        }
    }

}

#[async_trait]
impl Transport for HttpTransport {
    /// Submit message to all configured nodes (broadcast)
    ///
    /// Returns success if ANY node accepts the message.
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        // Encode as WirePayload (includes type discriminator)
        let wire_payload = WirePayload::Message(envelope);
        let wire_bytes = wire_payload.encode();

        // Base64 encode
        let envelope_b64 = BASE64_STANDARD.encode(&wire_bytes);

        // Submit to all nodes in parallel
        let futures: Vec<_> = self
            .base_urls
            .iter()
            .map(|url| self.submit_to_node(url, &envelope_b64))
            .collect();

        let results = join_all(futures).await;

        // Check results - succeed if ANY node succeeded
        let mut last_error = None;
        let mut success_count = 0;

        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(()) => {
                    debug!("Message submitted to node {}", self.base_urls[i]);
                    success_count += 1;
                }
                Err(e) => {
                    warn!("Failed to submit to node {}: {}", self.base_urls[i], e);
                    last_error = Some(e);
                }
            }
        }

        if success_count > 0 {
            debug!(
                "Message submitted to {}/{} nodes",
                success_count,
                self.base_urls.len()
            );
            Ok(())
        } else {
            Err(last_error.unwrap_or(TransportError::Network("All nodes failed".to_string())))
        }
    }

    /// Submit tombstone to all configured nodes (broadcast)
    ///
    /// Returns success if ANY node accepts the tombstone.
    async fn submit_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), TransportError> {
        // Encode as WirePayload (includes type discriminator)
        let wire_payload = WirePayload::Tombstone(tombstone);
        let wire_bytes = wire_payload.encode();

        // Base64 encode
        let tombstone_b64 = BASE64_STANDARD.encode(&wire_bytes);

        // Submit to all nodes in parallel
        let futures: Vec<_> = self
            .base_urls
            .iter()
            .map(|url| self.submit_to_node(url, &tombstone_b64))
            .collect();

        let results = join_all(futures).await;

        // Check results - succeed if ANY node succeeded
        let mut last_error = None;
        let mut success_count = 0;

        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(()) => {
                    debug!("Tombstone submitted to node {}", self.base_urls[i]);
                    success_count += 1;
                }
                Err(e) => {
                    warn!("Failed to submit tombstone to node {}: {}", self.base_urls[i], e);
                    last_error = Some(e);
                }
            }
        }

        if success_count > 0 {
            debug!(
                "Tombstone submitted to {}/{} nodes",
                success_count,
                self.base_urls.len()
            );
            Ok(())
        } else {
            Err(last_error.unwrap_or(TransportError::Network("All nodes failed".to_string())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_transport_single_node() {
        let transport = HttpTransport::new("https://example.com");
        assert_eq!(transport.base_urls, vec!["https://example.com"]);
    }

    #[test]
    fn test_http_transport_multiple_nodes() {
        let transport = HttpTransport::with_nodes(vec![
            "https://node1.example.com".to_string(),
            "https://node2.example.com".to_string(),
            "https://node3.example.com".to_string(),
        ]);
        assert_eq!(transport.base_urls.len(), 3);
    }

    #[test]
    fn test_node_urls_accessor() {
        let transport = HttpTransport::with_nodes(vec![
            "https://a.com".to_string(),
            "https://b.com".to_string(),
        ]);
        assert_eq!(transport.node_urls(), &["https://a.com", "https://b.com"]);
    }

    #[test]
    #[should_panic(expected = "At least one node URL is required")]
    fn test_empty_nodes_panics() {
        HttpTransport::with_nodes(vec![]);
    }
}
