use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::*;
use reme_message::{OuterEnvelope, RoutingKey};
use reme_prekeys::SignedPrekeyBundle;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{Transport, TransportError};

/// HTTP transport client for communicating with mailbox nodes
pub struct HttpTransport {
    base_url: String,
    client: Client,
}

#[derive(Debug, Serialize)]
struct EnqueueRequest {
    /// Base64-encoded OuterEnvelope
    envelope: String,
}

#[derive(Debug, Deserialize)]
struct EnqueueResponse {
    status: String,
}

#[derive(Debug, Deserialize)]
struct FetchResponse {
    messages: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UploadPrekeysRequest {
    /// Base64-encoded SignedPrekeyBundle
    bundle: String,
}

#[derive(Debug, Deserialize)]
struct UploadPrekeysResponse {
    status: String,
}

#[derive(Debug, Deserialize)]
struct FetchPrekeysResponse {
    bundle: String,
}

impl HttpTransport {
    /// Create a new HTTP transport with the given base URL
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: Client::new(),
        }
    }

    /// Create with a custom reqwest client
    pub fn with_client(base_url: impl Into<String>, client: Client) -> Self {
        Self {
            base_url: base_url.into(),
            client,
        }
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        // Serialize envelope to bytes
        let envelope_bytes = bincode::encode_to_vec(&envelope, bincode::config::standard())
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        // Base64 encode
        let envelope_b64 = BASE64_STANDARD.encode(&envelope_bytes);

        let request = EnqueueRequest { envelope: envelope_b64 };

        let url = format!("{}/api/v1/enqueue", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(&request)
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

        let _result: EnqueueResponse = response
            .json()
            .await
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        Ok(())
    }

    async fn fetch_messages(
        &self,
        routing_key: RoutingKey,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        let routing_key_b64 = URL_SAFE_NO_PAD.encode(&routing_key);
        let url = format!("{}/api/v1/fetch/{}", self.base_url, routing_key_b64);

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

        // Decode and deserialize each envelope
        let mut envelopes = Vec::new();
        for blob in result.messages {
            let envelope_bytes = BASE64_STANDARD.decode(&blob)
                .map_err(|e| TransportError::Serialization(format!("base64 decode: {}", e)))?;

            let (envelope, _): (OuterEnvelope, usize) =
                bincode::decode_from_slice(&envelope_bytes, bincode::config::standard())
                    .map_err(|e| TransportError::Serialization(format!("bincode decode: {}", e)))?;

            envelopes.push(envelope);
        }

        Ok(envelopes)
    }

    async fn upload_prekeys(
        &self,
        routing_key: RoutingKey,
        bundle: SignedPrekeyBundle,
    ) -> Result<(), TransportError> {
        // Serialize bundle to bytes
        let bundle_bytes = bincode::encode_to_vec(&bundle, bincode::config::standard())
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        // Base64 encode (URL-safe for routing key in path)
        let bundle_b64 = BASE64_STANDARD.encode(&bundle_bytes);
        let routing_key_b64 = URL_SAFE_NO_PAD.encode(&routing_key);

        let request = UploadPrekeysRequest {
            bundle: bundle_b64,
        };

        let url = format!("{}/api/v1/prekeys/{}", self.base_url, routing_key_b64);
        let response = self
            .client
            .post(&url)
            .json(&request)
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

        let _result: UploadPrekeysResponse = response
            .json()
            .await
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        Ok(())
    }

    async fn fetch_prekeys(
        &self,
        routing_key: RoutingKey,
    ) -> Result<SignedPrekeyBundle, TransportError> {
        let routing_key_b64 = URL_SAFE_NO_PAD.encode(&routing_key);
        let url = format!("{}/api/v1/prekeys/{}", self.base_url, routing_key_b64);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;

        if response.status() == 404 {
            return Err(TransportError::NotFound);
        }

        if !response.status().is_success() {
            let status = response.status();
            return Err(TransportError::ServerError(format!(
                "HTTP {}",
                status
            )));
        }

        let result: FetchPrekeysResponse = response
            .json()
            .await
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        // Decode and deserialize bundle
        let bundle_bytes = BASE64_STANDARD.decode(&result.bundle)
            .map_err(|e| TransportError::Serialization(format!("base64 decode: {}", e)))?;

        let (bundle, _): (SignedPrekeyBundle, usize) =
            bincode::decode_from_slice(&bundle_bytes, bincode::config::standard())
                .map_err(|e| TransportError::Serialization(format!("bincode decode: {}", e)))?;

        Ok(bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_transport_creation() {
        let transport = HttpTransport::new("https://example.com");
        assert_eq!(transport.base_url, "https://example.com");
    }
}
