//! Composite transport for broadcasting to multiple transport backends.
//!
//! This module provides a transport that sends messages to multiple
//! underlying transports (HTTP, MQTT, etc.) simultaneously.

use crate::{Transport, TransportError};
use async_trait::async_trait;
use futures::future::join_all;
use reme_message::{OuterEnvelope, TombstoneEnvelope};
use std::sync::Arc;
use tracing::{trace, warn};

/// A transport that broadcasts to multiple underlying transports.
///
/// Messages are sent to all configured transports in parallel.
/// Success is reported if at least one transport succeeds.
///
/// # Example
/// ```ignore
/// use reme_transport::{CompositeTransport, HttpTransport, MqttTransport};
///
/// let http = HttpTransport::new("https://node1.example.com:23003".to_string());
/// let mqtt = MqttTransport::new(vec![broker_spec]).await?;
///
/// let composite = CompositeTransport::new()
///     .with_transport(http)
///     .with_transport(mqtt);
/// ```
pub struct CompositeTransport {
    transports: Vec<Arc<dyn Transport>>,
}

impl CompositeTransport {
    /// Create a new empty composite transport.
    pub fn new() -> Self {
        Self {
            transports: Vec::new(),
        }
    }

    /// Add a transport to the composite.
    pub fn with_transport<T: Transport + 'static>(mut self, transport: T) -> Self {
        self.transports.push(Arc::new(transport));
        self
    }

    /// Add an Arc-wrapped transport to the composite.
    pub fn with_arc_transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transports.push(transport);
        self
    }

    /// Create a composite from two optional transports.
    ///
    /// This is a convenience method for the common case of HTTP + MQTT.
    pub fn from_options<H: Transport + 'static, M: Transport + 'static>(
        http: Option<H>,
        mqtt: Option<M>,
    ) -> Self {
        let mut composite = Self::new();
        if let Some(h) = http {
            composite = composite.with_transport(h);
        }
        if let Some(m) = mqtt {
            composite = composite.with_transport(m);
        }
        composite
    }

    /// Check if any transports are configured.
    pub fn is_empty(&self) -> bool {
        self.transports.is_empty()
    }

    /// Get the number of configured transports.
    pub fn len(&self) -> usize {
        self.transports.len()
    }

    /// Internal helper to broadcast an operation to all transports.
    async fn broadcast<F, Fut>(&self, op: F) -> Result<(), TransportError>
    where
        F: Fn(Arc<dyn Transport>) -> Fut,
        Fut: std::future::Future<Output = Result<(), TransportError>>,
    {
        if self.transports.is_empty() {
            return Err(TransportError::Network(
                "No transports configured".to_string(),
            ));
        }

        let futures: Vec<_> = self
            .transports
            .iter()
            .cloned()
            .map(|t| op(t))
            .collect();

        let results = join_all(futures).await;

        // Collect successes and errors
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        let errors: Vec<_> = results
            .into_iter()
            .filter_map(|r| r.err())
            .collect();

        if success_count > 0 {
            trace!(
                "Broadcast succeeded on {}/{} transports",
                success_count,
                self.transports.len()
            );
            if !errors.is_empty() {
                warn!(
                    "Some transports failed ({} of {}): {:?}",
                    errors.len(),
                    self.transports.len(),
                    errors.iter().map(|e| e.to_string()).collect::<Vec<_>>()
                );
            }
            Ok(())
        } else {
            Err(TransportError::Network(format!(
                "All transports failed: {:?}",
                errors.iter().map(|e| e.to_string()).collect::<Vec<_>>()
            )))
        }
    }
}

impl Default for CompositeTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for CompositeTransport {
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        self.broadcast(|t| {
            let env = envelope.clone();
            async move { t.submit_message(env).await }
        })
        .await
    }

    async fn submit_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), TransportError> {
        self.broadcast(|t| {
            let ts = tombstone.clone();
            async move { t.submit_tombstone(ts).await }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock transport for testing that counts calls.
    struct MockTransport {
        call_count: Arc<AtomicUsize>,
        should_fail: bool,
    }

    impl MockTransport {
        fn new(call_count: Arc<AtomicUsize>, should_fail: bool) -> Self {
            Self { call_count, should_fail }
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn submit_message(&self, _envelope: OuterEnvelope) -> Result<(), TransportError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail {
                Err(TransportError::Network("Mock failure".to_string()))
            } else {
                Ok(())
            }
        }

        async fn submit_tombstone(&self, _tombstone: TombstoneEnvelope) -> Result<(), TransportError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail {
                Err(TransportError::Network("Mock failure".to_string()))
            } else {
                Ok(())
            }
        }
    }

    fn make_test_envelope() -> OuterEnvelope {
        use reme_message::{MessageID, RoutingKey, Version};

        OuterEnvelope {
            version: Version { major: 0, minor: 1 },
            routing_key: RoutingKey::from_bytes([0u8; 16]),
            timestamp_hours: 0,
            ttl_hours: Some(24),
            message_id: MessageID::new(),
            ephemeral_key: [0u8; 32],
            inner_ciphertext: vec![0u8; 64],
        }
    }

    #[tokio::test]
    async fn test_empty_composite_fails() {
        let composite = CompositeTransport::new();
        let envelope = make_test_envelope();

        let result = composite.submit_message(envelope).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_single_transport_success() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let transport = MockTransport::new(call_count.clone(), false);

        let composite = CompositeTransport::new().with_transport(transport);
        let envelope = make_test_envelope();

        let result = composite.submit_message(envelope).await;
        assert!(result.is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_multiple_transports_all_succeed() {
        let call_count = Arc::new(AtomicUsize::new(0));

        let composite = CompositeTransport::new()
            .with_transport(MockTransport::new(call_count.clone(), false))
            .with_transport(MockTransport::new(call_count.clone(), false))
            .with_transport(MockTransport::new(call_count.clone(), false));

        let envelope = make_test_envelope();

        let result = composite.submit_message(envelope).await;
        assert!(result.is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_partial_failure_still_succeeds() {
        let success_count = Arc::new(AtomicUsize::new(0));
        let fail_count = Arc::new(AtomicUsize::new(0));

        let composite = CompositeTransport::new()
            .with_transport(MockTransport::new(success_count.clone(), false))
            .with_transport(MockTransport::new(fail_count.clone(), true))
            .with_transport(MockTransport::new(success_count.clone(), false));

        let envelope = make_test_envelope();

        let result = composite.submit_message(envelope).await;
        assert!(result.is_ok()); // At least one succeeded
        assert_eq!(success_count.load(Ordering::SeqCst), 2);
        assert_eq!(fail_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_all_fail() {
        let call_count = Arc::new(AtomicUsize::new(0));

        let composite = CompositeTransport::new()
            .with_transport(MockTransport::new(call_count.clone(), true))
            .with_transport(MockTransport::new(call_count.clone(), true));

        let envelope = make_test_envelope();

        let result = composite.submit_message(envelope).await;
        assert!(result.is_err());
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_from_options() {
        let call_count = Arc::new(AtomicUsize::new(0));

        // Both Some
        let composite = CompositeTransport::from_options(
            Some(MockTransport::new(call_count.clone(), false)),
            Some(MockTransport::new(call_count.clone(), false)),
        );
        assert_eq!(composite.len(), 2);

        // HTTP only
        let composite = CompositeTransport::from_options::<MockTransport, MockTransport>(
            Some(MockTransport::new(call_count.clone(), false)),
            None,
        );
        assert_eq!(composite.len(), 1);

        // MQTT only
        let composite = CompositeTransport::from_options::<MockTransport, MockTransport>(
            None,
            Some(MockTransport::new(call_count.clone(), false)),
        );
        assert_eq!(composite.len(), 1);

        // Neither
        let composite = CompositeTransport::from_options::<MockTransport, MockTransport>(None, None);
        assert!(composite.is_empty());
    }
}
