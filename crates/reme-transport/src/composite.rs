//! Composite transport for broadcasting to multiple transport backends.
//!
//! This module provides a transport that sends messages to multiple
//! underlying transports (HTTP, MQTT, etc.) simultaneously.
//!
//! The composite transport supports runtime addition of new transports
//! via the [`add_transport`](CompositeTransport::add_transport) method,
//! enabling dynamic configuration through TUI popups or other interfaces.

use crate::{Transport, TransportError};
use async_trait::async_trait;
use futures::future::join_all;
use reme_message::{OuterEnvelope, SignedAckTombstone, TombstoneEnvelope};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

/// A transport that broadcasts to multiple underlying transports.
///
/// Messages are sent to all configured transports in parallel.
/// Success is reported if at least one transport succeeds.
///
/// The transport list can be modified at runtime using [`add_transport`](Self::add_transport),
/// allowing dynamic addition of ephemeral upstreams discovered during operation.
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
///
/// // Later, add ephemeral transport at runtime
/// composite.add_transport(another_http).await;
/// ```
pub struct CompositeTransport {
    transports: RwLock<Vec<Arc<dyn Transport>>>,
}

/// Builder for constructing a [`CompositeTransport`].
///
/// Use [`CompositeTransport::builder()`] to create a builder,
/// chain [`with_transport`](Self::with_transport) calls, then
/// call [`build()`](Self::build) to create the final transport.
pub struct CompositeTransportBuilder {
    transports: Vec<Arc<dyn Transport>>,
}

impl CompositeTransportBuilder {
    fn new() -> Self {
        Self {
            transports: Vec::new(),
        }
    }

    /// Add a transport to the builder.
    pub fn with_transport<T: Transport + 'static>(mut self, transport: T) -> Self {
        self.transports.push(Arc::new(transport));
        self
    }

    /// Add an Arc-wrapped transport to the builder.
    pub fn with_arc_transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transports.push(transport);
        self
    }

    /// Build the final [`CompositeTransport`].
    pub fn build(self) -> CompositeTransport {
        CompositeTransport {
            transports: RwLock::new(self.transports),
        }
    }
}

impl CompositeTransport {
    /// Create a new empty composite transport.
    pub fn new() -> Self {
        Self {
            transports: RwLock::new(Vec::new()),
        }
    }

    /// Create a builder for constructing a composite transport.
    pub fn builder() -> CompositeTransportBuilder {
        CompositeTransportBuilder::new()
    }

    /// Add a transport to the composite (builder pattern, sync).
    ///
    /// **Note**: This consumes and recreates the transport. For runtime addition
    /// in async contexts, use [`add_transport`](Self::add_transport) instead.
    pub fn with_transport<T: Transport + 'static>(self, transport: T) -> Self {
        // Extract existing transports, add new one, return new composite
        let mut transports = self.transports.into_inner();
        transports.push(Arc::new(transport));
        Self {
            transports: RwLock::new(transports),
        }
    }

    /// Add an Arc-wrapped transport to the composite (builder pattern, sync).
    ///
    /// **Note**: This consumes and recreates the transport. For runtime addition
    /// in async contexts, use [`add_arc_transport`](Self::add_arc_transport) instead.
    pub fn with_arc_transport(self, transport: Arc<dyn Transport>) -> Self {
        let mut transports = self.transports.into_inner();
        transports.push(transport);
        Self {
            transports: RwLock::new(transports),
        }
    }

    /// Add a transport at runtime.
    ///
    /// This method can be called from async contexts to dynamically
    /// add new transports discovered during operation.
    pub async fn add_transport<T: Transport + 'static>(&self, transport: T) {
        let mut transports = self.transports.write().await;
        transports.push(Arc::new(transport));
        debug!("Added transport at runtime, total: {}", transports.len());
    }

    /// Add an Arc-wrapped transport at runtime.
    ///
    /// This method can be called from async contexts to dynamically
    /// add new transports discovered during operation.
    pub async fn add_arc_transport(&self, transport: Arc<dyn Transport>) {
        let mut transports = self.transports.write().await;
        transports.push(transport);
        debug!("Added transport at runtime, total: {}", transports.len());
    }

    /// Create a composite from two optional transports.
    ///
    /// This is a convenience method for the common case of HTTP + MQTT.
    pub fn from_options<H: Transport + 'static, M: Transport + 'static>(
        http: Option<H>,
        mqtt: Option<M>,
    ) -> Self {
        let mut builder = Self::builder();
        if let Some(h) = http {
            builder = builder.with_transport(h);
        }
        if let Some(m) = mqtt {
            builder = builder.with_transport(m);
        }
        builder.build()
    }

    /// Check if any transports are configured (async version).
    pub async fn is_empty_async(&self) -> bool {
        self.transports.read().await.is_empty()
    }

    /// Check if any transports are configured (sync version).
    ///
    /// **Note**: This tries to acquire a read lock. Returns false if lock unavailable.
    pub fn is_empty(&self) -> bool {
        match self.transports.try_read() {
            Ok(guard) => guard.is_empty(),
            Err(_) => {
                // Fallback: assume not empty if we can't get lock
                false
            }
        }
    }

    /// Get the number of configured transports (async version).
    pub async fn len_async(&self) -> usize {
        self.transports.read().await.len()
    }

    /// Get the number of configured transports (sync version).
    ///
    /// **Note**: This tries to acquire a read lock. Returns 1 if lock unavailable
    /// (conservative: assumes not empty, consistent with `is_empty()`).
    pub fn len(&self) -> usize {
        match self.transports.try_read() {
            Ok(guard) => guard.len(),
            Err(_) => 1, // Conservative: assume not empty if lock is contended
        }
    }

    /// Internal helper to broadcast an operation to all transports.
    async fn broadcast<F, Fut>(&self, op: F) -> Result<(), TransportError>
    where
        F: Fn(Arc<dyn Transport>) -> Fut,
        Fut: std::future::Future<Output = Result<(), TransportError>>,
    {
        // Take a read lock and clone the transport list
        let transports = self.transports.read().await.clone();

        if transports.is_empty() {
            return Err(TransportError::Network(
                "No transports configured".to_string(),
            ));
        }

        let transport_count = transports.len();
        let futures: Vec<_> = transports
            .into_iter()
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
                transport_count
            );
            if !errors.is_empty() {
                warn!(
                    "Some transports failed ({} of {}): {:?}",
                    errors.len(),
                    transport_count,
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

    async fn submit_ack_tombstone(&self, tombstone: SignedAckTombstone) -> Result<(), TransportError> {
        self.broadcast(|t| {
            let ts = tombstone.clone();
            async move { t.submit_ack_tombstone(ts).await }
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

        async fn submit_ack_tombstone(&self, _tombstone: SignedAckTombstone) -> Result<(), TransportError> {
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
            ack_hash: [0u8; 16],
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

    #[tokio::test]
    async fn test_add_transport_at_runtime() {
        let call_count = Arc::new(AtomicUsize::new(0));

        // Start with one transport
        let composite = CompositeTransport::new()
            .with_transport(MockTransport::new(call_count.clone(), false));
        assert_eq!(composite.len(), 1);

        // Add another at runtime
        composite.add_transport(MockTransport::new(call_count.clone(), false)).await;
        assert_eq!(composite.len_async().await, 2);

        // Both transports should be called
        let envelope = make_test_envelope();
        let result = composite.submit_message(envelope).await;
        assert!(result.is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }
}
