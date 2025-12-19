//! Transport coordinator for unified multi-transport messaging.
//!
//! This module provides `TransportCoordinator`, which manages multiple
//! transport pools (HTTP, MQTT) with configurable routing strategies.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::join_all;
use reme_message::{OuterEnvelope, RoutingKey, TombstoneEnvelope};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::http_target::HttpTarget;
use crate::pool::TransportPool;
use crate::receiver::ReceiverConfig;
use crate::seen_cache::SharedSeenCache;
use crate::target::TransportTarget;
use crate::{EventReceiver, EventSender, Transport, TransportError, TransportEvent};

#[cfg(feature = "mqtt")]
use crate::mqtt_target::MqttTarget;

/// Type alias for boxed futures used in broadcast operations.
type BoxedFuture = Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send>>;

/// Routing strategy for outgoing messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RoutingStrategy {
    /// Send to all transports in parallel (default).
    /// Success if at least one transport succeeds.
    #[default]
    BroadcastAll,

    /// Try direct/ephemeral targets first, fall back to stable.
    /// Useful for P2P-first with mailbox fallback.
    DirectFirst,

    /// Try HTTP only (skip MQTT if available).
    HttpOnly,

    /// Try MQTT only (skip HTTP if available).
    #[cfg(feature = "mqtt")]
    MqttOnly,
}

/// Configuration for the transport coordinator.
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// Default routing strategy for outgoing messages.
    pub routing_strategy: RoutingStrategy,

    /// Configuration for polling (HTTP only).
    pub receiver_config: ReceiverConfig,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            routing_strategy: RoutingStrategy::BroadcastAll,
            receiver_config: ReceiverConfig::default(),
        }
    }
}

/// Handle to control a running coordinator subscription.
pub struct CoordinatorHandle {
    cancel_token: CancellationToken,
}

impl CoordinatorHandle {
    /// Stop all receiver tasks.
    pub fn stop(&self) {
        self.cancel_token.cancel();
    }
}

impl Drop for CoordinatorHandle {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

/// Unified transport coordinator for multiple transport pools.
///
/// The coordinator manages HTTP and MQTT transport pools with:
/// - Configurable routing strategies for outgoing messages
/// - Unified event channel for incoming messages
/// - Shared deduplication cache across transports
/// - Health-aware target selection
///
/// # Example
///
/// ```ignore
/// use reme_transport::{TransportCoordinator, CoordinatorConfig};
/// use reme_transport::http_target::{HttpTarget, HttpTargetConfig};
///
/// let mut coordinator = TransportCoordinator::new(CoordinatorConfig::default());
///
/// // Add HTTP targets
/// let http_pool = TransportPool::single("https://mailbox.example.com:23003")?;
/// coordinator.set_http_pool(http_pool);
///
/// // Subscribe to messages
/// let (events, handle) = coordinator.subscribe(routing_key);
/// while let Some(event) = events.recv().await {
///     // Process events from any transport
/// }
/// ```
pub struct TransportCoordinator {
    config: CoordinatorConfig,
    http_pool: Option<Arc<TransportPool<HttpTarget>>>,
    #[cfg(feature = "mqtt")]
    mqtt_pool: Option<Arc<TransportPool<MqttTarget>>>,
    seen_cache: Arc<SharedSeenCache>,
}

impl TransportCoordinator {
    /// Create a new transport coordinator with the given configuration.
    pub fn new(config: CoordinatorConfig) -> Self {
        Self {
            config,
            http_pool: None,
            #[cfg(feature = "mqtt")]
            mqtt_pool: None,
            seen_cache: Arc::new(SharedSeenCache::with_defaults()),
        }
    }

    /// Create a coordinator with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CoordinatorConfig::default())
    }

    /// Set the HTTP transport pool.
    pub fn set_http_pool(&mut self, pool: TransportPool<HttpTarget>) {
        self.http_pool = Some(Arc::new(pool));
    }

    /// Set the HTTP transport pool (Arc version).
    pub fn set_http_pool_arc(&mut self, pool: Arc<TransportPool<HttpTarget>>) {
        self.http_pool = Some(pool);
    }

    /// Set the MQTT transport pool.
    #[cfg(feature = "mqtt")]
    pub fn set_mqtt_pool(&mut self, pool: TransportPool<MqttTarget>) {
        self.mqtt_pool = Some(Arc::new(pool));
    }

    /// Set the MQTT transport pool (Arc version).
    #[cfg(feature = "mqtt")]
    pub fn set_mqtt_pool_arc(&mut self, pool: Arc<TransportPool<MqttTarget>>) {
        self.mqtt_pool = Some(pool);
    }

    /// Get the shared seen cache for deduplication.
    pub fn seen_cache(&self) -> &Arc<SharedSeenCache> {
        &self.seen_cache
    }

    /// Set the routing strategy.
    pub fn set_routing_strategy(&mut self, strategy: RoutingStrategy) {
        self.config.routing_strategy = strategy;
    }

    /// Check if any transport pools are available.
    pub fn has_transports(&self) -> bool {
        let has_http = self.http_pool.as_ref().map_or(false, |p| p.has_available());
        #[cfg(feature = "mqtt")]
        let has_mqtt = self.mqtt_pool.as_ref().map_or(false, |p| p.has_available());
        #[cfg(not(feature = "mqtt"))]
        let has_mqtt = false;

        has_http || has_mqtt
    }

    /// Get health summary across all transports.
    pub fn health_summary(&self) -> CoordinatorHealth {
        let http_health = self.http_pool.as_ref().map(|p| p.health_summary());
        #[cfg(feature = "mqtt")]
        let mqtt_health = self.mqtt_pool.as_ref().map(|p| p.health_summary());
        #[cfg(not(feature = "mqtt"))]
        let mqtt_health: Option<crate::pool::PoolHealthSummary> = None;

        CoordinatorHealth {
            http: http_health,
            mqtt: mqtt_health,
        }
    }

    /// Subscribe to messages for a routing key from all transports.
    ///
    /// Returns a unified event channel and a handle to stop all receivers.
    pub fn subscribe(&self, routing_key: RoutingKey) -> (EventReceiver, CoordinatorHandle) {
        let (tx, rx) = mpsc::unbounded_channel();
        let cancel_token = CancellationToken::new();

        // Spawn HTTP polling if available
        if let Some(ref pool) = self.http_pool {
            self.spawn_http_receiver(
                pool.clone(),
                routing_key.clone(),
                tx.clone(),
                cancel_token.clone(),
            );
        }

        // MQTT subscription would be added here when MqttTarget supports receiving
        // For now, MQTT is send-only in this implementation

        let handle = CoordinatorHandle { cancel_token };
        (rx, handle)
    }

    /// Spawn an HTTP polling receiver task.
    fn spawn_http_receiver(
        &self,
        pool: Arc<TransportPool<HttpTarget>>,
        routing_key: RoutingKey,
        tx: EventSender,
        cancel_token: CancellationToken,
    ) {
        let config = self.config.receiver_config;
        let seen_cache = self.seen_cache.clone();

        tokio::spawn(async move {
            use tokio::time::{interval, MissedTickBehavior};

            let mut poll_interval = interval(config.poll_interval);
            poll_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            debug!(
                "Coordinator: started HTTP polling for {:?}",
                &routing_key[..4]
            );

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        debug!("Coordinator: HTTP polling cancelled");
                        break;
                    }
                    _ = poll_interval.tick() => {
                        match pool.fetch_once(&routing_key).await {
                            Ok(messages) => {
                                for envelope in messages {
                                    // Deduplicate across transports
                                    if seen_cache.check_and_mark(&envelope.message_id) {
                                        if tx.send(TransportEvent::Message(envelope)).is_err() {
                                            debug!("Coordinator: channel closed");
                                            return;
                                        }
                                    } else {
                                        trace!("Coordinator: duplicate message skipped");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Coordinator: HTTP fetch error: {}", e);
                                if tx.send(TransportEvent::Error(e.to_string())).is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    /// Submit a message using the configured routing strategy.
    async fn submit_with_strategy(
        &self,
        envelope: OuterEnvelope,
    ) -> Result<(), TransportError> {
        match self.config.routing_strategy {
            RoutingStrategy::BroadcastAll => self.broadcast_message(envelope).await,
            RoutingStrategy::DirectFirst => self.direct_first_message(envelope).await,
            RoutingStrategy::HttpOnly => self.http_only_message(envelope).await,
            #[cfg(feature = "mqtt")]
            RoutingStrategy::MqttOnly => self.mqtt_only_message(envelope).await,
        }
    }

    /// Submit a tombstone using the configured routing strategy.
    async fn submit_tombstone_with_strategy(
        &self,
        tombstone: TombstoneEnvelope,
    ) -> Result<(), TransportError> {
        match self.config.routing_strategy {
            RoutingStrategy::BroadcastAll => self.broadcast_tombstone(tombstone).await,
            RoutingStrategy::DirectFirst => self.direct_first_tombstone(tombstone).await,
            RoutingStrategy::HttpOnly => self.http_only_tombstone(tombstone).await,
            #[cfg(feature = "mqtt")]
            RoutingStrategy::MqttOnly => self.mqtt_only_tombstone(tombstone).await,
        }
    }

    /// Broadcast message to all available transports.
    async fn broadcast_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        let mut futures: Vec<BoxedFuture> = Vec::new();

        if let Some(ref pool) = self.http_pool {
            let env = envelope.clone();
            let pool = pool.clone();
            futures.push(Box::pin(async move {
                pool.submit_message(env).await
            }));
        }

        #[cfg(feature = "mqtt")]
        if let Some(ref pool) = self.mqtt_pool {
            let env = envelope.clone();
            let pool = pool.clone();
            futures.push(Box::pin(async move {
                pool.submit_message(env).await
            }));
        }

        if futures.is_empty() {
            return Err(TransportError::Network("No transports configured".to_string()));
        }

        self.await_any_success(futures).await
    }

    /// Broadcast tombstone to all available transports.
    async fn broadcast_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), TransportError> {
        let mut futures: Vec<BoxedFuture> = Vec::new();

        if let Some(ref pool) = self.http_pool {
            let ts = tombstone.clone();
            let pool = pool.clone();
            futures.push(Box::pin(async move {
                pool.submit_tombstone(ts).await
            }));
        }

        #[cfg(feature = "mqtt")]
        if let Some(ref pool) = self.mqtt_pool {
            let ts = tombstone.clone();
            let pool = pool.clone();
            futures.push(Box::pin(async move {
                pool.submit_tombstone(ts).await
            }));
        }

        if futures.is_empty() {
            return Err(TransportError::Network("No transports configured".to_string()));
        }

        self.await_any_success(futures).await
    }

    /// Try direct/ephemeral targets first, fall back to stable.
    async fn direct_first_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        // Try ephemeral HTTP targets first
        if let Some(ref pool) = self.http_pool {
            let ephemeral = pool.targets_by_kind(crate::target::TargetKind::Ephemeral);
            if !ephemeral.is_empty() {
                for target in ephemeral {
                    if target.is_available() {
                        if target.submit_message(envelope.clone()).await.is_ok() {
                            return Ok(());
                        }
                    }
                }
            }
        }

        // Fall back to broadcast
        self.broadcast_message(envelope).await
    }

    /// Try direct/ephemeral targets first for tombstones.
    async fn direct_first_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), TransportError> {
        if let Some(ref pool) = self.http_pool {
            let ephemeral = pool.targets_by_kind(crate::target::TargetKind::Ephemeral);
            if !ephemeral.is_empty() {
                for target in ephemeral {
                    if target.is_available() {
                        if target.submit_tombstone(tombstone.clone()).await.is_ok() {
                            return Ok(());
                        }
                    }
                }
            }
        }

        self.broadcast_tombstone(tombstone).await
    }

    /// HTTP-only message submission.
    async fn http_only_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        if let Some(ref pool) = self.http_pool {
            pool.submit_message(envelope).await
        } else {
            Err(TransportError::Network("No HTTP transport configured".to_string()))
        }
    }

    /// HTTP-only tombstone submission.
    async fn http_only_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), TransportError> {
        if let Some(ref pool) = self.http_pool {
            pool.submit_tombstone(tombstone).await
        } else {
            Err(TransportError::Network("No HTTP transport configured".to_string()))
        }
    }

    /// MQTT-only message submission.
    #[cfg(feature = "mqtt")]
    async fn mqtt_only_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        if let Some(ref pool) = self.mqtt_pool {
            pool.submit_message(envelope).await
        } else {
            Err(TransportError::Network("No MQTT transport configured".to_string()))
        }
    }

    /// MQTT-only tombstone submission.
    #[cfg(feature = "mqtt")]
    async fn mqtt_only_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), TransportError> {
        if let Some(ref pool) = self.mqtt_pool {
            pool.submit_tombstone(tombstone).await
        } else {
            Err(TransportError::Network("No MQTT transport configured".to_string()))
        }
    }

    /// Wait for any future to succeed, or return error if all fail.
    async fn await_any_success<F>(&self, futures: Vec<F>) -> Result<(), TransportError>
    where
        F: std::future::Future<Output = Result<(), TransportError>>,
    {
        let results = join_all(futures).await;

        let success_count = results.iter().filter(|r| r.is_ok()).count();
        let errors: Vec<_> = results.into_iter().filter_map(|r| r.err()).collect();

        if success_count > 0 {
            trace!("Broadcast succeeded on {} transport(s)", success_count);
            if !errors.is_empty() {
                warn!(
                    "Some transports failed: {:?}",
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

/// Health summary across all transport pools.
#[derive(Debug, Clone)]
pub struct CoordinatorHealth {
    /// HTTP pool health (if configured).
    pub http: Option<crate::pool::PoolHealthSummary>,
    /// MQTT pool health (if configured).
    pub mqtt: Option<crate::pool::PoolHealthSummary>,
}

impl CoordinatorHealth {
    /// Check if any transport has healthy targets.
    pub fn has_healthy(&self) -> bool {
        self.http.as_ref().map_or(false, |h| h.healthy > 0)
            || self.mqtt.as_ref().map_or(false, |h| h.healthy > 0)
    }

    /// Get total healthy target count.
    pub fn total_healthy(&self) -> usize {
        self.http.as_ref().map_or(0, |h| h.healthy)
            + self.mqtt.as_ref().map_or(0, |h| h.healthy)
    }
}

#[async_trait]
impl Transport for TransportCoordinator {
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        self.submit_with_strategy(envelope).await
    }

    async fn submit_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), TransportError> {
        self.submit_tombstone_with_strategy(tombstone).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CoordinatorConfig::default();
        assert_eq!(config.routing_strategy, RoutingStrategy::BroadcastAll);
    }

    #[test]
    fn test_coordinator_creation() {
        let coordinator = TransportCoordinator::with_defaults();
        assert!(!coordinator.has_transports());
    }

    #[test]
    fn test_health_summary_empty() {
        let coordinator = TransportCoordinator::with_defaults();
        let health = coordinator.health_summary();
        assert!(!health.has_healthy());
        assert_eq!(health.total_healthy(), 0);
    }

    #[test]
    fn test_routing_strategy_change() {
        let mut coordinator = TransportCoordinator::with_defaults();
        assert_eq!(coordinator.config.routing_strategy, RoutingStrategy::BroadcastAll);

        coordinator.set_routing_strategy(RoutingStrategy::DirectFirst);
        assert_eq!(coordinator.config.routing_strategy, RoutingStrategy::DirectFirst);
    }
}
