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

use crate::delivery::{
    DeliveryResult, DeliveryTier, TargetResult, TierResult, TieredDeliveryConfig,
};
use crate::http_target::HttpTarget;
use crate::pool::TransportPool;
use crate::receiver::ReceiverConfig;
use crate::seen_cache::SharedSeenCache;
use crate::target::{TargetId, TargetKind, TransportTarget};
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
///
/// When this handle is dropped, all receiver tasks will be automatically
/// cancelled via the internal `CancellationToken`. This ensures clean
/// resource cleanup but may be surprising if the handle is stored in a
/// scope that ends prematurely.
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
    ///
    /// # Note
    ///
    /// Uses an unbounded channel for events. If the consumer is slow,
    /// messages will accumulate in memory. For high-throughput scenarios,
    /// ensure the receiver processes events promptly.
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

        self.broadcast_await_any_success(futures).await
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

        self.broadcast_await_any_success(futures).await
    }

    /// Try direct/ephemeral targets first, fall back to stable.
    async fn direct_first_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        // Try ephemeral HTTP targets first
        if let Some(ref pool) = self.http_pool {
            let ephemeral = pool.targets_by_kind(crate::target::TargetKind::Ephemeral);
            if !ephemeral.is_empty() {
                for target in ephemeral {
                    if target.is_available() {
                        match target.submit_message(envelope.clone()).await {
                            Ok(()) => return Ok(()),
                            Err(e) => {
                                debug!(
                                    target = %target.id(),
                                    error = %e,
                                    "Ephemeral target failed, trying next"
                                );
                            }
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
                        match target.submit_tombstone(tombstone.clone()).await {
                            Ok(()) => return Ok(()),
                            Err(e) => {
                                debug!(
                                    target = %target.id(),
                                    error = %e,
                                    "Ephemeral target failed tombstone, trying next"
                                );
                            }
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

    /// Run all futures to completion, succeed if at least one succeeds.
    ///
    /// Unlike a true "race" that cancels on first success, this waits for
    /// all futures to complete to ensure delivery attempts to all transports.
    /// Returns `Ok(())` if any transport succeeded, or an error with all
    /// failure messages if all transports failed.
    async fn broadcast_await_any_success<F>(&self, futures: Vec<F>) -> Result<(), TransportError>
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

    // ========================================================================
    // TIERED DELIVERY WITH QUORUM
    // ========================================================================

    /// Submit message through delivery tiers with quorum semantics.
    ///
    /// Tiers are attempted in order:
    /// 1. **Direct**: Race all ephemeral targets, exit on any success
    /// 2. **Quorum**: Broadcast to all stable targets, require quorum
    /// 3. **Best-Effort**: Future expansion (BLE, LoRa)
    ///
    /// Returns a `DeliveryResult` with per-target outcomes and confidence level.
    pub async fn submit_tiered(
        &self,
        envelope: &OuterEnvelope,
        config: &TieredDeliveryConfig,
    ) -> DeliveryResult {
        let mut all_results: Vec<TargetResult> = Vec::new();

        // Tier 1: Direct (race all ephemeral targets)
        let direct_result = self.try_direct_tier(envelope, config).await;
        let direct_success = direct_result.any_success();
        let direct_target = direct_result.first_success_target();
        all_results.extend(direct_result.results);

        if direct_success {
            if let Some(target) = direct_target {
                debug!(target = %target, "Direct tier succeeded");
                return DeliveryResult::direct_delivery(target, all_results);
            }
        }

        // Tier 2: Quorum (broadcast all stable targets, require quorum)
        let quorum_result = self.try_quorum_tier_all(envelope, config).await;
        let success_count = quorum_result.success_count();
        let total_targets = self.quorum_target_count(config);
        all_results.extend(quorum_result.results);

        let required = config.quorum.required_count(total_targets);

        if config.quorum.is_satisfied(success_count, total_targets) {
            debug!(
                success = success_count,
                required = required,
                total = total_targets,
                "Quorum tier succeeded"
            );
            return DeliveryResult::quorum_delivery(
                success_count,
                required,
                DeliveryTier::Quorum,
                all_results,
            );
        }

        // Tier 3: Best-Effort (future - BLE, LoRa)
        // Would add best-effort tier here when implemented

        // Quorum not reached
        debug!(
            success = success_count,
            required = required,
            total = total_targets,
            "Quorum not reached"
        );
        DeliveryResult::partial(success_count, required, all_results)
    }

    /// Try Direct tier: race all ephemeral targets, return on first success.
    ///
    /// This tier is for direct delivery where the recipient
    /// (or their proxy) directly receives the message.
    pub async fn try_direct_tier(
        &self,
        envelope: &OuterEnvelope,
        config: &TieredDeliveryConfig,
    ) -> TierResult {
        let mut tier_result = TierResult::new(DeliveryTier::Direct);

        // Collect all ephemeral targets from HTTP pool
        let mut targets: Vec<Arc<HttpTarget>> = Vec::new();
        if let Some(ref pool) = self.http_pool {
            for target in pool.targets_by_kind(TargetKind::Ephemeral) {
                if !config.is_excluded(target.id()) && target.is_available() {
                    targets.push(target);
                }
            }
        }

        if targets.is_empty() {
            trace!("Direct tier: no ephemeral targets available");
            return tier_result;
        }

        // Race all targets - first success wins
        use tokio::time::timeout;

        for target in targets {
            let target_id = target.id().clone();

            // Try each target with the tier timeout
            let result = timeout(
                config.direct_tier_timeout,
                target.submit_message(envelope.clone()),
            )
            .await;

            match result {
                Ok(Ok(())) => {
                    // Success! Record and return immediately
                    tier_result.push(TargetResult::success(
                        target_id,
                        DeliveryTier::Direct,
                        config.direct_tier_timeout, // Approximate latency
                    ));
                    return tier_result;
                }
                Ok(Err(e)) => {
                    tier_result.push(TargetResult::failed(
                        target_id,
                        DeliveryTier::Direct,
                        e,
                    ));
                }
                Err(_) => {
                    tier_result.push(TargetResult::timeout(target_id, DeliveryTier::Direct));
                }
            }
        }

        tier_result
    }

    /// Try Quorum tier: broadcast to ALL stable targets.
    ///
    /// This tier sends to all HTTP mailboxes and MQTT brokers in parallel.
    /// Used for initial delivery and maintenance refreshes.
    pub async fn try_quorum_tier_all(
        &self,
        envelope: &OuterEnvelope,
        config: &TieredDeliveryConfig,
    ) -> TierResult {
        self.submit_to_quorum_targets(envelope, config, None).await
    }

    /// Try Quorum tier: broadcast to SELECTED targets only.
    ///
    /// This is more efficient for retries where some targets already succeeded.
    /// Only attempts delivery to the specified target IDs.
    pub async fn try_quorum_tier_selective(
        &self,
        envelope: &OuterEnvelope,
        target_ids: &[TargetId],
        config: &TieredDeliveryConfig,
    ) -> TierResult {
        self.submit_to_quorum_targets(envelope, config, Some(target_ids)).await
    }

    /// Submit envelope to Quorum tier targets (HTTP stable + MQTT) in parallel.
    ///
    /// If `filter_ids` is Some, only targets with matching IDs are attempted.
    async fn submit_to_quorum_targets(
        &self,
        envelope: &OuterEnvelope,
        config: &TieredDeliveryConfig,
        filter_ids: Option<&[TargetId]>,
    ) -> TierResult {
        use std::time::Instant;

        let mut tier_result = TierResult::new(DeliveryTier::Quorum);
        let tier = DeliveryTier::Quorum;

        // Collect HTTP stable targets
        let http_targets: Vec<Arc<HttpTarget>> = self.http_pool
            .as_ref()
            .map(|pool| {
                pool.targets_by_kind(TargetKind::Stable)
                    .into_iter()
                    .filter(|t| {
                        !config.is_excluded(t.id())
                            && t.is_available()
                            && filter_ids.map_or(true, |ids| ids.contains(t.id()))
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Collect MQTT targets
        #[cfg(feature = "mqtt")]
        let mqtt_targets: Vec<Arc<MqttTarget>> = self.mqtt_pool
            .as_ref()
            .map(|pool| {
                pool.all_targets()
                    .into_iter()
                    .filter(|t| {
                        !config.is_excluded(t.id())
                            && t.is_available()
                            && filter_ids.map_or(true, |ids| ids.contains(t.id()))
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Build futures for HTTP targets
        let http_futures: Vec<_> = http_targets
            .into_iter()
            .map(|target| {
                let target_id = target.id().clone();
                let env = envelope.clone();
                async move {
                    let start = Instant::now();
                    let result = target.submit_message(env).await;
                    let latency = start.elapsed();
                    (target_id, result, latency)
                }
            })
            .collect();

        // Build futures for MQTT targets
        #[cfg(feature = "mqtt")]
        let mqtt_futures: Vec<_> = mqtt_targets
            .into_iter()
            .map(|target| {
                let target_id = target.id().clone();
                let env = envelope.clone();
                async move {
                    let start = Instant::now();
                    let result = target.submit_message(env).await;
                    let latency = start.elapsed();
                    (target_id, result, latency)
                }
            })
            .collect();

        // Execute all in parallel
        let http_results = join_all(http_futures).await;
        #[cfg(feature = "mqtt")]
        let mqtt_results = join_all(mqtt_futures).await;

        // Convert HTTP results
        for (target_id, result, latency) in http_results {
            match result {
                Ok(()) => tier_result.push(TargetResult::success(target_id, tier, latency)),
                Err(e) => tier_result.push(TargetResult::failed(target_id, tier, e)),
            }
        }

        // Convert MQTT results
        #[cfg(feature = "mqtt")]
        for (target_id, result, latency) in mqtt_results {
            match result {
                Ok(()) => tier_result.push(TargetResult::success(target_id, tier, latency)),
                Err(e) => tier_result.push(TargetResult::failed(target_id, tier, e)),
            }
        }

        tier_result
    }

    /// Get count of Quorum tier targets (for quorum calculation).
    pub fn quorum_target_count(&self, config: &TieredDeliveryConfig) -> u32 {
        let mut count = 0u32;

        // Count HTTP stable targets
        if let Some(ref pool) = self.http_pool {
            count += pool
                .targets_by_kind(TargetKind::Stable)
                .iter()
                .filter(|t| !config.is_excluded(t.id()) && t.is_available())
                .count() as u32;
        }

        // Count MQTT targets
        #[cfg(feature = "mqtt")]
        if let Some(ref pool) = self.mqtt_pool {
            count += pool
                .all_targets()
                .iter()
                .filter(|t| !config.is_excluded(t.id()) && t.is_available())
                .count() as u32;
        }

        count
    }

    /// Get all Quorum tier target IDs (for filtering in retry logic).
    ///
    /// Returns target IDs of all stable HTTP and MQTT targets.
    pub fn quorum_target_ids(&self, config: &TieredDeliveryConfig) -> Vec<TargetId> {
        let mut ids = Vec::new();

        // HTTP stable target IDs
        if let Some(ref pool) = self.http_pool {
            for target in pool.targets_by_kind(TargetKind::Stable) {
                if !config.is_excluded(target.id()) && target.is_available() {
                    ids.push(target.id().clone());
                }
            }
        }

        // MQTT target IDs
        #[cfg(feature = "mqtt")]
        if let Some(ref pool) = self.mqtt_pool {
            for target in pool.all_targets() {
                if !config.is_excluded(target.id()) && target.is_available() {
                    ids.push(target.id().clone());
                }
            }
        }

        ids
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
    use crate::delivery::QuorumStrategy;

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

    // ========================================================================
    // TIERED DELIVERY TESTS
    // ========================================================================

    #[test]
    fn test_quorum_target_count_empty() {
        let coordinator = TransportCoordinator::with_defaults();
        let config = TieredDeliveryConfig::default();
        assert_eq!(coordinator.quorum_target_count(&config), 0);
    }

    #[test]
    fn test_quorum_target_ids_empty() {
        let coordinator = TransportCoordinator::with_defaults();
        let config = TieredDeliveryConfig::default();
        assert!(coordinator.quorum_target_ids(&config).is_empty());
    }

    #[test]
    fn test_tiered_delivery_config_defaults() {
        let config = TieredDeliveryConfig::default();
        assert_eq!(config.quorum, QuorumStrategy::Any);
        assert!(config.maintenance_enabled);
        assert!(config.excluded_targets.is_empty());
    }

    #[test]
    fn test_tiered_delivery_config_builder() {
        let excluded = TargetId::http("https://excluded.example.com");
        let config = TieredDeliveryConfig::default()
            .with_quorum(QuorumStrategy::Count(2))
            .with_excluded_target(excluded.clone())
            .without_maintenance();

        assert_eq!(config.quorum, QuorumStrategy::Count(2));
        assert!(!config.maintenance_enabled);
        assert!(config.is_excluded(&excluded));
    }

    #[tokio::test]
    async fn test_tiered_submit_empty_coordinator() {
        use reme_message::{OuterEnvelope, RoutingKey, MessageID, CURRENT_VERSION};

        let coordinator = TransportCoordinator::with_defaults();
        let config = TieredDeliveryConfig::default();

        // Create a test envelope
        let envelope = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key: RoutingKey::from_bytes([1u8; 16]),
            message_id: MessageID::from_bytes([2u8; 16]),
            timestamp_hours: 0,
            ttl_hours: None,
            ephemeral_key: [3u8; 32],
            inner_ciphertext: vec![1, 2, 3],
        };

        let result = coordinator.submit_tiered(&envelope, &config).await;

        // With no transports, quorum cannot be reached
        assert!(!result.quorum_reached);
        assert!(result.target_results.is_empty());
        assert!(result.completed_tier.is_none());
    }

    #[tokio::test]
    async fn test_direct_tier_empty() {
        use reme_message::{OuterEnvelope, RoutingKey, MessageID, CURRENT_VERSION};

        let coordinator = TransportCoordinator::with_defaults();
        let config = TieredDeliveryConfig::default();

        let envelope = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key: RoutingKey::from_bytes([1u8; 16]),
            message_id: MessageID::from_bytes([2u8; 16]),
            timestamp_hours: 0,
            ttl_hours: None,
            ephemeral_key: [3u8; 32],
            inner_ciphertext: vec![1, 2, 3],
        };

        let result = coordinator.try_direct_tier(&envelope, &config).await;

        assert!(!result.any_success());
        assert_eq!(result.success_count(), 0);
        assert!(result.results.is_empty());
    }

    #[tokio::test]
    async fn test_quorum_tier_empty() {
        use reme_message::{OuterEnvelope, RoutingKey, MessageID, CURRENT_VERSION};

        let coordinator = TransportCoordinator::with_defaults();
        let config = TieredDeliveryConfig::default();

        let envelope = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key: RoutingKey::from_bytes([1u8; 16]),
            message_id: MessageID::from_bytes([2u8; 16]),
            timestamp_hours: 0,
            ttl_hours: None,
            ephemeral_key: [3u8; 32],
            inner_ciphertext: vec![1, 2, 3],
        };

        let result = coordinator.try_quorum_tier_all(&envelope, &config).await;

        assert!(!result.any_success());
        assert_eq!(result.success_count(), 0);
        assert!(result.results.is_empty());
    }
}
