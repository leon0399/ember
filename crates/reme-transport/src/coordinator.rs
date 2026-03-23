//! Transport coordinator for unified multi-transport messaging.
//!
//! This module provides `TransportCoordinator`, which manages multiple
//! transport pools (HTTP, MQTT) with configurable routing strategies.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use derivative::Derivative;
use futures::future::join_all;
use reme_message::{OuterEnvelope, RoutingKey, SignedAckTombstone};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::delivery::{
    DeliveryResult, DeliveryTier, TargetResult, TierResult, TieredDeliveryConfig,
};
use crate::http_target::HttpTarget;
use crate::pool::TransportPool;
use crate::query::{HealthSummary, TargetSnapshot, TransportQuery};
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
#[derive(Debug, Clone, Derivative)]
#[derivative(Default)]
pub struct CoordinatorConfig {
    /// Default routing strategy for outgoing messages.
    pub routing_strategy: RoutingStrategy,

    /// How often to poll HTTP targets for new messages.
    #[derivative(Default(value = "Duration::from_secs(5)"))]
    pub poll_interval: Duration,
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

    /// Get a reference to the HTTP pool (for cases needing direct access).
    pub fn http_pool(&self) -> Option<&Arc<TransportPool<HttpTarget>>> {
        self.http_pool.as_ref()
    }

    /// Get a reference to the MQTT pool (for cases needing direct access).
    #[cfg(feature = "mqtt")]
    pub fn mqtt_pool(&self) -> Option<&Arc<TransportPool<MqttTarget>>> {
        self.mqtt_pool.as_ref()
    }

    /// Add an HTTP target at runtime (for discovered peers).
    pub fn add_http_target(&self, target: HttpTarget) {
        if let Some(ref pool) = self.http_pool {
            pool.add_target(target);
        }
    }

    /// Remove an HTTP target by ID (when peer disappears).
    pub fn remove_http_target(&self, id: &TargetId) -> bool {
        self.http_pool
            .as_ref()
            .is_some_and(|pool| pool.remove_target(id))
    }

    /// Replace an HTTP target atomically (e.g. when a discovered peer's address changes).
    ///
    /// Removes the target matching `old_id` (if present) and adds `new_target`
    /// under a single pool write lock, so concurrent senders never observe a
    /// state where neither target exists. Always adds `new_target` even if
    /// `old_id` was not found (upsert semantics).
    ///
    /// Returns `true` if a target with `old_id` was found and removed.
    pub fn replace_http_target(&self, old_id: &TargetId, new_target: HttpTarget) -> bool {
        if let Some(ref pool) = self.http_pool {
            pool.replace_target(old_id, new_target)
        } else {
            false
        }
    }

    /// Check if any transport pools are available.
    pub fn has_transports(&self) -> bool {
        let has_http = self.http_pool.as_ref().is_some_and(|p| p.has_available());
        #[cfg(feature = "mqtt")]
        let has_mqtt = self.mqtt_pool.as_ref().is_some_and(|p| p.has_available());
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
            self.spawn_http_receiver(pool.clone(), routing_key, tx.clone(), cancel_token.clone());
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
        let poll_duration = self.config.poll_interval;
        let seen_cache = self.seen_cache.clone();

        tokio::spawn(async move {
            use tokio::time::{interval, MissedTickBehavior};

            let mut poll_interval = interval(poll_duration);
            poll_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            debug!(
                "Coordinator: started HTTP polling for {:?}",
                &routing_key[..4]
            );

            loop {
                tokio::select! {
                    () = cancel_token.cancelled() => {
                        debug!("Coordinator: HTTP polling cancelled");
                        break;
                    }
                    _ = poll_interval.tick() => {
                        match pool.fetch_once(&routing_key).await {
                            Ok(messages) => {
                                // Collect IDs to mark after forwarding, so
                                // byte-distinct variants within the same batch
                                // are not suppressed by check_and_mark.
                                let mut ids_to_mark = Vec::new();
                                for envelope in messages {
                                    // Cross-poll dedup: skip messages already
                                    // forwarded in a previous poll cycle.
                                    if seen_cache.was_seen(&envelope.message_id) {
                                        trace!("Coordinator: duplicate message skipped");
                                        continue;
                                    }
                                    ids_to_mark.push(envelope.message_id);
                                    if tx.send(TransportEvent::Message(envelope)).is_err() {
                                        debug!("Coordinator: channel closed");
                                        return;
                                    }
                                }
                                for id in &ids_to_mark {
                                    seen_cache.mark(id);
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
    async fn submit_with_strategy(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        match self.config.routing_strategy {
            RoutingStrategy::BroadcastAll => self.broadcast_message(envelope).await,
            RoutingStrategy::DirectFirst => self.direct_first_message(envelope).await,
            RoutingStrategy::HttpOnly => self.http_only_message(envelope).await,
            #[cfg(feature = "mqtt")]
            RoutingStrategy::MqttOnly => self.mqtt_only_message(envelope).await,
        }
    }

    /// Broadcast message to all available transports.
    async fn broadcast_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        let mut futures: Vec<BoxedFuture> = Vec::new();

        if let Some(ref pool) = self.http_pool {
            let env = envelope.clone();
            let pool = pool.clone();
            futures.push(Box::pin(async move { pool.submit_message(env).await }));
        }

        #[cfg(feature = "mqtt")]
        if let Some(ref pool) = self.mqtt_pool {
            let env = envelope.clone();
            let pool = pool.clone();
            futures.push(Box::pin(async move { pool.submit_message(env).await }));
        }

        if futures.is_empty() {
            return Err(TransportError::Network(
                "No transports configured".to_string(),
            ));
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
                        match TransportTarget::submit_message(&*target, envelope.clone()).await {
                            Ok(_receipt) => return Ok(()),
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

    /// HTTP-only message submission.
    async fn http_only_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        if let Some(ref pool) = self.http_pool {
            pool.submit_message(envelope).await
        } else {
            Err(TransportError::Network(
                "No HTTP transport configured".to_string(),
            ))
        }
    }

    /// MQTT-only message submission.
    #[cfg(feature = "mqtt")]
    async fn mqtt_only_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        if let Some(ref pool) = self.mqtt_pool {
            pool.submit_message(envelope).await
        } else {
            Err(TransportError::Network(
                "No MQTT transport configured".to_string(),
            ))
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
        let errors: Vec<_> = results
            .into_iter()
            .filter_map(std::result::Result::err)
            .collect();

        if success_count > 0 {
            trace!("Broadcast succeeded on {} transport(s)", success_count);
            if !errors.is_empty() {
                warn!(
                    "Some transports failed: {:?}",
                    errors
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>()
                );
            }
            Ok(())
        } else {
            Err(TransportError::Network(format!(
                "All transports failed: {:?}",
                errors
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
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
    /// 3. **Best-Effort**: Future expansion (BLE, `LoRa`)
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
    /// (or their proxy) directly receives the message. All targets are
    /// attempted in parallel, and we return as soon as any one succeeds.
    pub async fn try_direct_tier(
        &self,
        envelope: &OuterEnvelope,
        config: &TieredDeliveryConfig,
    ) -> TierResult {
        use futures::stream::{FuturesUnordered, StreamExt};
        use std::time::Instant;
        use tokio::time::timeout;

        let mut tier_result = TierResult::new(DeliveryTier::Direct);
        let message_id = envelope.message_id;

        // Collect all ephemeral targets from HTTP pool that can serve this routing key
        let mut targets: Vec<Arc<HttpTarget>> = Vec::new();
        if let Some(ref pool) = self.http_pool {
            for target in pool.targets_by_kind(TargetKind::Ephemeral) {
                if !config.is_excluded(target.id())
                    && target.is_available()
                    && target.config().can_serve(&envelope.routing_key)
                {
                    targets.push(target);
                }
            }
        }

        if targets.is_empty() {
            trace!("Direct tier: no ephemeral targets available");
            return tier_result;
        }

        // Race all targets in parallel - first success wins
        let tier_timeout = config.direct_tier_timeout;
        let mut futures = FuturesUnordered::new();

        for target in targets {
            let target_id = target.id().clone();
            let node_pubkey = target.config().node_pubkey;
            let envelope_clone = envelope.clone();
            let target_clone = target.clone();

            futures.push(async move {
                let start = Instant::now();
                let result = timeout(
                    tier_timeout,
                    TransportTarget::submit_message(&*target_clone, envelope_clone),
                )
                .await;
                let latency = start.elapsed();
                (target_id, node_pubkey, result, latency)
            });
        }

        // Poll futures until we get a success or all have completed
        while let Some((target_id, node_pubkey, result, latency)) = futures.next().await {
            match result {
                Ok(Ok(raw_receipt)) => {
                    // Success! Verify receipt and return immediately
                    let receipt_status = raw_receipt.verify(&message_id, node_pubkey.as_ref());
                    tier_result.push(TargetResult::success(
                        target_id,
                        DeliveryTier::Direct,
                        latency,
                        receipt_status,
                    ));
                    return tier_result;
                }
                Ok(Err(e)) => {
                    tier_result.push(TargetResult::failed(target_id, DeliveryTier::Direct, e));
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
        self.submit_to_quorum_targets(envelope, config, Some(target_ids))
            .await
    }

    /// Submit envelope to Quorum tier targets (HTTP stable + MQTT) in parallel.
    ///
    /// If `filter_ids` is Some, only targets with matching IDs are attempted.
    #[allow(clippy::too_many_lines)]
    async fn submit_to_quorum_targets(
        &self,
        envelope: &OuterEnvelope,
        config: &TieredDeliveryConfig,
        filter_ids: Option<&[TargetId]>,
    ) -> TierResult {
        use std::time::Instant;
        use tokio::time::timeout;

        let mut tier_result = TierResult::new(DeliveryTier::Quorum);
        let tier = DeliveryTier::Quorum;
        let tier_timeout = config.quorum_tier_timeout;
        let message_id = envelope.message_id;

        // Collect HTTP targets with QUORUM_CREDIT capability
        let http_targets: Vec<Arc<HttpTarget>> = self
            .http_pool
            .as_ref()
            .map(|pool| {
                pool.targets_by_capability(|c| c.quorum_credit)
                    .into_iter()
                    .filter(|t| {
                        !config.is_excluded(t.id())
                            && t.is_available()
                            && filter_ids.is_none_or(|ids| ids.contains(t.id()))
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Collect MQTT targets with QUORUM_CREDIT capability (matching HTTP path)
        #[cfg(feature = "mqtt")]
        let mqtt_targets: Vec<Arc<MqttTarget>> = self
            .mqtt_pool
            .as_ref()
            .map(|pool| {
                pool.targets_by_capability(|c| c.quorum_credit)
                    .into_iter()
                    .filter(|t| {
                        !config.is_excluded(t.id())
                            && t.is_available()
                            && filter_ids.is_none_or(|ids| ids.contains(t.id()))
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Build futures for HTTP targets (with timeout)
        let http_futures: Vec<_> = http_targets
            .into_iter()
            .map(|target| {
                let target_id = target.id().clone();
                let node_pubkey = target.config().node_pubkey;
                let env = envelope.clone();
                async move {
                    let start = Instant::now();
                    let result =
                        timeout(tier_timeout, TransportTarget::submit_message(&*target, env)).await;
                    let latency = start.elapsed();
                    // Map timeout to TransportError::Timeout
                    let mapped = match result {
                        Ok(inner) => inner,
                        Err(_) => Err(TransportError::Timeout),
                    };
                    (target_id, node_pubkey, mapped, latency)
                }
            })
            .collect();

        // Build futures for MQTT targets (with timeout)
        // Note: MQTT doesn't currently return receipts, but we pass node_pubkey
        // for consistency and future-proofing
        #[cfg(feature = "mqtt")]
        let mqtt_futures: Vec<_> = mqtt_targets
            .into_iter()
            .map(|target| {
                let target_id = target.id().clone();
                let node_pubkey = target.config().node_pubkey;
                let env = envelope.clone();
                async move {
                    let start = Instant::now();
                    let result = timeout(tier_timeout, target.submit_message(env)).await;
                    let latency = start.elapsed();
                    // Map timeout to TransportError::Timeout
                    let mapped = match result {
                        Ok(inner) => inner,
                        Err(_) => Err(TransportError::Timeout),
                    };
                    (target_id, node_pubkey, mapped, latency)
                }
            })
            .collect();

        // Execute all in parallel (HTTP and MQTT concurrently)
        #[cfg(feature = "mqtt")]
        let (http_results, mqtt_results) =
            tokio::join!(join_all(http_futures), join_all(mqtt_futures));

        #[cfg(not(feature = "mqtt"))]
        let http_results = join_all(http_futures).await;

        // Convert HTTP results with receipt verification
        for (target_id, node_pubkey, result, latency) in http_results {
            match result {
                Ok(raw_receipt) => {
                    let receipt_status = raw_receipt.verify(&message_id, node_pubkey.as_ref());
                    tier_result.push(TargetResult::success(
                        target_id,
                        tier,
                        latency,
                        receipt_status,
                    ));
                }
                Err(e) => tier_result.push(TargetResult::failed(target_id, tier, e)),
            }
        }

        // Convert MQTT results (MQTT doesn't return receipts)
        #[cfg(feature = "mqtt")]
        for (target_id, node_pubkey, result, latency) in mqtt_results {
            match result {
                Ok(raw_receipt) => {
                    let receipt_status = raw_receipt.verify(&message_id, node_pubkey.as_ref());
                    tier_result.push(TargetResult::success(
                        target_id,
                        tier,
                        latency,
                        receipt_status,
                    ));
                }
                Err(e) => tier_result.push(TargetResult::failed(target_id, tier, e)),
            }
        }

        tier_result
    }

    /// Get count of Quorum tier targets (for quorum calculation).
    ///
    /// Uses `capabilities.quorum_credit` to identify targets that
    /// count toward quorum, rather than relying on `TargetKind`.
    /// Delegates to `quorum_target_ids` to avoid duplicating the filter logic.
    #[allow(clippy::cast_possible_truncation)] // Target count won't exceed u32::MAX
    pub fn quorum_target_count(&self, config: &TieredDeliveryConfig) -> u32 {
        self.quorum_target_ids(config).len() as u32
    }

    /// Get all Quorum tier target IDs (for filtering in retry logic).
    ///
    /// Returns target IDs of all targets with `QUORUM_CREDIT` capability.
    pub fn quorum_target_ids(&self, config: &TieredDeliveryConfig) -> Vec<TargetId> {
        let mut ids = Vec::new();

        // HTTP targets with QUORUM_CREDIT capability
        if let Some(ref pool) = self.http_pool {
            ids.extend(
                pool.targets_by_capability(|c| c.quorum_credit)
                    .iter()
                    .filter(|t| !config.is_excluded(t.id()) && t.is_available())
                    .map(|t| t.id().clone()),
            );
        }

        // MQTT targets with QUORUM_CREDIT capability
        #[cfg(feature = "mqtt")]
        if let Some(ref pool) = self.mqtt_pool {
            ids.extend(
                pool.targets_by_capability(|c| c.quorum_credit)
                    .iter()
                    .filter(|t| !config.is_excluded(t.id()) && t.is_available())
                    .map(|t| t.id().clone()),
            );
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
        self.http.as_ref().is_some_and(|h| h.healthy > 0)
            || self.mqtt.as_ref().is_some_and(|h| h.healthy > 0)
    }

    /// Get total healthy target count.
    pub fn total_healthy(&self) -> usize {
        self.http.as_ref().map_or(0, |h| h.healthy) + self.mqtt.as_ref().map_or(0, |h| h.healthy)
    }
}

#[async_trait]
impl Transport for TransportCoordinator {
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        self.submit_with_strategy(envelope).await
    }

    async fn submit_ack_tombstone(
        &self,
        tombstone: SignedAckTombstone,
    ) -> Result<(), TransportError> {
        // Broadcast ack tombstone to all available transports
        let mut futures: Vec<BoxedFuture> = Vec::new();

        if let Some(ref pool) = self.http_pool {
            let ts = tombstone.clone();
            let pool = pool.clone();
            futures.push(Box::pin(async move { pool.submit_ack_tombstone(ts).await }));
        }

        #[cfg(feature = "mqtt")]
        if let Some(ref pool) = self.mqtt_pool {
            let ts = tombstone.clone();
            let pool = pool.clone();
            futures.push(Box::pin(async move { pool.submit_ack_tombstone(ts).await }));
        }

        if futures.is_empty() {
            return Err(TransportError::Network(
                "No transports configured".to_string(),
            ));
        }

        self.broadcast_await_any_success(futures).await
    }
}

/// Implement `TransportQuery` for unified access to all transport targets.
impl TransportQuery for TransportCoordinator {
    fn list_targets(&self) -> Vec<TargetSnapshot> {
        let mut targets = Vec::new();

        // Collect HTTP targets
        if let Some(ref pool) = self.http_pool {
            targets.extend(TransportQuery::list_targets(pool.as_ref()));
        }

        // Collect MQTT targets
        #[cfg(feature = "mqtt")]
        if let Some(ref pool) = self.mqtt_pool {
            targets.extend(TransportQuery::list_targets(pool.as_ref()));
        }

        targets
    }

    fn health_summary(&self) -> HealthSummary {
        let mut summary = HealthSummary::new();

        // Merge HTTP pool health
        if let Some(ref pool) = self.http_pool {
            summary.merge(&TransportQuery::health_summary(pool.as_ref()));
        }

        // Merge MQTT pool health
        #[cfg(feature = "mqtt")]
        if let Some(ref pool) = self.mqtt_pool {
            summary.merge(&TransportQuery::health_summary(pool.as_ref()));
        }

        summary
    }

    fn has_available(&self) -> bool {
        self.has_transports()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::QuorumStrategy;
    use crate::target::TargetCapabilities;

    #[test]
    fn test_default_config() {
        let config = CoordinatorConfig::default();
        assert_eq!(config.routing_strategy, RoutingStrategy::BroadcastAll);
        assert_eq!(config.poll_interval, Duration::from_secs(5));
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
        assert_eq!(
            coordinator.config.routing_strategy,
            RoutingStrategy::BroadcastAll
        );

        coordinator.set_routing_strategy(RoutingStrategy::DirectFirst);
        assert_eq!(
            coordinator.config.routing_strategy,
            RoutingStrategy::DirectFirst
        );
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
        use reme_message::{MessageID, OuterEnvelope, RoutingKey, CURRENT_VERSION};

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
            ack_hash: [0u8; 16],
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
        use reme_message::{MessageID, OuterEnvelope, RoutingKey, CURRENT_VERSION};

        let coordinator = TransportCoordinator::with_defaults();
        let config = TieredDeliveryConfig::default();

        let envelope = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key: RoutingKey::from_bytes([1u8; 16]),
            message_id: MessageID::from_bytes([2u8; 16]),
            timestamp_hours: 0,
            ttl_hours: None,
            ephemeral_key: [3u8; 32],
            ack_hash: [0u8; 16],
            inner_ciphertext: vec![1, 2, 3],
        };

        let result = coordinator.try_direct_tier(&envelope, &config).await;

        assert!(!result.any_success());
        assert_eq!(result.success_count(), 0);
        assert!(result.results.is_empty());
    }

    // ========================================================================
    // COORDINATOR MUTATION API TESTS
    // ========================================================================

    #[test]
    fn test_add_http_target() {
        let mut coordinator = TransportCoordinator::with_defaults();
        let pool = TransportPool::<HttpTarget>::new();
        coordinator.set_http_pool(pool);

        let target = HttpTarget::new(crate::http_target::HttpTargetConfig::stable(
            "http://localhost:1",
        ))
        .unwrap();
        let id = target.id().clone();

        coordinator.add_http_target(target);

        let pool = coordinator.http_pool().unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.get_target(&id).is_some());
    }

    #[test]
    fn test_add_http_target_no_pool() {
        let coordinator = TransportCoordinator::with_defaults();
        let target = HttpTarget::new(crate::http_target::HttpTargetConfig::stable(
            "http://localhost:1",
        ))
        .unwrap();
        // Should not panic when no pool is configured
        coordinator.add_http_target(target);
    }

    #[test]
    fn test_remove_http_target() {
        let mut coordinator = TransportCoordinator::with_defaults();
        let pool = TransportPool::<HttpTarget>::new();
        coordinator.set_http_pool(pool);

        let target = HttpTarget::new(crate::http_target::HttpTargetConfig::stable(
            "http://localhost:1",
        ))
        .unwrap();
        let id = target.id().clone();
        coordinator.add_http_target(target);

        assert!(coordinator.remove_http_target(&id));
        assert!(!coordinator.remove_http_target(&id)); // Already removed
        assert_eq!(coordinator.http_pool().unwrap().len(), 0);
    }

    #[test]
    fn test_remove_http_target_no_pool() {
        let coordinator = TransportCoordinator::with_defaults();
        let id = TargetId::http("http://localhost:1");
        assert!(!coordinator.remove_http_target(&id));
    }

    #[test]
    fn test_replace_http_target() {
        let mut coordinator = TransportCoordinator::with_defaults();
        let pool = TransportPool::<HttpTarget>::new();
        coordinator.set_http_pool(pool);

        let target = HttpTarget::new(crate::http_target::HttpTargetConfig::stable(
            "http://localhost:1",
        ))
        .unwrap();
        let old_id = target.id().clone();
        coordinator.add_http_target(target);

        let new_target = HttpTarget::new(crate::http_target::HttpTargetConfig::stable(
            "http://localhost:2",
        ))
        .unwrap();
        let new_id = new_target.id().clone();

        assert!(coordinator.replace_http_target(&old_id, new_target));

        let pool = coordinator.http_pool().unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.get_target(&old_id).is_none());
        assert!(pool.get_target(&new_id).is_some());
    }

    #[test]
    fn test_replace_http_target_nonexistent() {
        let mut coordinator = TransportCoordinator::with_defaults();
        let pool = TransportPool::<HttpTarget>::new();
        coordinator.set_http_pool(pool);

        let old_id = TargetId::http("http://nonexistent:1");
        let new_target = HttpTarget::new(crate::http_target::HttpTargetConfig::stable(
            "http://localhost:2",
        ))
        .unwrap();

        // Returns false because old target didn't exist, but still adds new one
        assert!(!coordinator.replace_http_target(&old_id, new_target));
        assert_eq!(coordinator.http_pool().unwrap().len(), 1);
    }

    #[test]
    fn test_replace_http_target_no_pool() {
        let coordinator = TransportCoordinator::with_defaults();
        let old_id = TargetId::http("http://localhost:1");
        let new_target = HttpTarget::new(crate::http_target::HttpTargetConfig::stable(
            "http://localhost:2",
        ))
        .unwrap();
        assert!(!coordinator.replace_http_target(&old_id, new_target));
    }

    #[test]
    fn test_http_pool_accessor() {
        let coordinator = TransportCoordinator::with_defaults();
        assert!(coordinator.http_pool().is_none());

        let mut coordinator = TransportCoordinator::with_defaults();
        coordinator.set_http_pool(TransportPool::<HttpTarget>::new());
        assert!(coordinator.http_pool().is_some());
    }

    // ========================================================================
    // CAPABILITY-FILTERED QUORUM TESTS
    // ========================================================================

    #[test]
    fn test_quorum_target_count_uses_capabilities() {
        use crate::http_target::HttpTargetConfig;

        let mut coordinator = TransportCoordinator::with_defaults();
        let pool = TransportPool::<HttpTarget>::new();

        // Stable target: has QUORUM_CREDIT by default
        pool.add_target(HttpTarget::new(HttpTargetConfig::stable("http://stable:1")).unwrap());

        // Ephemeral target: no QUORUM_CREDIT by default
        pool.add_target(
            HttpTarget::new(HttpTargetConfig::ephemeral("http://ephemeral:1")).unwrap(),
        );

        // Ephemeral target with QUORUM_CREDIT override
        let mut config = HttpTargetConfig::ephemeral("http://ephemeral-quorum:1");
        config.base.capabilities = TargetCapabilities {
            send: true,
            quorum_credit: true,
            ..TargetCapabilities::ephemeral_defaults()
        };
        pool.add_target(HttpTarget::new(config).unwrap());

        coordinator.set_http_pool(pool);

        let delivery_config = TieredDeliveryConfig::default();
        // Should count 2: stable (has QUORUM_CREDIT) + ephemeral-quorum (override)
        assert_eq!(coordinator.quorum_target_count(&delivery_config), 2);
    }

    #[test]
    fn test_quorum_target_ids_uses_capabilities() {
        use crate::http_target::HttpTargetConfig;

        let mut coordinator = TransportCoordinator::with_defaults();
        let pool = TransportPool::<HttpTarget>::new();

        let stable = HttpTarget::new(HttpTargetConfig::stable("http://stable:1")).unwrap();
        let stable_id = stable.id().clone();
        pool.add_target(stable);

        // Ephemeral: no QUORUM_CREDIT
        pool.add_target(
            HttpTarget::new(HttpTargetConfig::ephemeral("http://ephemeral:1")).unwrap(),
        );

        coordinator.set_http_pool(pool);

        let delivery_config = TieredDeliveryConfig::default();
        let ids = coordinator.quorum_target_ids(&delivery_config);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], stable_id);
    }

    #[tokio::test]
    async fn test_quorum_tier_empty() {
        use reme_message::{MessageID, OuterEnvelope, RoutingKey, CURRENT_VERSION};

        let coordinator = TransportCoordinator::with_defaults();
        let config = TieredDeliveryConfig::default();

        let envelope = OuterEnvelope {
            version: CURRENT_VERSION,
            routing_key: RoutingKey::from_bytes([1u8; 16]),
            message_id: MessageID::from_bytes([2u8; 16]),
            timestamp_hours: 0,
            ttl_hours: None,
            ephemeral_key: [3u8; 32],
            ack_hash: [0u8; 16],
            inner_ciphertext: vec![1, 2, 3],
        };

        let result = coordinator.try_quorum_tier_all(&envelope, &config).await;

        assert!(!result.any_success());
        assert_eq!(result.success_count(), 0);
        assert!(result.results.is_empty());
    }
}
