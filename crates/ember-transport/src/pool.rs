//! Transport pool for managing multiple targets of the same type.
//!
//! A `TransportPool<T>` aggregates multiple transport targets and provides
//! different strategies for routing messages across them.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use derivative::Derivative;
use ember_message::{OuterEnvelope, SignedAckTombstone};
use futures::future::join_all;
use tracing::{debug, warn};

use crate::query::{HealthSummary, TargetSnapshot, TransportQuery};
use crate::seen_cache::SharedSeenCache;
use crate::target::{HealthState, TargetCapabilities, TargetId, TargetKind, TransportTarget};
use crate::{Transport, TransportError};

/// Strategy for selecting and routing to targets in a pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PoolStrategy {
    /// Broadcast to all targets, succeed if any succeeds.
    ///
    /// This is the default strategy for redundancy.
    #[default]
    Broadcast,

    /// Try targets in priority order, stop on first success.
    ///
    /// Useful when you want to prefer certain targets but fallback to others.
    PriorityFallback,

    /// Race all targets in parallel, return on first success.
    ///
    /// Similar to Broadcast but cancels remaining requests on first success.
    /// Provides lowest latency but may waste resources.
    Race,

    /// Round-robin across healthy targets.
    ///
    /// Distributes load evenly across targets.
    RoundRobin,

    /// Prefer the target with lowest average latency.
    ///
    /// Optimizes for speed by routing to the fastest target.
    FastestFirst,
}

/// Configuration for a transport pool.
#[derive(Debug, Clone, Derivative)]
#[derivative(Default)]
pub struct PoolConfig {
    /// Strategy for routing to targets.
    pub strategy: PoolStrategy,

    /// Whether to use the shared seen cache for deduplication.
    #[derivative(Default(value = "true"))]
    pub use_seen_cache: bool,
}

impl PoolConfig {
    /// Create a new pool config with the given strategy.
    pub fn with_strategy(strategy: PoolStrategy) -> Self {
        Self {
            strategy,
            ..Default::default()
        }
    }
}

/// A pool of transport targets of the same type.
///
/// The pool manages multiple targets and routes messages according to the
/// configured strategy. It also provides:
/// - Health-based filtering (skips unhealthy targets)
/// - Deduplication via shared seen cache
/// - Target management (add/remove at runtime)
pub struct TransportPool<T: TransportTarget> {
    targets: RwLock<Vec<Arc<T>>>,
    config: PoolConfig,
    seen_cache: Arc<SharedSeenCache>,
    round_robin_index: AtomicUsize,
}

impl<T: TransportTarget + 'static> TransportPool<T> {
    /// Create a new transport pool with default configuration.
    pub fn new() -> Self {
        Self::with_config(
            PoolConfig::default(),
            Arc::new(SharedSeenCache::with_defaults()),
        )
    }

    /// Create a new transport pool with shared seen cache.
    pub fn with_seen_cache(seen_cache: Arc<SharedSeenCache>) -> Self {
        Self::with_config(PoolConfig::default(), seen_cache)
    }

    /// Create a new transport pool with configuration and seen cache.
    pub const fn with_config(config: PoolConfig, seen_cache: Arc<SharedSeenCache>) -> Self {
        Self {
            targets: RwLock::new(Vec::new()),
            config,
            seen_cache,
            round_robin_index: AtomicUsize::new(0),
        }
    }

    /// Get a reference to the shared seen cache.
    pub const fn seen_cache(&self) -> &Arc<SharedSeenCache> {
        &self.seen_cache
    }

    /// Add a target to the pool.
    pub fn add_target(&self, target: T) {
        let Ok(mut targets) = self.targets.write() else {
            return;
        };
        targets.push(Arc::new(target));
    }

    /// Add an already-Arc'd target to the pool.
    pub fn add_arc_target(&self, target: Arc<T>) {
        let Ok(mut targets) = self.targets.write() else {
            return;
        };
        targets.push(target);
    }

    /// Remove a target by ID.
    ///
    /// Returns true if a target was removed.
    pub fn remove_target(&self, id: &TargetId) -> bool {
        let Ok(mut targets) = self.targets.write() else {
            return false;
        };
        let before_len = targets.len();
        targets.retain(|t| t.id() != id);
        targets.len() < before_len
    }

    /// Atomically replace a target by ID, with upsert semantics.
    ///
    /// If a target with `old_id` exists it is removed and `new_target` is
    /// inserted in its place. If no target with `old_id` is found,
    /// `new_target` is still inserted (upsert). Both operations happen
    /// under a single write lock so concurrent readers never see a state
    /// with neither target present.
    ///
    /// Returns `true` if the old target was found and removed.
    pub fn replace_target(&self, old_id: &TargetId, new_target: T) -> bool {
        let new_id = new_target.id();
        let Ok(mut targets) = self.targets.write() else {
            return false;
        };
        let before_len = targets.len();
        // Remove both the old target and any existing target with the new ID
        // to prevent duplicate entries when old_id != new_id.
        targets.retain(|t| t.id() != old_id && t.id() != new_id);
        let removed = targets.len() < before_len;
        targets.push(Arc::new(new_target));
        removed
    }

    /// Get all targets.
    pub fn all_targets(&self) -> Vec<Arc<T>> {
        let Ok(targets) = self.targets.read() else {
            return Vec::new();
        };
        targets.clone()
    }

    /// Get all healthy (available) targets.
    pub fn healthy_targets(&self) -> Vec<Arc<T>> {
        let Ok(targets) = self.targets.read() else {
            return Vec::new();
        };
        targets
            .iter()
            .filter(|t| t.is_available())
            .cloned()
            .collect()
    }

    /// Get targets by kind.
    pub fn targets_by_kind(&self, kind: TargetKind) -> Vec<Arc<T>> {
        let Ok(targets) = self.targets.read() else {
            return Vec::new();
        };
        targets
            .iter()
            .filter(|t| t.config().kind == kind)
            .cloned()
            .collect()
    }

    /// Get targets matching a capability predicate.
    pub fn targets_by_capability(&self, pred: impl Fn(&TargetCapabilities) -> bool) -> Vec<Arc<T>> {
        let Ok(targets) = self.targets.read() else {
            return Vec::new();
        };
        targets
            .iter()
            .filter(|t| pred(&t.config().capabilities))
            .cloned()
            .collect()
    }

    /// Get a target by ID.
    pub fn get_target(&self, id: &TargetId) -> Option<Arc<T>> {
        let Ok(targets) = self.targets.read() else {
            return None;
        };
        targets.iter().find(|t| t.id() == id).cloned()
    }

    /// Get the number of targets in the pool.
    pub fn len(&self) -> usize {
        let Ok(targets) = self.targets.read() else {
            return 0;
        };
        targets.len()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        let Ok(targets) = self.targets.read() else {
            return true;
        };
        targets.is_empty()
    }

    /// Check if any target is available.
    pub fn has_available(&self) -> bool {
        let Ok(targets) = self.targets.read() else {
            return false;
        };
        targets.iter().any(|t| t.is_available())
    }

    /// Select targets based on current strategy.
    fn select_targets(&self) -> Vec<Arc<T>> {
        let Ok(all_targets) = self.targets.read() else {
            return Vec::new();
        };
        let available: Vec<_> = all_targets
            .iter()
            .filter(|t| t.is_available())
            .cloned()
            .collect();

        if available.is_empty() {
            // If no healthy targets, try all (circuit breaker may have recovered)
            return all_targets.clone();
        }

        match self.config.strategy {
            PoolStrategy::Broadcast | PoolStrategy::Race => available,
            PoolStrategy::PriorityFallback => {
                let mut sorted = available;
                sorted.sort_by_key(|t| std::cmp::Reverse(t.config().priority));
                sorted
            }
            PoolStrategy::RoundRobin => {
                let index =
                    self.round_robin_index.fetch_add(1, Ordering::Relaxed) % available.len();
                vec![available[index].clone()]
            }
            PoolStrategy::FastestFirst => {
                let mut sorted = available;
                sorted.sort_by_key(|t| {
                    // Use health's avg_latency_ms if available
                    // This requires downcasting or a method on the trait
                    // For now, use priority as proxy (higher priority = preferred)
                    std::cmp::Reverse(t.config().priority)
                });
                // available is non-empty (checked above), so sorted is non-empty
                match sorted.first() {
                    Some(target) => vec![target.clone()],
                    None => Vec::new(),
                }
            }
        }
    }

    /// Submit a message using the pool strategy.
    pub async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        // Deduplication check
        if self.config.use_seen_cache && self.seen_cache.was_seen(&envelope.message_id) {
            debug!("Message {:?} already seen, skipping", envelope.message_id);
            return Ok(());
        }

        let targets = self.select_targets();
        if targets.is_empty() {
            return Err(TransportError::Network("No targets available".to_string()));
        }

        let result = match self.config.strategy {
            PoolStrategy::Broadcast => self.broadcast_message(&targets, envelope.clone()).await,
            PoolStrategy::Race => self.race_message(&targets, envelope.clone()).await,
            PoolStrategy::PriorityFallback => {
                self.priority_fallback_message(&targets, envelope.clone())
                    .await
            }
            PoolStrategy::RoundRobin | PoolStrategy::FastestFirst => {
                // Single target selected - discard receipt
                targets[0]
                    .submit_message(envelope.clone())
                    .await
                    .map(|_| ())
            }
        };

        if result.is_ok() && self.config.use_seen_cache {
            self.seen_cache.mark(&envelope.message_id);
        }

        result
    }

    /// Submit an ack tombstone using the pool strategy.
    pub async fn submit_ack_tombstone(
        &self,
        tombstone: SignedAckTombstone,
    ) -> Result<(), TransportError> {
        let targets = self.select_targets();
        if targets.is_empty() {
            return Err(TransportError::Network("No targets available".to_string()));
        }

        // Ack tombstones use broadcast strategy for redundancy
        self.broadcast_ack_tombstone(&targets, tombstone).await
    }

    /// Broadcast message to all targets, succeed if any succeeds.
    async fn broadcast_message(
        &self,
        targets: &[Arc<T>],
        envelope: OuterEnvelope,
    ) -> Result<(), TransportError> {
        let futures: Vec<_> = targets
            .iter()
            .map(|t| {
                let t = t.clone();
                let env = envelope.clone();
                async move { t.submit_message(env).await }
            })
            .collect();

        let results = join_all(futures).await;
        Self::tally_broadcast_results(&results, targets, "Message")
    }

    /// Tally broadcast results: return Ok if any succeeded, Err with last error otherwise.
    fn tally_broadcast_results<R>(
        results: &[Result<R, TransportError>],
        targets: &[Arc<T>],
        label: &str,
    ) -> Result<(), TransportError> {
        Self::log_target_failures(results, targets);

        let success_count = results.iter().filter(|r| r.is_ok()).count();
        if success_count > 0 {
            debug!(
                "{} sent to {}/{} targets",
                label,
                success_count,
                targets.len()
            );
            return Ok(());
        }

        let last_error = results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .last()
            .cloned();
        Err(last_error.unwrap_or_else(|| TransportError::Network("All targets failed".to_string())))
    }

    /// Log warnings for failed targets in a broadcast batch.
    fn log_target_failures<R>(results: &[Result<R, TransportError>], targets: &[Arc<T>]) {
        for (i, result) in results.iter().enumerate() {
            if let Err(e) = result {
                warn!("Target {} failed: {}", targets[i].id(), e);
            }
        }
    }

    /// Race message to all targets, return on first success.
    ///
    /// Runs all requests in parallel and returns as soon as one succeeds.
    /// If one fails, continues polling remaining futures rather than
    /// falling back to broadcast (which would restart all requests).
    async fn race_message(
        &self,
        targets: &[Arc<T>],
        envelope: OuterEnvelope,
    ) -> Result<(), TransportError> {
        if targets.len() == 1 {
            return targets[0].submit_message(envelope).await.map(|_| ());
        }

        // Create futures for all targets
        let futures: Vec<_> = targets
            .iter()
            .map(|t| {
                let t = t.clone();
                let env = envelope.clone();
                Box::pin(async move { t.submit_message(env).await })
            })
            .collect();

        // Poll futures until one succeeds or all fail
        let mut remaining = futures;
        let mut last_error = None;

        while !remaining.is_empty() {
            let (result, _index, rest) = futures::future::select_all(remaining).await;

            match result {
                Ok(_receipt) => {
                    // Success - cancel remaining futures and return
                    drop(rest);
                    return Ok(());
                }
                Err(e) => {
                    // This target failed - continue polling the rest
                    last_error = Some(e);
                    remaining = rest;
                }
            }
        }

        // All targets failed
        Err(last_error.unwrap_or_else(|| TransportError::Network("All targets failed".to_string())))
    }

    /// Try targets in priority order, stop on first success.
    async fn priority_fallback_message(
        &self,
        targets: &[Arc<T>],
        envelope: OuterEnvelope,
    ) -> Result<(), TransportError> {
        let mut last_error = None;

        for target in targets {
            match target.submit_message(envelope.clone()).await {
                Ok(_) => {
                    Self::log_fallback_success(target);
                    return Ok(());
                }
                Err(e) => last_error = Some(Self::log_fallback_failure(target, e)),
            }
        }

        Err(last_error.unwrap_or_else(|| TransportError::Network("All targets failed".to_string())))
    }

    fn log_fallback_success(target: &T) {
        debug!("Message sent via {}", target.id());
    }

    fn log_fallback_failure(target: &T, err: TransportError) -> TransportError {
        warn!("Target {} failed, trying next: {}", target.id(), err);
        err
    }

    /// Broadcast ack tombstone to all targets, succeed if any succeeds.
    async fn broadcast_ack_tombstone(
        &self,
        targets: &[Arc<T>],
        tombstone: SignedAckTombstone,
    ) -> Result<(), TransportError> {
        let futures: Vec<_> = targets
            .iter()
            .map(|t| {
                let t = t.clone();
                let ts = tombstone.clone();
                async move { t.submit_ack_tombstone(ts).await }
            })
            .collect();

        let results = join_all(futures).await;
        Self::tally_broadcast_results(&results, targets, "Tombstone")
    }
}

impl<T: TransportTarget + 'static> Default for TransportPool<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Implement Transport trait for `TransportPool` to allow use with existing code.
#[async_trait]
impl<T: TransportTarget + 'static> Transport for TransportPool<T> {
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError> {
        Self::submit_message(self, envelope).await
    }

    async fn submit_ack_tombstone(
        &self,
        tombstone: SignedAckTombstone,
    ) -> Result<(), TransportError> {
        Self::submit_ack_tombstone(self, tombstone).await
    }
}

/// Summary of pool health status.
#[derive(Debug, Clone)]
pub struct PoolHealthSummary {
    /// Total number of targets.
    pub total: usize,
    /// Number of healthy targets.
    pub healthy: usize,
    /// Number of degraded targets.
    pub degraded: usize,
    /// Number of unhealthy targets.
    pub unhealthy: usize,
    /// Number of targets with unknown health.
    pub unknown: usize,
}

impl<T: TransportTarget> TransportPool<T> {
    /// Get a summary of pool health.
    pub fn health_summary(&self) -> PoolHealthSummary {
        let Ok(targets) = self.targets.read() else {
            return PoolHealthSummary {
                total: 0,
                healthy: 0,
                degraded: 0,
                unhealthy: 0,
                unknown: 0,
            };
        };
        let mut summary = PoolHealthSummary {
            total: targets.len(),
            healthy: 0,
            degraded: 0,
            unhealthy: 0,
            unknown: 0,
        };

        for target in targets.iter() {
            match target.health() {
                HealthState::Healthy => summary.healthy += 1,
                HealthState::Degraded => summary.degraded += 1,
                HealthState::Unhealthy => summary.unhealthy += 1,
                HealthState::Unknown => summary.unknown += 1,
            }
        }

        summary
    }
}

/// Implement `TransportQuery` for UI and monitoring access.
impl<T: TransportTarget + 'static> TransportQuery for TransportPool<T> {
    fn list_targets(&self) -> Vec<TargetSnapshot> {
        let Ok(targets) = self.targets.read() else {
            return Vec::new();
        };
        targets
            .iter()
            .map(|t| TargetSnapshot::from_target(t.as_ref()))
            .collect()
    }

    fn health_summary(&self) -> HealthSummary {
        let pool_summary = Self::health_summary(self);
        HealthSummary {
            total: pool_summary.total,
            healthy: pool_summary.healthy,
            degraded: pool_summary.degraded,
            unhealthy: pool_summary.unhealthy,
            unknown: pool_summary.unknown,
        }
    }

    fn has_available(&self) -> bool {
        Self::has_available(self)
    }
}

// HTTP-specific pool methods for fetching messages
use crate::http::NodeSpec;
use crate::http_target::{HttpTarget, HttpTargetConfig};
use crate::url_auth::sanitize_url_for_logging;
use ember_message::RoutingKey;
use tracing::info;

impl TransportPool<HttpTarget> {
    /// Create a pool with a single HTTP target.
    ///
    /// This is a convenience constructor for simple setups and testing.
    pub fn single(url: impl Into<String>) -> Result<Self, TransportError> {
        let config = HttpTargetConfig::stable(url);
        let target = HttpTarget::new(config)?;
        let pool = Self::new();
        pool.add_target(target);
        Ok(pool)
    }

    /// Create a pool from a list of node specifications.
    ///
    /// This is a convenience constructor for migrating from the old `HttpTransport` API.
    /// Each node spec is converted to a stable HTTP target.
    ///
    /// # Example
    /// ```ignore
    /// let nodes = vec![
    ///     NodeSpec { url: "https://node1.example.com".into(), cert_pin: Some(pin) },
    ///     NodeSpec { url: "https://node2.example.com".into(), cert_pin: None },
    /// ];
    /// let pool = TransportPool::from_node_specs(nodes)?;
    /// ```
    pub fn from_node_specs(nodes: Vec<NodeSpec>) -> Result<Self, TransportError> {
        if nodes.is_empty() {
            return Err(TransportError::Network(
                "At least one node is required".to_string(),
            ));
        }

        let pool = Self::new();

        for node in nodes {
            let mut config = HttpTargetConfig::stable(&node.url);
            if let Some(pin) = node.cert_pin {
                config = config.with_cert_pin(pin);
            }

            Self::log_node_security(&node.url, &config);

            let target = HttpTarget::new(config)?;
            pool.add_target(target);
        }

        Ok(pool)
    }

    /// Log security warnings for a node configuration.
    fn log_node_security(url: &str, config: &HttpTargetConfig) {
        let safe_url = sanitize_url_for_logging(url);
        Self::log_node_security_warning(url, config, &safe_url);
        Self::log_node_security_info(config, &safe_url);
    }

    fn log_node_security_warning(url: &str, config: &HttpTargetConfig, safe_url: &str) {
        if url.starts_with("http://") {
            Self::warn_plain_http(safe_url);
        } else if url.starts_with("https://") && config.cert_pin.is_none() {
            Self::warn_no_cert_pin(safe_url);
        }
    }

    fn warn_plain_http(safe_url: &str) {
        warn!(
            "Node {} uses unencrypted HTTP - credentials and messages may be exposed",
            safe_url
        );
    }

    fn warn_no_cert_pin(safe_url: &str) {
        warn!(
            "Node {} has no certificate pin - vulnerable to MITM attacks",
            safe_url
        );
    }

    fn log_node_security_info(config: &HttpTargetConfig, safe_url: &str) {
        if config.cert_pin.is_some() {
            info!("Certificate pinning enabled for {}", safe_url);
        }
    }
    /// Fetch messages once from all healthy targets and deduplicate.
    ///
    /// This method performs a single fetch operation from all available targets
    /// and returns unique messages (deduplicated by `message_id`).
    pub async fn fetch_once(
        &self,
        routing_key: &RoutingKey,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        let targets = self.healthy_targets();
        if targets.is_empty() {
            // Try all targets if none are healthy (circuit breaker may have recovered)
            let all_targets = self.all_targets();
            if all_targets.is_empty() {
                return Err(TransportError::Network("No targets available".to_string()));
            }
            return self.fetch_from_targets(&all_targets, routing_key).await;
        }

        self.fetch_from_targets(&targets, routing_key).await
    }

    /// Fetch from a specific set of targets.
    ///
    /// **Layered capability filter:** The caller (`fetch_once`) pre-filters by
    /// health/availability, then this method applies a second filter keeping
    /// only targets with the `FETCH` capability. Targets without this
    /// capability (e.g., ephemeral peers) are skipped to avoid exposing
    /// routing keys to untrusted nodes. Future refactors must preserve this
    /// two-layer invariant: health first, then capability.
    async fn fetch_from_targets(
        &self,
        targets: &[Arc<HttpTarget>],
        routing_key: &RoutingKey,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        // Filter to only targets with FETCH capability
        let fetchable: Vec<_> = targets
            .iter()
            .filter(|t| t.config().capabilities.fetch)
            .cloned()
            .collect();

        if fetchable.is_empty() {
            return Err(TransportError::Network(
                "No fetchable targets available".to_string(),
            ));
        }

        // Fetch from fetchable targets in parallel
        let futures: Vec<_> = fetchable
            .iter()
            .map(|t| {
                let t = t.clone();
                let rk = *routing_key;
                async move { t.fetch_once(&rk).await }
            })
            .collect();

        let results = join_all(futures).await;
        Self::accumulate_fetch_results(results, &fetchable)
    }

    /// Accumulate fetch results from multiple targets, deduplicating by message ID.
    fn accumulate_fetch_results(
        results: Vec<Result<Vec<OuterEnvelope>, TransportError>>,
        fetchable: &[Arc<HttpTarget>],
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        let mut accumulated = crate::dedup::EnvelopeAccumulator::default();
        let mut last_error = None;
        let mut success_count = 0u32;

        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(messages) => {
                    success_count += 1;
                    crate::dedup::merge_envelopes(
                        &mut accumulated,
                        messages,
                        fetchable[i].id().as_str(),
                    );
                }
                Err(e) => {
                    warn!("Target {} fetch failed: {}", fetchable[i].id(), e);
                    last_error = Some(e);
                }
            }
        }

        Self::finalize_fetch(accumulated, last_error, success_count, fetchable.len())
    }

    /// Convert accumulated fetch data into a final result.
    fn finalize_fetch(
        accumulated: crate::dedup::EnvelopeAccumulator,
        last_error: Option<TransportError>,
        success_count: u32,
        total_targets: usize,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        if success_count == 0 {
            return Err(last_error
                .unwrap_or_else(|| TransportError::Network("All targets failed".to_string())));
        }

        let messages = crate::dedup::flatten_variants(accumulated);
        debug!(
            "Fetched {} unique messages from {}/{} targets",
            messages.len(),
            success_count,
            total_targets
        );
        Ok(messages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_target::{HttpTarget, HttpTargetConfig};

    fn create_test_target(url: &str) -> HttpTarget {
        HttpTarget::new(HttpTargetConfig::stable(url)).unwrap()
    }

    #[test]
    fn test_pool_add_remove() {
        let pool: TransportPool<HttpTarget> = TransportPool::new();
        assert!(pool.is_empty());

        let target = create_test_target("http://localhost:1");
        let id = target.id().clone();
        pool.add_target(target);

        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());
        assert!(pool.get_target(&id).is_some());

        assert!(pool.remove_target(&id));
        assert!(pool.is_empty());
        assert!(pool.get_target(&id).is_none());
    }

    #[test]
    fn test_pool_healthy_targets() {
        let pool: TransportPool<HttpTarget> = TransportPool::new();

        pool.add_target(create_test_target("http://localhost:1"));
        pool.add_target(create_test_target("http://localhost:2"));

        let healthy = pool.healthy_targets();
        assert_eq!(healthy.len(), 2);
    }

    #[test]
    fn test_pool_targets_by_kind() {
        let pool: TransportPool<HttpTarget> = TransportPool::new();

        pool.add_target(HttpTarget::new(HttpTargetConfig::stable("http://stable:1")).unwrap());
        pool.add_target(
            HttpTarget::new(HttpTargetConfig::ephemeral("http://ephemeral:1")).unwrap(),
        );
        pool.add_target(HttpTarget::new(HttpTargetConfig::stable("http://stable:2")).unwrap());

        let stable = pool.targets_by_kind(TargetKind::Stable);
        let ephemeral = pool.targets_by_kind(TargetKind::Ephemeral);

        assert_eq!(stable.len(), 2);
        assert_eq!(ephemeral.len(), 1);
    }

    #[test]
    fn test_pool_health_summary() {
        let pool: TransportPool<HttpTarget> = TransportPool::new();

        pool.add_target(create_test_target("http://localhost:1"));
        pool.add_target(create_test_target("http://localhost:2"));

        let summary = pool.health_summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.healthy, 2);
        assert_eq!(summary.degraded, 0);
        assert_eq!(summary.unhealthy, 0);
    }

    #[test]
    fn test_pool_config() {
        let config = PoolConfig::with_strategy(PoolStrategy::PriorityFallback);
        assert_eq!(config.strategy, PoolStrategy::PriorityFallback);
        assert!(config.use_seen_cache);
    }

    #[test]
    fn test_pool_has_available() {
        let pool: TransportPool<HttpTarget> = TransportPool::new();
        assert!(!pool.has_available());

        pool.add_target(create_test_target("http://localhost:1"));
        assert!(pool.has_available());
    }

    // ========================================================================
    // CAPABILITY-FILTERED FETCH TESTS
    // ========================================================================

    #[tokio::test]
    async fn test_fetch_skips_non_fetchable_targets() {
        let pool: TransportPool<HttpTarget> = TransportPool::new();

        // Ephemeral target: SEND only, no FETCH capability
        pool.add_target(
            HttpTarget::new(HttpTargetConfig::ephemeral("http://ephemeral:1")).unwrap(),
        );

        let routing_key = ember_message::RoutingKey::from_bytes([1u8; 16]);
        let result = pool.fetch_once(&routing_key).await;

        // Should fail because the only target lacks FETCH capability
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("No fetchable targets"),
            "Expected 'No fetchable targets' error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_fetch_includes_fetchable_targets() {
        let pool: TransportPool<HttpTarget> = TransportPool::new();

        // Stable target: has FETCH capability by default
        pool.add_target(HttpTarget::new(HttpTargetConfig::stable("http://stable:1")).unwrap());

        // Ephemeral target: no FETCH capability
        pool.add_target(
            HttpTarget::new(HttpTargetConfig::ephemeral("http://ephemeral:1")).unwrap(),
        );

        let routing_key = ember_message::RoutingKey::from_bytes([1u8; 16]);
        // This will fail with a network error (targets aren't real),
        // but the error should NOT be "No fetchable targets" since the stable target is fetchable.
        let result = pool.fetch_once(&routing_key).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("No fetchable targets"),
            "Should have attempted fetch from stable target, got: {err}"
        );
    }
}
