//! Core types for per-target transport instances.
//!
//! This module defines the foundational types for the unified transport architecture
//! where each transport target (HTTP endpoint, MQTT broker, etc.) is an independent
//! instance with its own configuration, health tracking, and retry policies.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use derive_more::Display as DeriveDisplay;
use reme_identity::PublicID;
use reme_message::{OuterEnvelope, RoutingKey, SignedAckTombstone};
use strum::{Display, EnumIter};

use crate::url_auth::sanitize_url_for_logging;
use crate::TransportError;

// =============================================================================
// Raw Receipt (unverified receipt data from transport)
// =============================================================================

/// Raw receipt data from a node (not yet verified).
///
/// This struct holds the raw bytes returned by a node after message submission.
/// Verification happens at the coordinator level using the configured `node_pubkey`.
///
/// For transports that don't support receipts (e.g., MQTT), this will be empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawReceipt {
    /// Raw `ack_secret` bytes (16 bytes if present).
    /// Present only if the node is the intended recipient.
    pub ack_secret: Option<[u8; 16]>,

    /// Raw `XEdDSA` signature bytes (64 bytes if present).
    /// Present when the node has an identity configured.
    pub signature: Option<[u8; 64]>,
}

impl RawReceipt {
    /// Check if any receipt data was returned.
    pub fn has_data(&self) -> bool {
        self.ack_secret.is_some() || self.signature.is_some()
    }

    /// Create a receipt with only a signature (no `ack_secret`).
    pub fn signature_only(signature: [u8; 64]) -> Self {
        Self {
            ack_secret: None,
            signature: Some(signature),
        }
    }

    /// Create a full receipt with both `ack_secret` and signature.
    pub fn full(ack_secret: [u8; 16], signature: [u8; 64]) -> Self {
        Self {
            ack_secret: Some(ack_secret),
            signature: Some(signature),
        }
    }
}

/// Unique identifier for a transport target.
///
/// Format: `{type}:{sanitized_url}` e.g., `http:https://node.example.com:23003`
///
/// URLs are sanitized to remove any embedded credentials, preventing
/// credential exposure in logs or debug output.
#[derive(Debug, Clone, PartialEq, Eq, Hash, DeriveDisplay)]
pub struct TargetId(String);

impl TargetId {
    /// Create a target ID for an HTTP endpoint.
    ///
    /// The URL is sanitized to remove any embedded credentials.
    pub fn http(url: &str) -> Self {
        Self(format!("http:{}", sanitize_url_for_logging(url)))
    }

    /// Create a target ID for an MQTT broker.
    ///
    /// The URL is sanitized to remove any embedded credentials.
    pub fn mqtt(broker_url: &str) -> Self {
        Self(format!("mqtt:{}", sanitize_url_for_logging(broker_url)))
    }

    /// Create a target ID for an embedded node (in-process).
    pub fn embedded() -> Self {
        Self("embedded:local".to_string())
    }

    /// Get the raw ID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Binary classification of transport targets.
///
/// This simple classification drives default retry behavior and routing priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Display, EnumIter)]
pub enum TargetKind {
    /// Stable targets: mailbox nodes, manually configured peers, MQTT brokers.
    ///
    /// Characteristics:
    /// - Expected to be reliably available
    /// - Aggressive retry with long backoff (5s → 300s)
    /// - Failure is a problem to address
    /// - No `max_attempts` limit
    #[default]
    Stable,

    /// Ephemeral targets: discovered peers (DHT, mDNS, Iroh).
    ///
    /// Characteristics:
    /// - Temporary availability expected
    /// - Quick retry, quick give-up (1s → 10s, max 5 attempts)
    /// - Failure is normal (peer went offline)
    /// - Higher priority when available (prefer direct delivery)
    Ephemeral,
}

impl TargetKind {
    /// Get the default priority for this target kind.
    ///
    /// Higher values = higher priority (preferred for routing).
    pub fn default_priority(&self) -> u8 {
        match self {
            TargetKind::Stable => 100,
            TargetKind::Ephemeral => 200, // Prefer direct when available
        }
    }

    /// Get the default request timeout for this target kind.
    pub fn default_request_timeout(&self) -> Duration {
        match self {
            TargetKind::Stable => Duration::from_secs(30),
            TargetKind::Ephemeral => Duration::from_secs(5),
        }
    }

    /// Get the default connect timeout for this target kind.
    pub fn default_connect_timeout(&self) -> Duration {
        match self {
            TargetKind::Stable => Duration::from_secs(10),
            TargetKind::Ephemeral => Duration::from_secs(2),
        }
    }

    /// Get the default circuit breaker threshold (failures before unhealthy).
    pub fn default_circuit_breaker_threshold(&self) -> u32 {
        match self {
            TargetKind::Stable => 5,
            TargetKind::Ephemeral => 2,
        }
    }

    /// Get the default circuit breaker recovery time.
    pub fn default_circuit_breaker_recovery(&self) -> Duration {
        match self {
            TargetKind::Stable => Duration::from_secs(60),
            TargetKind::Ephemeral => Duration::from_secs(10),
        }
    }
}

/// Health state for circuit breaker pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Display, EnumIter)]
pub enum HealthState {
    /// Target is healthy, normal operation.
    #[default]
    Healthy,

    /// Target is degraded (slow or partially failing).
    Degraded,

    /// Target is unhealthy, circuit is open (skip this target).
    Unhealthy,

    /// Health state is unknown (e.g., composite-only targets without health tracking).
    Unknown,
}

/// Health tracking for a transport target.
#[derive(Debug)]
pub struct TargetHealth {
    /// Current health state.
    state: RwLock<HealthState>,

    /// Consecutive failures counter.
    consecutive_failures: AtomicU32,

    /// Last successful operation timestamp.
    last_success: RwLock<Option<Instant>>,

    /// Last failure timestamp.
    last_failure: RwLock<Option<Instant>>,

    /// Circuit breaker recovery started at (when state went Unhealthy).
    recovery_started: RwLock<Option<Instant>>,

    /// Moving average latency in milliseconds.
    avg_latency_ms: AtomicU32,

    /// Configuration for health decisions.
    circuit_breaker_threshold: u32,
    circuit_breaker_recovery: Duration,
}

impl TargetHealth {
    /// Create new health tracker with given configuration.
    pub fn new(threshold: u32, recovery: Duration) -> Self {
        Self {
            state: RwLock::new(HealthState::Healthy),
            consecutive_failures: AtomicU32::new(0),
            last_success: RwLock::new(None),
            last_failure: RwLock::new(None),
            recovery_started: RwLock::new(None),
            avg_latency_ms: AtomicU32::new(0),
            circuit_breaker_threshold: threshold,
            circuit_breaker_recovery: recovery,
        }
    }

    /// Create health tracker with defaults for a target kind.
    pub fn for_kind(kind: TargetKind) -> Self {
        Self::new(
            kind.default_circuit_breaker_threshold(),
            kind.default_circuit_breaker_recovery(),
        )
    }

    /// Get the current health state.
    pub fn state(&self) -> HealthState {
        // Check if recovery period has elapsed.
        // IMPORTANT: We must drop the recovery_started lock before acquiring
        // the state lock to prevent deadlock with record_failure(), which
        // acquires locks in the opposite order (state first, then recovery_started).
        let should_reset = {
            let recovery_started = self.recovery_started.read().unwrap();
            if let Some(started) = *recovery_started {
                started.elapsed() >= self.circuit_breaker_recovery
            } else {
                false
            }
        }; // recovery_started lock is dropped here

        if should_reset {
            self.reset_to_healthy();
            return HealthState::Healthy;
        }

        *self.state.read().unwrap()
    }

    /// Check if target is available for operations.
    pub fn is_available(&self) -> bool {
        matches!(self.state(), HealthState::Healthy | HealthState::Degraded)
    }

    /// Get consecutive failure count.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Get average latency in milliseconds.
    pub fn avg_latency_ms(&self) -> u32 {
        self.avg_latency_ms.load(Ordering::Relaxed)
    }

    /// Get last success time.
    pub fn last_success(&self) -> Option<Instant> {
        *self.last_success.read().unwrap()
    }

    /// Get last failure time.
    pub fn last_failure(&self) -> Option<Instant> {
        *self.last_failure.read().unwrap()
    }

    /// Record a successful operation.
    #[allow(clippy::cast_possible_truncation)] // Latency in ms won't exceed u32::MAX (~49 days)
    pub fn record_success(&self, latency: Duration) {
        // Reset failure counter
        self.consecutive_failures.store(0, Ordering::Relaxed);

        // Update last success
        *self.last_success.write().unwrap() = Some(Instant::now());

        // Update average latency (exponential moving average)
        let new_latency_ms = latency.as_millis() as u32;
        let old_avg = self.avg_latency_ms.load(Ordering::Relaxed);
        let new_avg = if old_avg == 0 {
            new_latency_ms
        } else {
            // EMA with alpha = 0.2
            (old_avg * 4 + new_latency_ms) / 5
        };
        self.avg_latency_ms.store(new_avg, Ordering::Relaxed);

        // Reset state to healthy
        *self.state.write().unwrap() = HealthState::Healthy;
        *self.recovery_started.write().unwrap() = None;
    }

    /// Record a failed operation.
    pub fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        *self.last_failure.write().unwrap() = Some(Instant::now());

        // Update state based on failure count
        let mut state = self.state.write().unwrap();
        if failures >= self.circuit_breaker_threshold {
            if *state != HealthState::Unhealthy {
                *self.recovery_started.write().unwrap() = Some(Instant::now());
            }
            *state = HealthState::Unhealthy;
        } else if failures > self.circuit_breaker_threshold / 2 {
            // Degraded when more than half of threshold reached
            *state = HealthState::Degraded;
        }
    }

    /// Reset health state to healthy.
    fn reset_to_healthy(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        *self.state.write().unwrap() = HealthState::Healthy;
        *self.recovery_started.write().unwrap() = None;
    }
}

impl Default for TargetHealth {
    fn default() -> Self {
        Self::for_kind(TargetKind::Stable)
    }
}

/// Configuration for a transport target.
#[derive(Debug, Clone)]
pub struct TargetConfig {
    /// Unique identifier for this target.
    pub id: TargetId,

    /// Human-readable label (for logging/UI).
    pub label: Option<String>,

    /// Target classification (affects default behaviors).
    pub kind: TargetKind,

    /// Request timeout (how long to wait for response).
    pub request_timeout: Duration,

    /// Connection timeout (how long to wait for connect).
    pub connect_timeout: Duration,

    /// Circuit breaker threshold (failures before marking unhealthy).
    pub circuit_breaker_threshold: u32,

    /// Circuit breaker recovery time (how long before trying unhealthy target).
    pub circuit_breaker_recovery: Duration,

    /// Priority for routing (higher = preferred).
    pub priority: u8,

    /// Node's public identity (for receipt verification).
    ///
    /// When set, receipts from this target can be verified using this public key.
    /// The `routing_key()` derived from this can also be used to filter targets
    /// during Direct tier delivery (only include targets that can serve the recipient).
    pub node_pubkey: Option<PublicID>,
}

impl TargetConfig {
    /// Create a new target configuration with defaults for the given kind.
    pub fn new(id: TargetId, kind: TargetKind) -> Self {
        Self {
            id,
            label: None,
            kind,
            request_timeout: kind.default_request_timeout(),
            connect_timeout: kind.default_connect_timeout(),
            circuit_breaker_threshold: kind.default_circuit_breaker_threshold(),
            circuit_breaker_recovery: kind.default_circuit_breaker_recovery(),
            priority: kind.default_priority(),
            node_pubkey: None,
        }
    }

    /// Create a stable target configuration.
    pub fn stable(id: TargetId) -> Self {
        Self::new(id, TargetKind::Stable)
    }

    /// Create an ephemeral target configuration.
    pub fn ephemeral(id: TargetId) -> Self {
        Self::new(id, TargetKind::Ephemeral)
    }

    /// Set a human-readable label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set an optional human-readable label.
    pub fn with_label_opt(mut self, label: Option<String>) -> Self {
        self.label = label;
        self
    }

    /// Set the request timeout.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Set the connect timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Set the circuit breaker threshold.
    pub fn with_circuit_breaker_threshold(mut self, threshold: u32) -> Self {
        self.circuit_breaker_threshold = threshold;
        self
    }

    /// Set the circuit breaker recovery time.
    pub fn with_circuit_breaker_recovery(mut self, recovery: Duration) -> Self {
        self.circuit_breaker_recovery = recovery;
        self
    }

    /// Set the node's public identity for receipt verification.
    pub fn with_node_pubkey(mut self, pubkey: PublicID) -> Self {
        self.node_pubkey = Some(pubkey);
        self
    }

    /// Set an optional node public identity.
    pub fn with_node_pubkey_opt(mut self, pubkey: Option<PublicID>) -> Self {
        self.node_pubkey = pubkey;
        self
    }

    /// Check if this target can serve messages for the given routing key.
    ///
    /// Returns `true` if:
    /// - No `node_pubkey` is configured (optimistically include unknown targets)
    /// - The `node_pubkey`'s routing key matches the given routing key
    ///
    /// This is used to filter Direct tier targets to only those that can
    /// actually deliver to the intended recipient.
    pub fn can_serve(&self, routing_key: &RoutingKey) -> bool {
        match &self.node_pubkey {
            Some(pk) => pk.routing_key() == *routing_key,
            None => true, // Unknown = optimistically include
        }
    }
}

/// Detailed health data for UI display and monitoring.
///
/// This struct captures timing and failure information that's useful
/// for debugging and display purposes.
#[derive(Debug, Clone, Default)]
pub struct HealthData {
    /// Current health state.
    pub state: HealthState,
    /// Average latency in milliseconds (0 if unknown).
    pub avg_latency_ms: u32,
    /// Number of consecutive failures.
    pub consecutive_failures: u32,
    /// Time since last successful operation (if any).
    pub since_last_success: Option<Duration>,
    /// Time since last failed operation (if any).
    pub since_last_failure: Option<Duration>,
}

impl TargetHealth {
    /// Get a snapshot of health data for UI display.
    pub fn to_health_data(&self) -> HealthData {
        HealthData {
            state: self.state(),
            avg_latency_ms: self.avg_latency_ms(),
            consecutive_failures: self.consecutive_failures(),
            since_last_success: self.last_success().map(|t| t.elapsed()),
            since_last_failure: self.last_failure().map(|t| t.elapsed()),
        }
    }
}

/// A single transport target (one URL, one broker, one peer).
///
/// Each target is an independent instance with its own:
/// - Configuration (timeouts, priority, etc.)
/// - Health state (circuit breaker)
/// - HTTP client or connection (for type-specific implementations)
#[async_trait]
pub trait TransportTarget: Send + Sync {
    /// Get the target's unique identifier.
    fn id(&self) -> &TargetId;

    /// Get the target's configuration.
    fn config(&self) -> &TargetConfig;

    /// Get the target's current health state.
    fn health(&self) -> HealthState;

    /// Check if target is currently available for operations.
    fn is_available(&self) -> bool;

    /// Get detailed health data for UI display.
    ///
    /// Default implementation returns only the health state.
    /// Implementations with access to `TargetHealth` should override this.
    fn health_data(&self) -> HealthData {
        HealthData {
            state: self.health(),
            ..Default::default()
        }
    }

    /// Submit a message to this specific target.
    ///
    /// Returns the raw receipt data from the target (if any).
    /// For transports that don't support receipts (e.g., MQTT), returns an empty `RawReceipt`.
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<RawReceipt, TransportError>;

    /// Submit an ack tombstone to this specific target (Tombstone V2).
    async fn submit_ack_tombstone(
        &self,
        tombstone: SignedAckTombstone,
    ) -> Result<(), TransportError>;

    /// Record a successful operation (updates health).
    fn record_success(&self, latency: Duration);

    /// Record a failed operation (updates health).
    fn record_failure(&self, error: &TransportError);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_id() {
        // URL is sanitized and normalized (adds trailing slash when no path)
        let id = TargetId::http("https://example.com:23003");
        assert_eq!(id.as_str(), "http:https://example.com:23003/");
        assert_eq!(format!("{id}"), "http:https://example.com:23003/");
    }

    #[test]
    fn test_target_id_with_path() {
        // URL with path is not modified
        let id = TargetId::http("https://example.com:23003/api");
        assert_eq!(id.as_str(), "http:https://example.com:23003/api");
    }

    #[test]
    fn test_target_id_sanitizes_credentials() {
        // HTTP: Credentials should be stripped from the URL
        let id = TargetId::http("https://user:pass@example.com:23003/api");
        assert_eq!(id.as_str(), "http:https://example.com:23003/api");

        // MQTT: The url crate parses mqtt:// schemes and strips credentials
        let id = TargetId::mqtt("mqtts://user:pass@broker.example.com:8883");
        assert_eq!(id.as_str(), "mqtt:mqtts://broker.example.com:8883");
        // Verify credentials are NOT in the output
        assert!(!id.as_str().contains("user"));
        assert!(!id.as_str().contains("pass"));

        // MQTT without credentials: Passes through unchanged
        let id = TargetId::mqtt("mqtts://broker.example.com:8883");
        assert_eq!(id.as_str(), "mqtt:mqtts://broker.example.com:8883");
    }

    #[test]
    fn test_target_id_embedded() {
        let id = TargetId::embedded();
        assert_eq!(id.as_str(), "embedded:local");
    }

    #[test]
    fn test_target_kind_defaults() {
        assert_eq!(TargetKind::Stable.default_priority(), 100);
        assert_eq!(TargetKind::Ephemeral.default_priority(), 200);
        assert_eq!(
            TargetKind::Stable.default_request_timeout(),
            Duration::from_secs(30)
        );
        assert_eq!(
            TargetKind::Ephemeral.default_request_timeout(),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn test_target_health_success() {
        let health = TargetHealth::for_kind(TargetKind::Stable);
        assert_eq!(health.state(), HealthState::Healthy);
        assert!(health.is_available());

        health.record_success(Duration::from_millis(100));
        assert_eq!(health.state(), HealthState::Healthy);
        assert_eq!(health.consecutive_failures(), 0);
        assert!(health.avg_latency_ms() > 0);
    }

    #[test]
    fn test_target_health_failures() {
        let health = TargetHealth::new(3, Duration::from_secs(60));

        health.record_failure();
        assert_eq!(health.state(), HealthState::Healthy);
        assert_eq!(health.consecutive_failures(), 1);

        health.record_failure();
        assert_eq!(health.state(), HealthState::Degraded);

        health.record_failure();
        assert_eq!(health.state(), HealthState::Unhealthy);
        assert!(!health.is_available());
    }

    #[test]
    fn test_target_health_recovery_on_success() {
        let health = TargetHealth::new(2, Duration::from_secs(60));

        health.record_failure();
        health.record_failure();
        assert_eq!(health.state(), HealthState::Unhealthy);

        health.record_success(Duration::from_millis(50));
        assert_eq!(health.state(), HealthState::Healthy);
        assert!(health.is_available());
    }

    #[test]
    fn test_target_config_builder() {
        let config = TargetConfig::stable(TargetId::http("https://example.com"))
            .with_label("Primary node")
            .with_priority(150)
            .with_request_timeout(Duration::from_secs(60));

        assert_eq!(config.label, Some("Primary node".to_string()));
        assert_eq!(config.priority, 150);
        assert_eq!(config.request_timeout, Duration::from_secs(60));
        assert_eq!(config.kind, TargetKind::Stable);
    }

    #[test]
    fn test_target_config_can_serve_without_pubkey() {
        // No node_pubkey = optimistically include (unknown target)
        let config = TargetConfig::stable(TargetId::http("https://example.com"));
        let routing_key = [0u8; 16].into();

        assert!(config.can_serve(&routing_key));
    }

    #[test]
    fn test_target_config_can_serve_with_matching_pubkey() {
        use reme_identity::Identity;

        let identity = Identity::generate();
        let pubkey = *identity.public_id();
        let routing_key = pubkey.routing_key();

        let config =
            TargetConfig::stable(TargetId::http("https://example.com")).with_node_pubkey(pubkey);

        assert!(config.can_serve(&routing_key));
    }

    #[test]
    fn test_target_config_can_serve_with_non_matching_pubkey() {
        use reme_identity::Identity;

        let identity = Identity::generate();
        let pubkey = *identity.public_id();
        let different_routing_key = [0u8; 16].into(); // Different from identity's routing key

        let config =
            TargetConfig::stable(TargetId::http("https://example.com")).with_node_pubkey(pubkey);

        // Should NOT be able to serve a different routing key
        assert!(!config.can_serve(&different_routing_key));
    }
}
