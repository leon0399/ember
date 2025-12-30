//! Rate limiting middleware and extractors.
//!
//! Provides configurable rate limiting for the node API using `tower-governor`:
//! - Per-IP rate limiting (proxy-aware via X-Forwarded-For)
//! - Per-routing-key rate limiting (prevents mailbox flooding)
//!
//! Each limiter can be independently disabled by setting its `rps` config to 0.

use crate::config::RateLimitConfig;
use axum::Router;
use governor::clock::DefaultClock;
use governor::middleware::StateInformationMiddleware;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};
use http::Request;
use std::num::NonZeroU32;
use std::sync::Arc;
use tower_governor::governor::{GovernorConfig, GovernorConfigBuilder};
use tower_governor::key_extractor::{KeyExtractor, SmartIpKeyExtractor};
use tower_governor::{errors::GovernorError, GovernorLayer};

/// Extracts routing key from URL path for fetch endpoint rate limiting.
///
/// Expected path format: `/api/v1/fetch/{routing_key}`
#[derive(Debug, Clone, Copy)]
pub struct RoutingKeyExtractor;

impl KeyExtractor for RoutingKeyExtractor {
    type Key = String;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        let path = req.uri().path();
        path.strip_prefix("/api/v1/fetch/")
            .map(std::string::ToString::to_string)
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// Type alias for keyed rate limiter (used inline in submit handler)
pub type KeyedLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

/// Type alias for IP-based governor config with headers
type IpGovernorConfig = GovernorConfig<SmartIpKeyExtractor, StateInformationMiddleware>;

/// Type alias for routing-key governor config with headers
type RoutingKeyGovernorConfig = GovernorConfig<RoutingKeyExtractor, StateInformationMiddleware>;

/// Container for rate limiter configurations.
///
/// Use the `apply_*` methods to add rate limiting layers to routes.
pub struct RateLimiters {
    submit_ip_config: Option<Arc<IpGovernorConfig>>,
    fetch_ip_config: Option<Arc<IpGovernorConfig>>,
    fetch_key_config: Option<Arc<RoutingKeyGovernorConfig>>,
    /// Per-routing-key limiter for submit endpoint (inline check after body parse)
    pub submit_key: Option<Arc<KeyedLimiter>>,
}

impl RateLimiters {
    /// Create rate limiters from configuration.
    ///
    /// Only creates limiters where `rps > 0`.
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            submit_ip_config: make_ip_config(config.submit_ip_rps, config.submit_ip_burst),
            submit_key: make_keyed_limiter(config.submit_key_rps, config.submit_key_burst),
            fetch_ip_config: make_ip_config(config.fetch_ip_rps, config.fetch_ip_burst),
            fetch_key_config: make_fetch_key_config(config.fetch_key_rps, config.fetch_key_burst),
        }
    }

    /// Apply submit endpoint IP rate limiting to a router.
    pub fn apply_submit_ip<S: Clone + Send + Sync + 'static>(
        &self,
        router: Router<S>,
    ) -> Router<S> {
        if let Some(ref config) = self.submit_ip_config {
            router.layer(GovernorLayer::new(Arc::clone(config)))
        } else {
            router
        }
    }

    /// Apply fetch endpoint IP rate limiting to a router.
    pub fn apply_fetch_ip<S: Clone + Send + Sync + 'static>(&self, router: Router<S>) -> Router<S> {
        if let Some(ref config) = self.fetch_ip_config {
            router.layer(GovernorLayer::new(Arc::clone(config)))
        } else {
            router
        }
    }

    /// Apply fetch endpoint routing-key rate limiting to a router.
    pub fn apply_fetch_key<S: Clone + Send + Sync + 'static>(
        &self,
        router: Router<S>,
    ) -> Router<S> {
        if let Some(ref config) = self.fetch_key_config {
            router.layer(GovernorLayer::new(Arc::clone(config)))
        } else {
            router
        }
    }
}

/// Create an IP-based governor config.
fn make_ip_config(rps: u32, burst: u32) -> Option<Arc<IpGovernorConfig>> {
    if rps == 0 {
        return None;
    }
    // Default burst to rps if burst is 0 (burst=0 is invalid for governor)
    let burst = if burst == 0 { rps } else { burst };
    Some(Arc::new(
        GovernorConfigBuilder::default()
            .per_second(u64::from(rps))
            .burst_size(burst)
            .key_extractor(SmartIpKeyExtractor)
            .use_headers()
            .finish()
            .expect("valid governor config"),
    ))
}

/// Create a routing-key based governor config for fetch endpoint.
fn make_fetch_key_config(rps: u32, burst: u32) -> Option<Arc<RoutingKeyGovernorConfig>> {
    if rps == 0 {
        return None;
    }
    // Default burst to rps if burst is 0 (burst=0 is invalid for governor)
    let burst = if burst == 0 { rps } else { burst };
    Some(Arc::new(
        GovernorConfigBuilder::default()
            .per_second(u64::from(rps))
            .burst_size(burst)
            .key_extractor(RoutingKeyExtractor)
            .use_headers()
            .finish()
            .expect("valid governor config"),
    ))
}

/// Create a keyed rate limiter for inline checking (submit handler).
fn make_keyed_limiter(rps: u32, burst: u32) -> Option<Arc<KeyedLimiter>> {
    let rps = NonZeroU32::new(rps)?;
    // Default burst to rps if burst is 0 (burst=0 is invalid for governor)
    let burst = NonZeroU32::new(burst).unwrap_or(rps);
    let quota = Quota::per_second(rps).allow_burst(burst);
    Some(Arc::new(RateLimiter::keyed(quota)))
}
