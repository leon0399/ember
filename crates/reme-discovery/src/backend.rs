use tokio::sync::broadcast;

use crate::types::{AdvertisementSpec, DiscoveryError, DiscoveryEvent};

/// Async trait implemented by each discovery mechanism (mDNS, BLE, etc.).
///
/// A backend is expected to be long-lived: created once, then driven by
/// `start_advertising` / `subscribe` / `shutdown` calls.
#[async_trait::async_trait]
pub trait DiscoveryBackend: Send + Sync {
    /// Begin advertising this node on the local network.
    ///
    /// Returns [`DiscoveryError::AlreadyAdvertising`] if called twice without
    /// an intervening [`stop_advertising`](Self::stop_advertising).
    async fn start_advertising(&self, spec: AdvertisementSpec) -> Result<(), DiscoveryError>;

    /// Stop advertising. Does **not** stop the browse/subscribe side.
    ///
    /// Returns [`DiscoveryError::NotAdvertising`] if not currently advertising.
    async fn stop_advertising(&self) -> Result<(), DiscoveryError>;

    /// Subscribe to discovery events (peer found / lost / updated).
    ///
    /// Each call returns an independent receiver — multiple subscribers are
    /// supported (e.g. controller + TUI status). Events are cloned to each.
    /// The returned receiver will yield events until the backend is shut down.
    fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent>;

    /// Gracefully shut down the backend, releasing network resources.
    async fn shutdown(&self) -> Result<(), DiscoveryError>;
}
