use std::sync::Mutex;

use tokio::sync::broadcast;

use crate::backend::DiscoveryBackend;
use crate::types::{
    AdvertisementSpec, DiscoveryError, DiscoveryEvent, RawDiscoveredPeer,
    DISCOVERY_CHANNEL_CAPACITY,
};

/// A deterministic discovery backend for testing.
///
/// Peers are injected manually via [`inject_peer`](Self::inject_peer) and
/// [`inject_lost`](Self::inject_lost). Each call to [`subscribe`](Self::subscribe)
/// returns an independent receiver that will see all future injected events.
pub struct FakeDiscoveryBackend {
    advertising: Mutex<bool>,
    tx: broadcast::Sender<DiscoveryEvent>,
}

impl FakeDiscoveryBackend {
    /// Create a new fake backend with no peers.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(DISCOVERY_CHANNEL_CAPACITY);
        Self {
            advertising: Mutex::new(false),
            tx,
        }
    }

    /// Inject a discovered peer, delivering `PeerDiscovered` to all subscribers.
    pub fn inject_peer(&self, peer: RawDiscoveredPeer) {
        // Ignore send errors (no active subscribers is fine).
        let _ = self.tx.send(DiscoveryEvent::PeerDiscovered(peer));
    }

    /// Inject a peer-updated event, delivering `PeerUpdated` to all subscribers.
    pub fn inject_updated(&self, peer: RawDiscoveredPeer) {
        let _ = self.tx.send(DiscoveryEvent::PeerUpdated(peer));
    }

    /// Inject a peer-lost event, delivering `PeerLost` to all subscribers.
    pub fn inject_lost(&self, instance_name: String) {
        let _ = self.tx.send(DiscoveryEvent::PeerLost(instance_name));
    }
}

impl Default for FakeDiscoveryBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl DiscoveryBackend for FakeDiscoveryBackend {
    async fn start_advertising(&self, _spec: AdvertisementSpec) -> Result<(), DiscoveryError> {
        let mut advertising = self.advertising.lock().unwrap();
        if *advertising {
            return Err(DiscoveryError::AlreadyAdvertising);
        }
        *advertising = true;
        Ok(())
    }

    async fn stop_advertising(&self) -> Result<(), DiscoveryError> {
        let mut advertising = self.advertising.lock().unwrap();
        if !*advertising {
            return Err(DiscoveryError::NotAdvertising);
        }
        *advertising = false;
        Ok(())
    }

    fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.tx.subscribe()
    }

    async fn shutdown(&self) -> Result<(), DiscoveryError> {
        *self.advertising.lock().unwrap() = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::time::Instant;

    use super::*;

    fn make_peer(name: &str) -> RawDiscoveredPeer {
        RawDiscoveredPeer {
            instance_name: name.to_owned(),
            addresses: vec!["192.168.1.10".parse::<IpAddr>().unwrap()],
            port: 8443,
            txt_records: HashMap::new(),
            discovered_at: Instant::now(),
        }
    }

    #[test]
    fn inject_peer_and_receive() {
        let backend = FakeDiscoveryBackend::new();
        let mut rx = backend.subscribe();

        backend.inject_peer(make_peer("alice"));

        let event = rx.try_recv().unwrap();
        match event {
            DiscoveryEvent::PeerDiscovered(peer) => {
                assert_eq!(peer.instance_name, "alice");
            }
            other => panic!("expected PeerDiscovered, got {other:?}"),
        }
    }

    #[test]
    fn inject_updated_and_receive() {
        let backend = FakeDiscoveryBackend::new();
        let mut rx = backend.subscribe();

        backend.inject_updated(make_peer("alice"));

        let event = rx.try_recv().unwrap();
        match event {
            DiscoveryEvent::PeerUpdated(peer) => assert_eq!(peer.instance_name, "alice"),
            other => panic!("expected PeerUpdated, got {other:?}"),
        }
    }

    #[test]
    fn inject_lost_and_receive() {
        let backend = FakeDiscoveryBackend::new();
        let mut rx = backend.subscribe();

        backend.inject_lost("bob".to_owned());

        let event = rx.try_recv().unwrap();
        match event {
            DiscoveryEvent::PeerLost(name) => assert_eq!(name, "bob"),
            other => panic!("expected PeerLost, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn advertising_state_machine() {
        let backend = FakeDiscoveryBackend::new();
        let spec = AdvertisementSpec::new(8443);

        // Cannot stop before starting.
        assert_eq!(
            backend.stop_advertising().await,
            Err(DiscoveryError::NotAdvertising),
        );

        // Start succeeds.
        backend.start_advertising(spec.clone()).await.unwrap();

        // Double-start fails.
        assert_eq!(
            backend.start_advertising(spec).await,
            Err(DiscoveryError::AlreadyAdvertising),
        );

        // Stop succeeds.
        backend.stop_advertising().await.unwrap();

        // Double-stop fails.
        assert_eq!(
            backend.stop_advertising().await,
            Err(DiscoveryError::NotAdvertising),
        );
    }

    #[test]
    fn multiple_subscribers_receive_events() {
        let backend = FakeDiscoveryBackend::new();
        let mut rx1 = backend.subscribe();
        let mut rx2 = backend.subscribe();

        backend.inject_peer(make_peer("charlie"));

        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
    }

    #[tokio::test]
    async fn shutdown_stops_advertising() {
        let backend = FakeDiscoveryBackend::new();
        let spec = AdvertisementSpec::new(8443);

        backend.start_advertising(spec).await.unwrap();
        backend.shutdown().await.unwrap();

        // After shutdown, advertising is stopped.
        assert_eq!(
            backend.stop_advertising().await,
            Err(DiscoveryError::NotAdvertising),
        );
    }
}
