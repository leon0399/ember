use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Instant;

use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::backend::DiscoveryBackend;
use crate::types::{
    AdvertisementSpec, DiscoveryError, DiscoveryEvent, RawDiscoveredPeer, DEFAULT_SERVICE_TYPE,
    DISCOVERY_CHANNEL_CAPACITY,
};

/// mDNS-SD discovery backend using the [`mdns_sd`] crate.
///
/// Advertises and browses for `_reme._tcp.local.` services on the LAN.
pub struct MdnsSdBackend {
    daemon: mdns_sd::ServiceDaemon,
    state: Mutex<MdnsState>,
    tx: broadcast::Sender<DiscoveryEvent>,
}

struct MdnsState {
    advertising: bool,
    /// The full service name returned by `register`, needed for `unregister`.
    registered_fullname: Option<String>,
    /// Whether a browse thread is already running.
    browsing: bool,
    /// Handle to the browse thread, joined on shutdown.
    browse_handle: Option<std::thread::JoinHandle<()>>,
}

impl MdnsSdBackend {
    /// Create a new mDNS-SD backend.
    ///
    /// Returns [`DiscoveryError::BindFailed`] if the daemon cannot bind to the
    /// multicast socket.
    pub fn new() -> Result<Self, DiscoveryError> {
        let daemon =
            mdns_sd::ServiceDaemon::new().map_err(|e| DiscoveryError::BindFailed(e.to_string()))?;

        let (tx, _) = broadcast::channel(DISCOVERY_CHANNEL_CAPACITY);

        Ok(Self {
            daemon,
            state: Mutex::new(MdnsState {
                advertising: false,
                registered_fullname: None,
                browsing: false,
                browse_handle: None,
            }),
            tx,
        })
    }

    /// Convert an [`mdns_sd::ResolvedService`] into a [`RawDiscoveredPeer`].
    fn resolved_to_peer(info: &mdns_sd::ResolvedService) -> RawDiscoveredPeer {
        let addresses = info
            .addresses
            .iter()
            .map(mdns_sd::ScopedIp::to_ip_addr)
            .collect();

        let txt_records: HashMap<String, String> = info
            .txt_properties
            .iter()
            .map(|prop| (prop.key().to_owned(), prop.val_str().to_owned()))
            .collect();

        RawDiscoveredPeer {
            instance_name: info.fullname.clone(),
            addresses,
            port: info.port,
            txt_records,
            discovered_at: Instant::now(),
        }
    }

    /// Map an mDNS-SD service event to a [`DiscoveryEvent`], updating the known
    /// peer set. Returns `None` for events we don't propagate (e.g.
    /// `ServiceFound`, search-started/stopped).
    fn map_service_event(
        event: mdns_sd::ServiceEvent,
        known: &mut HashSet<String>,
    ) -> Option<DiscoveryEvent> {
        match event {
            mdns_sd::ServiceEvent::ServiceFound(_stype, fullname) => {
                debug!(fullname, "mDNS-SD: service found (awaiting resolution)");
                None
            }
            mdns_sd::ServiceEvent::ServiceResolved(info) => {
                Some(Self::handle_service_resolved(&info, known))
            }
            mdns_sd::ServiceEvent::ServiceRemoved(_stype, fullname) => {
                Some(Self::handle_service_removed(fullname, known))
            }
            _ => None,
        }
    }

    fn handle_service_resolved(
        info: &mdns_sd::ResolvedService,
        known: &mut HashSet<String>,
    ) -> DiscoveryEvent {
        let peer = Self::resolved_to_peer(info);
        let is_new = known.insert(info.fullname.clone());
        Self::log_resolved(&info.fullname, is_new);
        if is_new {
            DiscoveryEvent::PeerDiscovered(peer)
        } else {
            DiscoveryEvent::PeerUpdated(peer)
        }
    }

    fn log_resolved(fullname: &str, is_new: bool) {
        let label = if is_new { "resolved" } else { "re-resolved" };
        debug!(fullname, label, "mDNS-SD: service resolved/updated");
    }

    fn handle_service_removed(fullname: String, known: &mut HashSet<String>) -> DiscoveryEvent {
        known.remove(&fullname);
        debug!(fullname = %fullname, "mDNS-SD: service removed");
        DiscoveryEvent::PeerLost(fullname)
    }

    /// Try to claim the browsing slot. Returns `true` if this call claimed it.
    fn try_claim_browsing(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            warn!("mDNS-SD: lock poisoned, cannot start browsing");
            return false;
        };
        if state.browsing {
            return false;
        }
        state.browsing = true;
        true
    }

    /// Reset the browsing flag after a failed browse attempt.
    fn reset_browsing_flag(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.browsing = false;
        }
    }

    /// Store the browse thread handle so we can join it on shutdown.
    fn store_browse_handle(&self, handle: std::thread::JoinHandle<()>) {
        if let Ok(mut state) = self.state.lock() {
            state.browse_handle = Some(handle);
        } else {
            warn!("mDNS-SD: lock poisoned, browse handle will be leaked");
        }
    }

    /// Spawn the browse-to-broadcast bridge thread.
    fn spawn_browse_bridge(
        browse_receiver: mdns_sd::Receiver<mdns_sd::ServiceEvent>,
        tx: broadcast::Sender<DiscoveryEvent>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut known = HashSet::<String>::new();
            while let Ok(event) = browse_receiver.recv() {
                if let Some(discovery_event) = Self::map_service_event(event, &mut known) {
                    // Ignore errors — no active subscribers is fine.
                    let _ = tx.send(discovery_event);
                }
            }
        })
    }

    /// Start the browse thread if not already running. Called on first subscribe.
    fn ensure_browsing(&self) {
        // M2: Claim the browsing slot under lock, then drop the lock before
        // calling daemon.browse() (which may block briefly on the internal
        // mpsc channel). If browse() fails, re-acquire and reset.
        if !self.try_claim_browsing() {
            return;
        }

        let browse_receiver = match self.daemon.browse(DEFAULT_SERVICE_TYPE) {
            Ok(r) => r,
            Err(e) => {
                warn!("mDNS-SD: failed to start browsing: {e}");
                self.reset_browsing_flag();
                return;
            }
        };

        let handle = Self::spawn_browse_bridge(browse_receiver, self.tx.clone());
        self.store_browse_handle(handle);
    }
}

#[async_trait::async_trait]
impl DiscoveryBackend for MdnsSdBackend {
    async fn start_advertising(&self, spec: AdvertisementSpec) -> Result<(), DiscoveryError> {
        // M1: Hold the lock through the entire operation to avoid TOCTOU.
        // The work below (ServiceInfo::new, daemon.register) is fast
        // in-process work, not blocking I/O.
        let mut state = self
            .state
            .lock()
            .map_err(|_| DiscoveryError::LockPoisoned)?;
        if state.advertising {
            return Err(DiscoveryError::AlreadyAdvertising);
        }

        let rk_hex = hex::encode(spec.routing_key);
        let instance_name = format!("reme-{rk_hex}");
        let host_fqdn = format!("reme-{rk_hex}.local.");

        let properties: Vec<(&str, &str)> = spec
            .txt_records
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let service_info = mdns_sd::ServiceInfo::new(
            &spec.service_type,
            &instance_name,
            &host_fqdn,
            "",
            spec.port,
            &properties[..],
        )
        .map_err(|e| DiscoveryError::BackendError(e.to_string()))?
        .enable_addr_auto();

        let fullname = service_info.get_fullname().to_owned();

        self.daemon
            .register(service_info)
            .map_err(|e| DiscoveryError::BackendError(e.to_string()))?;

        debug!(fullname = %fullname, "mDNS-SD: advertising started");
        state.advertising = true;
        state.registered_fullname = Some(fullname);

        Ok(())
    }

    async fn stop_advertising(&self) -> Result<(), DiscoveryError> {
        // Update state and start unregister atomically under a single lock
        // acquisition. This prevents a TOCTOU race where `start_advertising`
        // could succeed between the lock release and a deferred state update,
        // only to have its `advertising = true` clobbered by a late
        // `advertising = false` write.
        let receiver = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| DiscoveryError::LockPoisoned)?;
            if !state.advertising {
                return Err(DiscoveryError::NotAdvertising);
            }

            // Clear state immediately — no second lock acquisition needed.
            state.advertising = false;
            let fullname = state.registered_fullname.take();

            // C1: Start the unregister if we had a registered fullname.
            fullname.map(|f| {
                self.daemon
                    .unregister(&f)
                    .map_err(|e| DiscoveryError::BackendError(e.to_string()))
            })
            // Lock dropped here — state is already consistent.
        };

        // Await unregister confirmation outside the lock.
        if let Some(receiver_result) = receiver {
            let receiver = receiver_result?;

            // The receiver is a std sync mpsc — recv on it in a blocking spawn
            // to avoid blocking the async runtime.
            let recv_result = tokio::task::spawn_blocking(move || receiver.recv())
                .await
                .map_err(|e| DiscoveryError::BackendError(e.to_string()))?;

            match recv_result {
                Ok(mdns_sd::UnregisterStatus::OK) => {
                    debug!("mDNS-SD: advertising stopped");
                }
                Ok(mdns_sd::UnregisterStatus::NotFound) => {
                    warn!("mDNS-SD: service was not found during unregister");
                }
                Err(e) => {
                    warn!("mDNS-SD: failed to receive unregister status: {e}");
                }
            }
        }

        Ok(())
    }

    fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        // Subscribe *before* starting the browse so that events emitted
        // immediately upon browse start (e.g. already-cached services) are
        // not lost. broadcast::Receiver only sees messages sent after creation.
        let rx = self.tx.subscribe();
        self.ensure_browsing();
        rx
    }

    async fn shutdown(&self) -> Result<(), DiscoveryError> {
        // Take state values under lock.
        let (fullname, browse_handle) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| DiscoveryError::LockPoisoned)?;
            state.advertising = false;
            state.browsing = false;
            (state.registered_fullname.take(), state.browse_handle.take())
        };

        // C1: Await unregister confirmation if we were advertising.
        if let Some(ref fullname) = fullname {
            match self.daemon.unregister(fullname) {
                Ok(receiver) => {
                    let fname = fullname.clone();
                    match tokio::task::spawn_blocking(move || receiver.recv()).await {
                        Ok(Ok(_status)) => {
                            debug!(fullname = %fname, "mDNS-SD: unregister confirmed");
                        }
                        Ok(Err(e)) => {
                            warn!(fullname = %fname, "mDNS-SD: unregister channel closed: {e}");
                        }
                        Err(e) => {
                            warn!(fullname = %fname, "mDNS-SD: failed to await unregister: {e}");
                        }
                    }
                }
                Err(e) => {
                    warn!(fullname = %fullname, "mDNS-SD: failed to unregister during shutdown: {e}");
                }
            }
        }

        // C1: Await daemon shutdown confirmation.
        let shutdown_receiver = self
            .daemon
            .shutdown()
            .map_err(|e| DiscoveryError::BackendError(e.to_string()))?;

        match tokio::task::spawn_blocking(move || shutdown_receiver.recv()).await {
            Ok(Ok(_status)) => {
                debug!("mDNS-SD: daemon shutdown confirmed");
            }
            Ok(Err(e)) => {
                warn!("mDNS-SD: daemon shutdown channel closed: {e}");
            }
            Err(e) => {
                warn!("mDNS-SD: failed to await daemon shutdown: {e}");
            }
        }

        // C2: Join the browse thread after daemon shutdown (daemon shutdown
        // closes the browse receiver, which causes the thread to exit).
        if let Some(handle) = browse_handle {
            match tokio::task::spawn_blocking(move || handle.join()).await {
                Ok(Ok(())) => {
                    debug!("mDNS-SD: browse thread joined");
                }
                Ok(Err(_panic)) => {
                    warn!("mDNS-SD: browse thread panicked");
                }
                Err(e) => {
                    warn!("mDNS-SD: failed to join browse thread: {e}");
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::print_stderr)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::backend::DiscoveryBackend;
    use crate::types::AdvertisementSpec;

    /// Try to create a backend; skip the test if the multicast socket is
    /// unavailable (common in CI containers).
    fn try_backend() -> Option<MdnsSdBackend> {
        MdnsSdBackend::new().ok()
    }

    #[tokio::test]
    async fn stop_start_cycle_is_consistent() {
        let Some(backend) = try_backend() else {
            eprintln!("skipping: mDNS daemon unavailable");
            return;
        };
        let spec = AdvertisementSpec::new(19876, [0xCC; 16]);

        // start → stop → start should succeed without state confusion.
        backend.start_advertising(spec.clone()).await.unwrap();
        backend.stop_advertising().await.unwrap();
        backend.start_advertising(spec.clone()).await.unwrap();
        backend.stop_advertising().await.unwrap();

        // Double-stop must fail cleanly.
        assert_eq!(
            backend.stop_advertising().await,
            Err(DiscoveryError::NotAdvertising),
        );

        backend.shutdown().await.unwrap();
    }

    /// Stress test: concurrent stop/start cycles must never leave the state
    /// machine inconsistent. Before the TOCTOU fix, a `start_advertising` that
    /// succeeded between the lock release and re-acquire in `stop_advertising`
    /// could have its `advertising = true` clobbered by a late `false` write.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_stop_start_no_state_corruption() {
        let Some(backend) = try_backend() else {
            eprintln!("skipping: mDNS daemon unavailable");
            return;
        };
        let backend = Arc::new(backend);

        for _ in 0..20 {
            let spec = AdvertisementSpec::new(19877, [0xDD; 16]);

            // Ensure we start from a known state.
            let _ = backend.stop_advertising().await;
            backend.start_advertising(spec.clone()).await.unwrap();

            // Race: stop and start from separate tasks.
            let b1 = Arc::clone(&backend);
            let b2 = Arc::clone(&backend);
            let spec2 = spec.clone();

            let stop_handle = tokio::spawn(async move { b1.stop_advertising().await });

            let start_handle = tokio::spawn(async move { b2.start_advertising(spec2).await });

            let stop_result = stop_handle.await.unwrap();
            let start_result = start_handle.await.unwrap();

            // Exactly one of these outcomes is valid per iteration:
            // 1. stop wins the lock first → stop Ok, start Ok (or start
            //    races and sees AlreadyAdvertising if stop hasn't cleared yet)
            // 2. start sees AlreadyAdvertising because stop hasn't run yet
            //
            // The critical invariant: if start succeeded, a subsequent stop
            // must also succeed — the state must not have been clobbered.
            match (&stop_result, &start_result) {
                (Ok(()), Ok(())) => {
                    // Both succeeded: stop ran first, then start.
                    // State should be advertising=true.
                    backend.stop_advertising().await.unwrap();
                }
                (Ok(()), Err(DiscoveryError::AlreadyAdvertising)) => {
                    // start raced before stop cleared state — it saw
                    // advertising=true and returned AlreadyAdvertising.
                    // After stop completed, advertising=false.
                    // Nothing to clean up.
                }
                (Err(DiscoveryError::NotAdvertising), Ok(())) => {
                    // start somehow ran before stop? Shouldn't happen since
                    // we started advertising above, but handle defensively.
                    backend.stop_advertising().await.unwrap();
                }
                (stop_r, start_r) => {
                    panic!("unexpected result combination: stop={stop_r:?}, start={start_r:?}");
                }
            }
        }

        backend.shutdown().await.unwrap();
    }
}
