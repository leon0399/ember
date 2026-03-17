use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Instant;

use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::backend::DiscoveryBackend;
use crate::types::{
    AdvertisementSpec, DiscoveryError, DiscoveryEvent, RawDiscoveredPeer, DEFAULT_SERVICE_TYPE,
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

        let (tx, _) = broadcast::channel(128);

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

    /// Start the browse thread if not already running. Called on first subscribe.
    fn ensure_browsing(&self) {
        // M2: Claim the browsing slot under lock, then drop the lock before
        // calling daemon.browse() (which may block briefly on the internal
        // mpsc channel). If browse() fails, re-acquire and reset.
        {
            let mut state = self.state.lock().unwrap();
            if state.browsing {
                return;
            }
            state.browsing = true;
        }

        let browse_receiver = match self.daemon.browse(DEFAULT_SERVICE_TYPE) {
            Ok(r) => r,
            Err(e) => {
                warn!("mDNS-SD: failed to start browsing: {e}");
                let mut state = self.state.lock().unwrap();
                state.browsing = false;
                return;
            }
        };

        let tx = self.tx.clone();

        // Bridge the std mpsc receiver from mdns-sd into our broadcast sender.
        let handle = std::thread::spawn(move || {
            let mut known = HashSet::<String>::new();
            while let Ok(event) = browse_receiver.recv() {
                let discovery_event = match event {
                    mdns_sd::ServiceEvent::ServiceFound(_stype, fullname) => {
                        debug!(fullname, "mDNS-SD: service found (awaiting resolution)");
                        continue;
                    }
                    mdns_sd::ServiceEvent::ServiceResolved(info) => {
                        let peer = Self::resolved_to_peer(&info);
                        if known.insert(info.fullname.clone()) {
                            debug!(fullname = %info.fullname, "mDNS-SD: service resolved");
                            DiscoveryEvent::PeerDiscovered(peer)
                        } else {
                            debug!(fullname = %info.fullname, "mDNS-SD: service re-resolved");
                            DiscoveryEvent::PeerUpdated(peer)
                        }
                    }
                    mdns_sd::ServiceEvent::ServiceRemoved(_stype, fullname) => {
                        known.remove(&fullname);
                        debug!(fullname, "mDNS-SD: service removed");
                        DiscoveryEvent::PeerLost(fullname)
                    }
                    _ => continue,
                };

                // Ignore errors — no active subscribers is fine.
                let _ = tx.send(discovery_event);
            }
        });

        // Store the handle so we can join it on shutdown.
        let mut state = self.state.lock().unwrap();
        state.browse_handle = Some(handle);
    }
}

#[async_trait::async_trait]
impl DiscoveryBackend for MdnsSdBackend {
    async fn start_advertising(&self, spec: AdvertisementSpec) -> Result<(), DiscoveryError> {
        // M1: Hold the lock through the entire operation to avoid TOCTOU.
        // The work below (hostname lookup, ServiceInfo::new, daemon.register)
        // is fast in-process work, not blocking I/O.
        let mut state = self.state.lock().unwrap();
        if state.advertising {
            return Err(DiscoveryError::AlreadyAdvertising);
        }

        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "reme-node".to_owned());

        let instance_name = format!("{hostname}-{}", std::process::id());

        let properties: Vec<(&str, &str)> = spec
            .txt_records
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let host_fqdn = format!("{hostname}.local.");
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
        // m5: Hold the lock through the entire method since daemon.unregister()
        // is an in-process mpsc send — no need for the clone+split-lock pattern.
        let mut state = self.state.lock().unwrap();
        if !state.advertising {
            return Err(DiscoveryError::NotAdvertising);
        }

        // C1: Await the unregister receiver to confirm completion.
        if let Some(ref fullname) = state.registered_fullname {
            let receiver = self
                .daemon
                .unregister(fullname)
                .map_err(|e| DiscoveryError::BackendError(e.to_string()))?;

            // The receiver is a std sync mpsc — recv on it in a blocking spawn
            // to avoid blocking the async runtime.
            let recv_result = tokio::task::spawn_blocking(move || receiver.recv())
                .await
                .map_err(|e| DiscoveryError::BackendError(e.to_string()))?;

            match recv_result {
                Ok(mdns_sd::UnregisterStatus::OK) => {
                    debug!(
                        fullname = %state.registered_fullname.as_deref().unwrap_or("?"),
                        "mDNS-SD: advertising stopped"
                    );
                }
                Ok(mdns_sd::UnregisterStatus::NotFound) => {
                    warn!("mDNS-SD: service was not found during unregister");
                }
                Err(e) => {
                    warn!("mDNS-SD: failed to receive unregister status: {e}");
                }
            }
        }

        state.advertising = false;
        state.registered_fullname = None;

        Ok(())
    }

    fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.ensure_browsing();
        self.tx.subscribe()
    }

    async fn shutdown(&self) -> Result<(), DiscoveryError> {
        // Take state values under lock.
        let (fullname, browse_handle) = {
            let mut state = self.state.lock().unwrap();
            state.advertising = false;
            state.browsing = false;
            (state.registered_fullname.take(), state.browse_handle.take())
        };

        // C1: Await unregister confirmation if we were advertising.
        if let Some(ref fullname) = fullname {
            match self.daemon.unregister(fullname) {
                Ok(receiver) => {
                    let fname = fullname.clone();
                    if let Err(e) = tokio::task::spawn_blocking(move || receiver.recv()).await {
                        warn!(fullname = %fname, "mDNS-SD: failed to await unregister during shutdown: {e}");
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

        if let Err(e) = tokio::task::spawn_blocking(move || shutdown_receiver.recv()).await {
            warn!("mDNS-SD: failed to await daemon shutdown status: {e}");
        }

        // C2: Join the browse thread after daemon shutdown (daemon shutdown
        // closes the browse receiver, which causes the thread to exit).
        if let Some(handle) = browse_handle {
            if let Err(e) = tokio::task::spawn_blocking(move || handle.join()).await {
                warn!("mDNS-SD: failed to join browse thread: {e}");
            }
        }

        Ok(())
    }
}
