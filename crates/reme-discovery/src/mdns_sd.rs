use std::collections::HashMap;
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
        let mut state = self.state.lock().unwrap();
        if state.browsing {
            return;
        }

        let browse_receiver = match self.daemon.browse(DEFAULT_SERVICE_TYPE) {
            Ok(r) => r,
            Err(e) => {
                warn!("mDNS-SD: failed to start browsing: {e}");
                return;
            }
        };

        state.browsing = true;
        let tx = self.tx.clone();

        // Bridge the std mpsc receiver from mdns-sd into our broadcast sender.
        std::thread::spawn(move || {
            while let Ok(event) = browse_receiver.recv() {
                let discovery_event = match event {
                    mdns_sd::ServiceEvent::ServiceFound(_stype, fullname) => {
                        debug!(fullname, "mDNS-SD: service found (awaiting resolution)");
                        continue;
                    }
                    mdns_sd::ServiceEvent::ServiceResolved(info) => {
                        debug!(fullname = %info.fullname, "mDNS-SD: service resolved");
                        DiscoveryEvent::PeerDiscovered(Self::resolved_to_peer(&info))
                    }
                    mdns_sd::ServiceEvent::ServiceRemoved(_stype, fullname) => {
                        debug!(fullname, "mDNS-SD: service removed");
                        DiscoveryEvent::PeerLost(fullname)
                    }
                    _ => continue,
                };

                // Ignore errors — no active subscribers is fine.
                let _ = tx.send(discovery_event);
            }
        });
    }
}

#[async_trait::async_trait]
impl DiscoveryBackend for MdnsSdBackend {
    async fn start_advertising(&self, spec: AdvertisementSpec) -> Result<(), DiscoveryError> {
        // Phase 1: Check state under lock.
        {
            let state = self.state.lock().unwrap();
            if state.advertising {
                return Err(DiscoveryError::AlreadyAdvertising);
            }
        }

        // Phase 2: Build and register service (no lock held).
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

        // Phase 3: Commit state under lock.
        {
            let mut state = self.state.lock().unwrap();
            debug!(fullname = %fullname, "mDNS-SD: advertising started");
            state.advertising = true;
            state.registered_fullname = Some(fullname);
        }
        Ok(())
    }

    async fn stop_advertising(&self) -> Result<(), DiscoveryError> {
        // Phase 1: Clone fullname under lock (don't take — keep it for retry on failure).
        let fullname = {
            let state = self.state.lock().unwrap();
            if !state.advertising {
                return Err(DiscoveryError::NotAdvertising);
            }
            state.registered_fullname.clone()
        };

        // Phase 2: Unregister with daemon (no lock held).
        if let Some(ref fullname) = fullname {
            self.daemon
                .unregister(fullname)
                .map_err(|e| DiscoveryError::BackendError(e.to_string()))?;
            debug!(fullname = %fullname, "mDNS-SD: advertising stopped");
        }

        // Phase 3: Commit state under lock only on success.
        {
            let mut state = self.state.lock().unwrap();
            state.advertising = false;
            state.registered_fullname = None;
        }
        Ok(())
    }

    fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.ensure_browsing();
        self.tx.subscribe()
    }

    async fn shutdown(&self) -> Result<(), DiscoveryError> {
        // Phase 1: Read state under lock.
        let fullname = {
            let mut state = self.state.lock().unwrap();
            state.advertising = false;
            state.registered_fullname.take()
        };

        // Phase 2: Unregister and shut down daemon (no lock held).
        if let Some(ref fullname) = fullname {
            if let Err(e) = self.daemon.unregister(fullname) {
                warn!(fullname = %fullname, "mDNS-SD: failed to unregister during shutdown: {e}");
            }
        }

        self.daemon
            .shutdown()
            .map_err(|e| DiscoveryError::BackendError(e.to_string()))?;
        Ok(())
    }
}
