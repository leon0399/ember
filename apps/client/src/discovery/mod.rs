pub mod controller;

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use crate::config::AppConfig;
use reme_discovery::mdns_sd::MdnsSdBackend;
use reme_discovery::DiscoveryBackend as _;
use reme_identity::{Identity, PublicID};
use reme_storage::Storage;
use reme_transport::coordinator::TransportCoordinator;
use reme_transport::registry::TransportRegistry;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Consolidated discovery subsystem state.
///
/// Groups the mDNS backend, cancellation token, and controller task handle
/// that were previously stored as three separate `Option` fields in `App`.
pub struct DiscoveryState {
    pub backend: Arc<MdnsSdBackend>,
    pub cancel: CancellationToken,
    pub controller_task: Option<JoinHandle<()>>,
    /// Channel for dynamically adding contacts to the controller at runtime.
    pub contact_tx: Option<mpsc::UnboundedSender<(PublicID, [u8; 16])>>,
    /// Shared counter of currently discovered (verified) LAN peers.
    pub peer_count: Arc<AtomicUsize>,
}

/// Result of attempting to initialize the discovery subsystem.
pub enum InitResult {
    /// Discovery is disabled in config.
    Disabled,
    /// mDNS backend failed to initialize (discovery was enabled).
    Failed(String),
    /// Successfully initialized.
    Ok(DiscoveryState),
}

/// Initialize the LAN discovery subsystem.
///
/// Creates the mDNS-SD backend, optionally spawns the discovery controller
/// (when `auto_direct_known_contacts` is enabled), and starts advertising
/// if an HTTP server bind address is configured.
///
/// Returns [`InitResult`] distinguishing disabled, failed, and success cases.
pub async fn initialize(
    config: &AppConfig,
    identity: &Identity,
    storage: &Storage,
    coordinator: Arc<TransportCoordinator>,
    registry: Arc<TransportRegistry>,
) -> InitResult {
    if !config.lan_discovery.enabled {
        return InitResult::Disabled;
    }

    let backend = match MdnsSdBackend::new() {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to initialize mDNS backend: {e}. LAN discovery disabled.");
            return InitResult::Failed(format!("{e}"));
        }
    };

    let peer_count = Arc::new(AtomicUsize::new(0));

    // Spawn discovery controller only if direct LAN delivery is allowed
    let cancel = CancellationToken::new();
    let (controller_task, contact_tx) = if config.lan_discovery.auto_direct_known_contacts {
        let contacts = storage
            .list_contacts()
            .unwrap_or_else(|e| {
                warn!("Failed to load contacts for discovery: {e}");
                Vec::new()
            })
            .into_iter()
            .map(|(_, pubkey, _)| {
                let rk: [u8; 16] = pubkey.routing_key().into();
                (pubkey, rk)
            })
            .collect();

        let events = backend.subscribe();
        let (contact_tx, contact_rx) = mpsc::unbounded_channel();
        let task = controller::spawn(controller::SpawnConfig {
            events,
            coordinator,
            registry,
            contacts,
            max_peers: config.lan_discovery.max_peers,
            refresh_interval_secs: config.lan_discovery.refresh_interval_secs,
            cancel: cancel.clone(),
            contact_rx,
            peer_count: peer_count.clone(),
        });
        (Some(task), Some(contact_tx))
    } else {
        info!("LAN discovery active but direct delivery disabled (auto_direct_known_contacts = false)");
        (None, None)
    };

    // Start advertising only if the embedded node is enabled and HTTP server is bound.
    // Without `enabled`, there is no HTTP server listening — advertising a dead
    // endpoint would cause discovery probes to fail silently.
    if let Some(http_bind) = config
        .embedded_node
        .http_bind
        .as_ref()
        .filter(|_| config.embedded_node.enabled)
    {
        let port: u16 = http_bind
            .parse::<std::net::SocketAddr>()
            .map(|a| a.port())
            .unwrap_or(23004);

        let our_rk: [u8; 16] = identity.public_id().routing_key().into();
        let txt = reme_discovery::encode_txt(&our_rk, port);
        let spec = reme_discovery::AdvertisementSpec {
            txt_records: txt,
            ..reme_discovery::AdvertisementSpec::new(port)
        };

        if let Err(e) = backend.start_advertising(spec).await {
            warn!("Failed to start mDNS advertising: {e}");
        }
    }

    info!("LAN discovery enabled");
    let backend = Arc::new(backend);
    InitResult::Ok(DiscoveryState {
        backend,
        cancel,
        controller_task,
        contact_tx,
        peer_count,
    })
}
