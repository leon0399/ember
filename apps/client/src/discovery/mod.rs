pub mod controller;

use std::sync::Arc;

use crate::config::AppConfig;
use reme_discovery::mdns_sd::MdnsSdBackend;
use reme_discovery::DiscoveryBackend as _;
use reme_identity::Identity;
use reme_storage::Storage;
use reme_transport::coordinator::TransportCoordinator;
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
}

/// Initialize the LAN discovery subsystem.
///
/// Creates the mDNS-SD backend, optionally spawns the discovery controller
/// (when `auto_direct_known_contacts` is enabled), and starts advertising
/// if an HTTP server bind address is configured.
///
/// Returns `None` if discovery is disabled or the backend fails to initialize.
pub async fn initialize(
    config: &AppConfig,
    identity: &Identity,
    storage: &Storage,
    coordinator: Arc<TransportCoordinator>,
) -> Option<DiscoveryState> {
    if !config.lan_discovery.enabled {
        return None;
    }

    let backend = match MdnsSdBackend::new() {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to initialize mDNS backend: {e}. LAN discovery disabled.");
            return None;
        }
    };

    // Spawn discovery controller only if direct LAN delivery is allowed
    let cancel = CancellationToken::new();
    let controller_task = if config.lan_discovery.auto_direct_known_contacts {
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
        Some(controller::spawn(
            events,
            coordinator,
            contacts,
            config.lan_discovery.max_peers,
            config.lan_discovery.refresh_interval_secs,
            cancel.clone(),
        ))
    } else {
        info!("LAN discovery active but direct delivery disabled (auto_direct_known_contacts = false)");
        None
    };

    // Start advertising only if HTTP server is bound
    if let Some(ref http_bind) = config.embedded_node.http_bind {
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
    Some(DiscoveryState {
        backend,
        cancel,
        controller_task,
    })
}
