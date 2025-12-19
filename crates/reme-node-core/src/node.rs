//! Embedded node run loop and core logic.
//!
//! The `EmbeddedNode` handles:
//! - Processing requests from the client via channels
//! - Storing messages in the mailbox
//! - Replicating to peer nodes
//! - Pushing incoming messages to the client

use reme_transport::{NodeError, NodeEvent, NodeRequest, EVENT_CHANNEL_SIZE, REQUEST_CHANNEL_SIZE};
use crate::replication::ReplicationClient;
use crate::storage::MailboxStorage;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use reme_message::{OuterEnvelope, RoutingKey, WirePayload};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

/// Configuration for the embedded node.
#[derive(Debug, Clone)]
pub struct EmbeddedNodeConfig {
    /// Maximum messages per mailbox.
    pub max_messages_per_mailbox: usize,

    /// Default TTL in seconds.
    pub default_ttl_secs: u64,

    /// Peer node URLs for replication.
    pub peers: Vec<String>,

    /// Unique node identifier.
    pub node_id: String,

    /// HTTP server bind address (None to disable HTTP server).
    pub http_bind_addr: Option<SocketAddr>,

    /// Routing keys to monitor for incoming messages (push to client).
    pub monitored_routing_keys: Vec<RoutingKey>,
}

impl Default for EmbeddedNodeConfig {
    fn default() -> Self {
        Self {
            max_messages_per_mailbox: 1000,
            default_ttl_secs: 7 * 24 * 60 * 60, // 7 days
            peers: Vec::new(),
            node_id: uuid::Uuid::new_v4().to_string(),
            http_bind_addr: None,
            monitored_routing_keys: Vec::new(),
        }
    }
}

/// Handle to control the embedded node.
///
/// Drop this handle to request shutdown.
pub struct EmbeddedNodeHandle {
    /// Send requests to the node.
    pub request_tx: mpsc::Sender<NodeRequest>,

    /// Receive events from the node.
    pub event_rx: mpsc::Receiver<NodeEvent>,

    /// The bound HTTP address (if HTTP server is enabled).
    pub http_addr: Option<SocketAddr>,

    /// Cancellation token for graceful shutdown.
    cancel_token: CancellationToken,

    /// Join handle for the node task.
    join_handle: tokio::task::JoinHandle<()>,
}

impl EmbeddedNodeHandle {
    /// Get the bound HTTP address (if HTTP server is enabled).
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// Get the HTTP URL for the embedded node.
    pub fn http_url(&self) -> Option<String> {
        self.http_addr.map(|addr| format!("http://{}", addr))
    }

    /// Clone the request sender for creating transports.
    pub fn request_sender(&self) -> mpsc::Sender<NodeRequest> {
        self.request_tx.clone()
    }

    /// Request graceful shutdown and wait for completion.
    pub async fn shutdown(self) -> Result<(), tokio::task::JoinError> {
        info!("Requesting embedded node shutdown...");
        self.cancel_token.cancel();
        self.join_handle.await
    }
}

/// The embedded node instance.
pub struct EmbeddedNode<S: MailboxStorage> {
    /// Storage backend.
    storage: Arc<S>,

    /// Configuration.
    config: EmbeddedNodeConfig,

    /// Replication client for peer nodes.
    replication: Arc<ReplicationClient>,

    /// Channel to send events to the client.
    event_tx: mpsc::Sender<NodeEvent>,

    /// Routing keys we monitor (push to client when messages arrive).
    monitored_keys: Arc<RwLock<HashSet<RoutingKey>>>,
}

impl<S: MailboxStorage + Send + Sync + 'static> EmbeddedNode<S> {
    /// Create a new embedded node.
    pub fn new(
        storage: Arc<S>,
        config: EmbeddedNodeConfig,
        event_tx: mpsc::Sender<NodeEvent>,
    ) -> Self {
        let monitored_keys: HashSet<RoutingKey> =
            config.monitored_routing_keys.iter().cloned().collect();

        let replication = Arc::new(ReplicationClient::new(
            config.node_id.clone(),
            config.peers.clone(),
        ));

        Self {
            storage,
            config,
            replication,
            event_tx,
            monitored_keys: Arc::new(RwLock::new(monitored_keys)),
        }
    }

    /// Run the node's main event loop.
    pub async fn run(
        self,
        mut request_rx: mpsc::Receiver<NodeRequest>,
        cancel_token: CancellationToken,
    ) {
        info!("Embedded node starting...");
        self.replication.log_config();

        loop {
            tokio::select! {
                biased;

                // Check for cancellation
                _ = cancel_token.cancelled() => {
                    info!("Embedded node received shutdown signal");
                    let _ = self.event_tx.send(NodeEvent::ShuttingDown).await;
                    break;
                }

                // Process requests from client
                Some(request) = request_rx.recv() => {
                    self.handle_request(request).await;
                }

                // Channel closed
                else => {
                    info!("Embedded node request channel closed");
                    break;
                }
            }
        }

        info!("Embedded node stopped");
    }

    /// Handle a request from the client.
    async fn handle_request(&self, request: NodeRequest) {
        match request {
            NodeRequest::SubmitMessage { envelope, response } => {
                let result = self.process_submit_message(envelope, None).await;
                let _ = response.send(result);
            }

            NodeRequest::SubmitTombstone {
                tombstone,
                response,
            } => {
                let result = self.process_submit_tombstone(tombstone).await;
                let _ = response.send(result);
            }

            NodeRequest::FetchMessages {
                routing_key,
                response,
            } => {
                let result = self.storage.mailbox_fetch(&routing_key).await;
                let _ = response.send(result.map_err(|e| NodeError::Storage(e.to_string())));
            }

            NodeRequest::Shutdown => {
                // Handled by cancel_token
                debug!("Received shutdown request via channel");
            }
        }
    }

    /// Process an incoming message submission.
    ///
    /// Called both from channel requests and HTTP handlers.
    pub async fn process_submit_message(
        &self,
        envelope: OuterEnvelope,
        from_node: Option<String>,
    ) -> Result<(), NodeError> {
        let routing_key = envelope.routing_key;
        let message_id = envelope.message_id;

        trace!(?message_id, ?routing_key, "Processing message submission");

        // Check if we already have this message (deduplication)
        match self.storage.mailbox_has_message(&routing_key, &message_id).await {
            Ok(true) => {
                trace!(?message_id, "Duplicate message, skipping");
                return Ok(()); // Idempotent - already stored
            }
            Ok(false) => {}
            Err(e) => {
                warn!(?message_id, error = %e, "Error checking for duplicate");
                // Continue anyway - worst case we get a duplicate
            }
        }

        // Store the message
        let envelope_for_replication = envelope.clone();
        let envelope_for_event = envelope.clone();

        match self.storage.mailbox_enqueue(routing_key, envelope).await {
            Ok(()) => {
                debug!(?message_id, ?routing_key, "Message stored");
            }
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("full") || error_str.contains("Full") {
                    return Err(NodeError::MailboxFull);
                }
                return Err(NodeError::Storage(error_str));
            }
        }

        // Replicate to peers (fire-and-forget)
        let wire_payload = WirePayload::Message(envelope_for_replication);
        let payload_b64 = BASE64_STANDARD.encode(wire_payload.encode());
        self.replication.replicate_payload(payload_b64, from_node);

        // If this message is for a monitored routing key, push to client
        let monitored = self.monitored_keys.read().await;
        if monitored.contains(&routing_key) {
            trace!(?message_id, "Pushing message to client");
            if let Err(e) = self
                .event_tx
                .send(NodeEvent::MessageReceived(envelope_for_event))
                .await
            {
                warn!(?message_id, error = %e, "Failed to push message to client");
            }
        }

        Ok(())
    }

    /// Process a tombstone submission.
    async fn process_submit_tombstone(
        &self,
        tombstone: reme_message::TombstoneEnvelope,
    ) -> Result<(), NodeError> {
        let routing_key = tombstone.routing_key;
        let message_id = tombstone.target_message_id;

        trace!(?message_id, ?routing_key, "Processing tombstone");

        // Delete the message if it exists
        match self.storage.mailbox_delete_message(&routing_key, &message_id).await {
            Ok(deleted) => {
                if deleted {
                    debug!(?message_id, "Message deleted by tombstone");
                } else {
                    trace!(?message_id, "Message not found for tombstone");
                }
            }
            Err(e) => {
                warn!(?message_id, error = %e, "Error deleting message");
                return Err(NodeError::Storage(e.to_string()));
            }
        }

        // Replicate tombstone to peers
        let wire_payload = WirePayload::Tombstone(tombstone);
        let payload_b64 = BASE64_STANDARD.encode(wire_payload.encode());
        self.replication.replicate_payload(payload_b64, None);

        Ok(())
    }

    /// Update the set of monitored routing keys.
    pub async fn set_monitored_keys(&self, keys: Vec<RoutingKey>) {
        let mut monitored = self.monitored_keys.write().await;
        monitored.clear();
        monitored.extend(keys);
        debug!(count = monitored.len(), "Updated monitored routing keys");
    }

    /// Add a routing key to monitor.
    pub async fn add_monitored_key(&self, key: RoutingKey) {
        let mut monitored = self.monitored_keys.write().await;
        monitored.insert(key);
    }

    /// Get the storage reference.
    pub fn storage(&self) -> &Arc<S> {
        &self.storage
    }

    /// Get the replication client.
    pub fn replication(&self) -> &Arc<ReplicationClient> {
        &self.replication
    }
}

/// Start an embedded node with the given storage and configuration.
///
/// Returns a handle for controlling the node and receiving events.
pub async fn start_embedded_node<S: MailboxStorage + Send + Sync + 'static>(
    storage: Arc<S>,
    config: EmbeddedNodeConfig,
) -> Result<EmbeddedNodeHandle, NodeError> {
    let (request_tx, request_rx) = mpsc::channel(REQUEST_CHANNEL_SIZE);
    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_SIZE);
    let cancel_token = CancellationToken::new();

    // Create monitored keys set
    let monitored_keys: HashSet<RoutingKey> =
        config.monitored_routing_keys.iter().cloned().collect();
    let monitored_keys = Arc::new(RwLock::new(monitored_keys));

    // Create replication client
    let replication = Arc::new(ReplicationClient::new(
        config.node_id.clone(),
        config.peers.clone(),
    ));

    // Start HTTP server if configured
    let http_addr = if let Some(bind_addr) = config.http_bind_addr {
        let http_state = Arc::new(crate::http::HttpState {
            storage: storage.clone(),
            event_tx: event_tx.clone(),
            monitored_keys: monitored_keys.clone(),
            replication: replication.clone(),
        });

        match crate::http::start_http_server(bind_addr, http_state, cancel_token.clone()).await {
            Ok(addr) => {
                info!("HTTP server started on {}", addr);
                Some(addr)
            }
            Err(e) => {
                return Err(NodeError::Storage(format!("Failed to start HTTP server: {}", e)));
            }
        }
    } else {
        None
    };

    // Create the embedded node with shared state
    let node = EmbeddedNode {
        storage,
        config,
        replication,
        event_tx,
        monitored_keys,
    };

    let cancel = cancel_token.clone();
    let join_handle = tokio::spawn(async move {
        node.run(request_rx, cancel).await;
    });

    info!("Embedded node started");

    Ok(EmbeddedNodeHandle {
        request_tx,
        event_rx,
        http_addr,
        cancel_token,
        join_handle,
    })
}
