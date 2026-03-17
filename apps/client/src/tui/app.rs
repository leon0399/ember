//! Application state and main loop

use crate::config::AppConfig;
use crate::tui::event::{Event, EventHandler};
use crate::tui::http_server;
use crate::tui::ui;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use ratatui::prelude::*;
use reme_config::{ParsedHttpPeer, ParsedMqttPeer};
use reme_core::Client;
use reme_identity::{Identity, PublicID};
use reme_message::Content;
use reme_node_core::{
    EmbeddedNode, EmbeddedNodeHandle, NodeEvent, PersistentMailboxStore, PersistentStoreConfig,
};
use reme_outbox::{OutboxConfig, TransportRetryPolicy};
use reme_storage::Storage;
use reme_transport::http_target::{HttpTarget, HttpTargetConfig};
use reme_transport::pool::TransportPool;
use reme_transport::target::TargetKind;
use reme_transport::{
    CoordinatorConfig, CoordinatorHandle, DeliveryTier, MqttTarget, MqttTargetConfig,
    ReceiverConfig, TargetId, TransportCoordinator, TransportEvent, TransportRegistry,
    TransportTarget,
};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use tui_textarea::{Input, TextArea};
use zeroize::Zeroizing;

pub type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Length of a `PublicID` when encoded as hexadecimal (32 bytes = 64 hex chars)
const PUBLIC_ID_HEX_LENGTH: usize = 64;

/// Help text shown in status bar (Alt+H or initial startup)
const HELP_TEXT: &str =
    "Alt+A/F2: add | Alt+U/F4: upstream | Alt+V/F5: view | Alt+I/F3: identity | Ctrl+Q: quit";

/// Short help hint for status bar
const HELP_HINT: &str = "Alt+H for help";

/// Maximum number of messages to cache per conversation (prevents unbounded memory growth)
const MAX_CACHED_MESSAGES_PER_CONTACT: usize = 500;

/// Maximum length for contact display names (prevents UI issues and potential abuse)
const MAX_NAME_LENGTH: usize = 64;

/// Focus area in the UI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Conversations,
    Messages,
    Input,
}

/// Which field is focused in the add contact popup
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddContactField {
    #[default]
    PublicId,
    Name,
}

/// Transport type for ephemeral upstream
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpstreamType {
    #[default]
    Http,
    Mqtt,
}

impl UpstreamType {
    /// Toggle between HTTP and MQTT
    pub fn toggle(&mut self) {
        *self = match self {
            UpstreamType::Http => UpstreamType::Mqtt,
            UpstreamType::Mqtt => UpstreamType::Http,
        };
    }
}

/// Which field is focused in the add upstream popup
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddUpstreamField {
    #[default]
    Type,
    Tier,
    Url,
}

/// State for the add contact popup
pub struct AddContactPopup<'a> {
    /// Currently focused field
    pub focused_field: AddContactField,
    /// Public ID input (64-char hex)
    pub public_id_input: TextArea<'a>,
    /// Name input (optional)
    pub name_input: TextArea<'a>,
    /// Error message to display
    pub error: Option<String>,
}

impl Default for AddContactPopup<'_> {
    fn default() -> Self {
        let mut public_id_input = TextArea::default();
        public_id_input
            .set_placeholder_text(format!("{PUBLIC_ID_HEX_LENGTH}-character hex string"));
        public_id_input.set_cursor_line_style(Style::default());

        let mut name_input = TextArea::default();
        name_input.set_placeholder_text("Display name (optional)");
        name_input.set_cursor_line_style(Style::default());

        Self {
            focused_field: AddContactField::PublicId,
            public_id_input,
            name_input,
            error: None,
        }
    }
}

impl AddContactPopup<'_> {
    /// Reset the popup to initial state
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Toggle focus between fields
    pub fn toggle_field(&mut self) {
        self.focused_field = match self.focused_field {
            AddContactField::PublicId => AddContactField::Name,
            AddContactField::Name => AddContactField::PublicId,
        };
    }

    /// Validate the public ID input
    pub fn validate_public_id(&self) -> Result<PublicID, String> {
        let hex_str: String = self.public_id_input.lines().join("");
        let hex_str = hex_str.trim();

        if hex_str.is_empty() {
            return Err("Public ID is required".to_string());
        }

        if hex_str.len() != PUBLIC_ID_HEX_LENGTH {
            return Err(format!(
                "Public ID must be {} hex characters (got {})",
                PUBLIC_ID_HEX_LENGTH,
                hex_str.len()
            ));
        }

        let bytes =
            hex::decode(hex_str).map_err(|_| "Invalid hex characters in Public ID".to_string())?;

        // Safe: hex::decode of 64-char hex string always produces exactly 32 bytes
        let bytes: [u8; 32] = bytes
            .try_into()
            .expect("hex::decode of 64-char hex produces 32 bytes");

        PublicID::try_from_bytes(&bytes)
            .map_err(|_| "Invalid Public ID: not a valid Curve25519 public key".to_string())
    }

    /// Get the name input (None if empty, truncated if too long)
    pub fn get_name(&self) -> Option<String> {
        let name_str = self.name_input.lines().join("");
        let name = name_str.trim();
        if name.is_empty() {
            None
        } else {
            // Truncate to max length to prevent UI issues and abuse
            let truncated: String = name.chars().take(MAX_NAME_LENGTH).collect();
            Some(truncated)
        }
    }
}

/// State for the add upstream popup
pub struct AddUpstreamPopup<'a> {
    /// Currently focused field
    pub focused_field: AddUpstreamField,
    /// Selected transport type
    pub transport_type: UpstreamType,
    /// Selected delivery tier
    pub tier: DeliveryTier,
    /// URL input
    pub url_input: TextArea<'a>,
    /// Error message to display
    pub error: Option<String>,
}

impl Default for AddUpstreamPopup<'_> {
    fn default() -> Self {
        let mut url_input = TextArea::default();
        url_input.set_placeholder_text("http://192.168.1.50:23003");
        url_input.set_cursor_line_style(Style::default());

        Self {
            focused_field: AddUpstreamField::Type,
            transport_type: UpstreamType::Http,
            tier: DeliveryTier::Direct,
            url_input,
            error: None,
        }
    }
}

impl AddUpstreamPopup<'_> {
    /// Reset the popup to initial state
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Toggle focus between fields
    pub fn toggle_field(&mut self) {
        self.focused_field = match self.focused_field {
            AddUpstreamField::Type => AddUpstreamField::Tier,
            AddUpstreamField::Tier => AddUpstreamField::Url,
            AddUpstreamField::Url => AddUpstreamField::Type,
        };
    }

    /// Toggle the delivery tier
    pub fn toggle_tier(&mut self) {
        self.tier = match self.tier {
            DeliveryTier::Direct => DeliveryTier::Quorum,
            DeliveryTier::Quorum => DeliveryTier::BestEffort,
            DeliveryTier::BestEffort => DeliveryTier::Direct,
        };
    }

    /// Get the URL input (trimmed)
    pub fn get_url(&self) -> String {
        self.url_input.lines().join("").trim().to_string()
    }

    /// Validate the URL input
    pub fn validate_url(&self) -> Result<String, String> {
        let url = self.get_url();

        if url.is_empty() {
            return Err("URL is required".to_string());
        }

        // Get schemes and type name based on transport type
        let (schemes, type_name) = match self.transport_type {
            UpstreamType::Http => (&["http://", "https://"][..], "HTTP"),
            UpstreamType::Mqtt => (&["mqtt://", "mqtts://"][..], "MQTT"),
        };

        // Check scheme prefix
        if !schemes.iter().any(|s| url.starts_with(s)) {
            return Err(format!(
                "{} URL must start with {} or {}",
                type_name, schemes[0], schemes[1]
            ));
        }

        // Basic sanity check: must have host after scheme
        let after_scheme = schemes
            .iter()
            .find_map(|s| url.strip_prefix(s))
            .unwrap_or("");
        if after_scheme.is_empty() || after_scheme.starts_with('/') {
            return Err(format!("Invalid {type_name} URL: missing host"));
        }

        Ok(url)
    }
}

/// A conversation/contact entry
#[derive(Debug, Clone)]
pub struct Conversation {
    #[allow(dead_code)] // Field for future UI features (editing, deleting contacts)
    pub id: i64,
    pub public_id: PublicID,
    pub name: String,
    pub last_message: Option<String>,
    pub unread_count: u32,
}

/// A message in the conversation
#[derive(Debug, Clone)]
pub struct Message {
    pub from_me: bool,
    pub sender_name: String,
    pub content: String,
    pub timestamp: String,
}

/// Application state
#[allow(clippy::struct_excessive_bools)] // UI state naturally has many boolean flags
pub struct App<'a> {
    /// Is the application running?
    pub running: bool,
    /// Current focus
    pub focus: Focus,
    /// List of conversations
    pub conversations: Vec<Conversation>,
    /// Selected conversation index
    pub selected_conversation: usize,
    /// Messages in current conversation
    pub messages: Vec<Message>,
    /// Message scroll offset
    pub message_scroll: u16,
    /// Input text area
    pub input: TextArea<'a>,
    /// Status message
    pub status: String,
    /// The messenger client (uses `TransportCoordinator` for sending via HTTP and/or MQTT)
    client: Client<TransportCoordinator>,
    /// Transport coordinator for unified multi-transport messaging
    coordinator: Arc<TransportCoordinator>,
    /// Coordinator event receiver for incoming messages
    coordinator_events: mpsc::UnboundedReceiver<TransportEvent>,
    /// Coordinator subscription handle (dropped on shutdown to cancel polling)
    _coordinator_handle: CoordinatorHandle,
    /// Embedded node handle (for shutdown)
    embedded_node_handle: Option<EmbeddedNodeHandle>,
    /// Embedded node task join handle (for awaiting shutdown)
    embedded_node_task: Option<tokio::task::JoinHandle<()>>,
    /// Embedded node event receiver (for incoming LAN messages)
    node_event_rx: Option<mpsc::Receiver<NodeEvent>>,
    /// Contacts by name (for reverse lookup)
    contacts_by_id: HashMap<PublicID, String>,
    /// In-memory message cache per contact (until storage retrieval is implemented)
    message_cache: HashMap<PublicID, VecDeque<Message>>,
    /// Whether the add contact popup is visible
    pub show_add_contact_popup: bool,
    /// Add contact popup state
    pub add_contact_popup: AddContactPopup<'a>,
    /// Whether the "my identity" popup is visible
    pub show_my_id_popup: bool,
    /// Whether the add upstream popup is visible
    pub show_add_upstream_popup: bool,
    /// Add upstream popup state
    pub add_upstream_popup: AddUpstreamPopup<'a>,
    /// Whether the view upstreams popup is visible
    pub show_upstreams_popup: bool,
    /// Transport registry for querying and managing transports
    pub registry: TransportRegistry,
    /// Outbox tick interval from config
    outbox_tick_interval: Duration,
}

impl App<'_> {
    /// Create a new app instance
    ///
    /// # Arguments
    /// * `config` - Application configuration
    /// * `identity` - The loaded/decrypted identity
    #[allow(clippy::too_many_lines)] // App initialization requires many steps
    pub async fn new(config: AppConfig, identity: Identity) -> AppResult<Self> {
        // Ensure data directory exists
        fs::create_dir_all(&config.data_dir)?;

        // Create storage
        let db_path = config.data_dir.join("messages.db");
        let db_path_str = db_path
            .to_str()
            .ok_or("Database path contains invalid UTF-8 characters")?;
        let storage = Storage::open(db_path_str)?;

        // Parse and validate all HTTP peers
        let parsed_http_peers: Vec<ParsedHttpPeer> = config
            .peers
            .http
            .iter()
            .map(|peer| ParsedHttpPeer::try_from(peer.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse HTTP peer configuration: {e}"))?;

        // Create HTTP transport pool with tier/priority/label configuration
        let http_pool = if parsed_http_peers.is_empty() {
            None
        } else {
            let pool = TransportPool::new();

            for parsed_peer in &parsed_http_peers {
                // Build HTTP target config with all metadata
                let mut config = HttpTargetConfig::stable(&parsed_peer.url);

                // Set certificate pin if present (convert from config type to transport type)
                if let Some(ref pin) = parsed_peer.cert_pin {
                    match reme_transport::CertPin::parse(&pin.to_pin_string()) {
                        Ok(transport_pin) => {
                            config = config.with_cert_pin(transport_pin);
                        }
                        Err(e) => {
                            warn!(
                                url = %parsed_peer.url,
                                error = %e,
                                "Certificate pin conversion failed after successful validation - this is a bug"
                            );
                        }
                    }
                }

                // Set label if present
                if let Some(ref label) = parsed_peer.common.label {
                    config = config.with_label(label.clone());
                }

                // Set priority (u16 from config -> u8 for transport, clamped)
                let priority_u8 = if parsed_peer.common.priority > 255 {
                    warn!(
                        url = %parsed_peer.url,
                        configured = parsed_peer.common.priority,
                        "Priority {} exceeds maximum 255, clamping to 255",
                        parsed_peer.common.priority
                    );
                    255
                } else {
                    // Safe cast: we've validated priority <= 255
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        parsed_peer.common.priority as u8
                    }
                };
                config = config.with_priority(priority_u8);

                // Set node pubkey if present
                config = config.with_node_pubkey_opt(parsed_peer.node_pubkey);

                // Set HTTP Basic Auth if configured
                if let Some((username, password)) = &parsed_peer.auth {
                    config = config.with_auth(username, password);
                }

                // Create target and add to pool
                let target = HttpTarget::new(config)?;
                pool.add_target(target);
            }

            Some(Arc::new(pool))
        };

        // Parse and validate all MQTT peers
        let parsed_mqtt_peers: Vec<ParsedMqttPeer> = config
            .peers
            .mqtt
            .iter()
            .map(|peer| ParsedMqttPeer::try_from(peer.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse MQTT peer configuration: {e}"))?;

        // Extract identity bytes for HTTP server (before embedded node block)
        // This allows us to create a separate Identity instance for the HTTP server
        // while still passing the original identity to Client::with_config
        // Wrapped in Zeroizing to ensure secret key is cleared from memory when dropped
        let identity_bytes = Zeroizing::new(identity.to_bytes());

        // Create embedded node if enabled
        let (embedded_node_handle, embedded_node_task, node_event_rx) = if config
            .embedded_node
            .enabled
        {
            info!("Starting embedded node...");

            // Create persistent store config from app config
            let store_config = PersistentStoreConfig::new(
                config.embedded_node.max_messages as usize,
                config.embedded_node.default_ttl_secs,
            )
            .map_err(|e| format!("Invalid embedded node config: {e}"))?;

            // Create mailbox store in the same data directory
            let mailbox_db_path = config.data_dir.join("mailbox.db");
            let mailbox_db_str = mailbox_db_path
                .to_str()
                .ok_or("Mailbox database path contains invalid UTF-8 characters")?;
            let mailbox_store = PersistentMailboxStore::open(mailbox_db_str, store_config)
                .map_err(|e| format!("Failed to open mailbox store: {e}"))?;

            // Create and spawn embedded node, keeping JoinHandle for graceful shutdown
            let (node, handle, event_rx) = EmbeddedNode::new(mailbox_store);
            let join_handle = tokio::spawn(async move { node.run().await });

            info!("Embedded node started");

            // Start HTTP server for LAN P2P if configured
            // Bind BEFORE spawning to fail fast on port conflicts
            if let Some(ref bind_addr) = config.embedded_node.http_bind {
                let http_handle = handle.clone();
                let our_routing_key = identity.public_id().routing_key();

                // Create a separate Identity instance for the HTTP server
                // This is needed because identity will be moved to Client::with_config later
                let http_identity = Arc::new(Identity::from_bytes(&identity_bytes));

                // Bind first to verify address is valid and port is available
                let (listener, router) = http_server::bind_server(
                    bind_addr,
                    http_handle,
                    our_routing_key,
                    http_identity,
                )
                .await
                .map_err(|e| format!("Failed to start HTTP server: {e}"))?;

                // Now spawn the server task - binding already succeeded
                tokio::spawn(async move {
                    if let Err(e) = http_server::run_server(listener, router).await {
                        tracing::error!(error = %e, "Embedded HTTP server stopped unexpectedly");
                    }
                });
            }

            (Some(handle), Some(join_handle), Some(event_rx))
        } else {
            (None, None, None)
        };

        // Build transport coordinator with 2s poll interval (matching old MessageReceiver)
        let coordinator_config = CoordinatorConfig {
            receiver_config: ReceiverConfig::with_poll_interval(Duration::from_secs(2)),
            ..CoordinatorConfig::default()
        };
        let mut coordinator = TransportCoordinator::new(coordinator_config);

        // Add HTTP pool to coordinator
        if let Some(http) = http_pool {
            coordinator.set_http_pool_arc(http);
        }

        // Create MQTT pool and connect configured brokers in parallel.
        // Pool is always created so runtime MQTT adds work even without initial config.
        let mqtt_pool = TransportPool::new();
        if !parsed_mqtt_peers.is_empty() {
            let mut join_set = tokio::task::JoinSet::new();
            for parsed_peer in parsed_mqtt_peers.iter().cloned() {
                join_set.spawn(async move {
                    let mut mqtt_config = MqttTargetConfig::new(&parsed_peer.url);
                    if let Some(ref client_id) = parsed_peer.client_id {
                        mqtt_config = mqtt_config.with_client_id(client_id);
                    }
                    if let Some(ref auth) = parsed_peer.auth {
                        mqtt_config = mqtt_config.with_auth(&auth.0, &auth.1);
                    }
                    if let Some(ref label) = parsed_peer.common.label {
                        mqtt_config = mqtt_config.with_label(label);
                    }
                    if let Some(ref prefix) = parsed_peer.topic_prefix {
                        mqtt_config = mqtt_config.with_topic_prefix(prefix);
                    }
                    #[allow(clippy::cast_possible_truncation)]
                    let priority = parsed_peer.common.priority as u8;
                    mqtt_config = mqtt_config.with_priority(priority);
                    (
                        parsed_peer.url.clone(),
                        MqttTarget::connect(mqtt_config).await,
                    )
                });
            }

            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok((_, Ok(target))) => {
                        mqtt_pool.add_target(target);
                    }
                    Ok((url, Err(e))) => {
                        warn!(
                            url = %url,
                            error = %e,
                            "Failed to connect to MQTT broker, skipping"
                        );
                    }
                    Err(e) => {
                        warn!(error = %e, "MQTT connection task panicked");
                    }
                }
            }
        }
        let mqtt_pool_arc = Arc::new(mqtt_pool);
        coordinator.set_mqtt_pool_arc(mqtt_pool_arc.clone());

        // Note: Embedded node is intentionally NOT added to the coordinator.
        // The embedded node stores messages locally, but recipients fetch via HTTP server
        // (started above if http_bind is configured). Direct P2P messaging uses the
        // direct_peers config to send TO contacts, and HTTP server to receive FROM them.

        // Add direct peers as ephemeral HTTP targets
        // Ensure HTTP pool exists if we have direct peers but no HTTP nodes
        if !config.direct_peers.is_empty() && coordinator.http_pool().is_none() {
            coordinator.set_http_pool(TransportPool::new());
        }

        let mut direct_peer_ids: Vec<(TargetId, Option<String>)> = Vec::new();
        for peer in &config.direct_peers {
            let target_config = HttpTargetConfig::new(&peer.address, TargetKind::Ephemeral)
                .with_label(peer.name.as_deref().unwrap_or(&peer.address));

            match HttpTarget::new(target_config) {
                Ok(target) => {
                    info!(
                        address = %peer.address,
                        name = peer.name.as_deref().unwrap_or("(unnamed)"),
                        "Added direct peer"
                    );
                    direct_peer_ids.push((target.id().clone(), peer.name.clone()));
                    coordinator.add_http_target(target);
                }
                Err(e) => {
                    warn!(
                        address = %peer.address,
                        error = %e,
                        "Failed to add direct peer, skipping"
                    );
                }
            }
        }

        // Ensure we have at least one transport
        if !coordinator.has_transports() {
            return Err("No transports configured. Add HTTP nodes and/or MQTT brokers.".into());
        }

        // Subscribe to incoming messages before wrapping in Arc
        let our_routing_key = identity.public_id().routing_key();
        let (coordinator_events, coordinator_handle) = coordinator.subscribe(our_routing_key);

        let coordinator = Arc::new(coordinator);

        // Create transport registry for UI queries
        let mut registry = TransportRegistry::new();
        if let Some(http) = coordinator.http_pool() {
            registry.set_http_pool(http.clone());
        }
        registry.set_mqtt_pool(mqtt_pool_arc);

        // Register HTTP targets with their tier/label information
        for parsed_peer in &parsed_http_peers {
            let id = TargetId::http(&parsed_peer.url);
            let tier = match parsed_peer.common.tier {
                reme_config::ConfiguredTier::Quorum => DeliveryTier::Quorum,
                reme_config::ConfiguredTier::BestEffort => DeliveryTier::BestEffort,
            };
            registry.register_stable(id, parsed_peer.common.label.clone(), tier);
        }

        // Register MQTT brokers for display
        for parsed_peer in &parsed_mqtt_peers {
            let id = TargetId::mqtt(&parsed_peer.url);
            let tier = match parsed_peer.common.tier {
                reme_config::ConfiguredTier::Quorum => DeliveryTier::Quorum,
                reme_config::ConfiguredTier::BestEffort => DeliveryTier::BestEffort,
            };
            registry.register_stable(id, parsed_peer.common.label.clone(), tier);
        }

        // Register direct peers for display
        for (id, label) in direct_peer_ids {
            registry.register_stable(id, label, DeliveryTier::Direct);
        }

        // Build OutboxConfig from app config
        let ttl_ms = if config.outbox.ttl_days == 0 {
            None
        } else {
            Some(config.outbox.ttl_days * 24 * 60 * 60 * 1000)
        };
        let outbox_config = OutboxConfig {
            default_ttl_ms: ttl_ms,
            attempt_timeout_ms: config.outbox.attempt_timeout_secs * 1000,
            ..OutboxConfig::default()
        };

        // Create custom retry policy from config
        let retry_policy = TransportRetryPolicy {
            initial_delay: Duration::from_secs(config.outbox.retry_initial_delay_secs),
            max_delay: Duration::from_secs(config.outbox.retry_max_delay_secs),
            ..TransportRetryPolicy::default()
        };

        // Create client with coordinator transport
        let mut client = Client::with_config(identity, coordinator.clone(), storage, outbox_config);

        // Set HTTP transport retry policy
        client.set_transport_policy("http:", retry_policy);

        // Store tick interval from config
        let outbox_tick_interval = Duration::from_secs(config.outbox.tick_interval_secs);

        // Create input area
        let mut input = TextArea::default();
        input.set_placeholder_text("Type a message...");
        input.set_cursor_line_style(Style::default());

        let mut app = Self {
            running: true,
            focus: Focus::Conversations,
            conversations: Vec::new(),
            selected_conversation: 0,
            messages: Vec::new(),
            message_scroll: 0,
            input,
            status: HELP_HINT.to_string(),
            client,
            coordinator,
            coordinator_events,
            _coordinator_handle: coordinator_handle,
            embedded_node_handle,
            embedded_node_task,
            node_event_rx,
            contacts_by_id: HashMap::new(),
            message_cache: HashMap::new(),
            show_add_contact_popup: false,
            add_contact_popup: AddContactPopup::default(),
            show_my_id_popup: false,
            show_add_upstream_popup: false,
            add_upstream_popup: AddUpstreamPopup::default(),
            show_upstreams_popup: false,
            registry,
            outbox_tick_interval,
        };

        // Load contacts
        app.load_contacts()?;

        Ok(app)
    }

    /// Load contacts from storage
    fn load_contacts(&mut self) -> AppResult<()> {
        let contacts = self.client.list_contacts()?;
        self.conversations.clear();
        self.contacts_by_id.clear();

        for contact in contacts {
            let name = format_display_name(contact.name.as_deref(), &contact.public_id);

            self.contacts_by_id.insert(contact.public_id, name.clone());

            self.conversations.push(Conversation {
                id: contact.id,
                public_id: contact.public_id,
                name,
                last_message: None, // TODO: Load from storage
                unread_count: 0,
            });
        }

        Ok(())
    }

    /// Get current user's public ID
    pub fn my_public_id(&self) -> &PublicID {
        self.client.public_id()
    }

    /// Get short ID for display
    pub fn my_short_id(&self) -> String {
        let hex = hex::encode(self.my_public_id().to_bytes());
        format!("{}...", &hex[..8])
    }

    /// Get full ID as hex string
    pub fn my_full_id(&self) -> String {
        hex::encode(self.my_public_id().to_bytes())
    }

    /// Run the application main loop
    pub async fn run(&mut self, terminal: &mut Terminal<impl Backend>) -> AppResult<()> {
        let mut event_handler = EventHandler::new(100);
        let mut last_outbox_tick = Instant::now();

        while self.running {
            // Draw UI
            terminal.draw(|frame| ui::render(frame, self))?;

            // Check for incoming messages from coordinator (non-blocking)
            while let Ok(event) = self.coordinator_events.try_recv() {
                if let TransportEvent::Message(envelope) = event {
                    self.process_incoming_envelope(&envelope, "coordinator")
                        .await;
                }
            }

            // Check for incoming messages from embedded node (non-blocking)
            // Collect events first to avoid borrow conflicts
            let node_events: Vec<NodeEvent> = if let Some(ref mut event_rx) = self.node_event_rx {
                let mut events = Vec::new();
                while let Ok(event) = event_rx.try_recv() {
                    events.push(event);
                }
                events
            } else {
                Vec::new()
            };

            for event in node_events {
                match event {
                    NodeEvent::MessageReceived(envelope) => {
                        debug!("Received message from embedded node");
                        self.process_incoming_envelope(&envelope, "embedded node")
                            .await;
                    }
                    NodeEvent::Error(e) => {
                        tracing::error!("Embedded node error: {}", e);
                        self.status = format!("Node error: {e}");
                    }
                }
            }

            // Handle UI events
            match event_handler.next().await? {
                Event::Tick => {
                    // Periodically run outbox tick for message retries
                    if last_outbox_tick.elapsed() >= self.outbox_tick_interval {
                        match self.client.outbox_tick().await {
                            Ok((retried, expired)) => {
                                if retried > 0 || expired > 0 {
                                    info!(
                                        retried = retried,
                                        expired = expired,
                                        "Outbox tick completed"
                                    );
                                } else {
                                    debug!("Outbox tick: no pending messages");
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "Outbox tick failed");
                            }
                        }
                        last_outbox_tick = Instant::now();
                    }
                }
                Event::Key(key_event) => self.handle_key_event(key_event).await?,
                Event::Resize(_, _) => {}
            }
        }

        // Graceful shutdown of embedded node
        self.shutdown_embedded_node().await;

        Ok(())
    }

    /// Shutdown the embedded node gracefully.
    ///
    /// First signals the node to shutdown via the handle, then awaits
    /// the background task to ensure it has fully completed.
    async fn shutdown_embedded_node(&mut self) {
        if let Some(ref handle) = self.embedded_node_handle {
            debug!("Shutting down embedded node...");
            if let Err(e) = handle.shutdown().await {
                warn!(error = %e, "Failed to signal embedded node shutdown");
            }
        }

        // Await the background task to ensure it has fully completed
        if let Some(join_handle) = self.embedded_node_task.take() {
            debug!("Waiting for embedded node task to complete...");
            if let Err(e) = join_handle.await {
                warn!(error = %e, "Embedded node task panicked during shutdown");
            } else {
                info!("Embedded node shutdown complete");
            }
        }
    }

    /// Process an incoming envelope from any transport source.
    ///
    /// Decrypts the message, extracts content, and updates the UI.
    async fn process_incoming_envelope(
        &mut self,
        envelope: &reme_message::OuterEnvelope,
        source: &str,
    ) {
        match self.client.process_message(envelope).await {
            Ok(msg) => {
                let content = match &msg.content {
                    Content::Text(t) => t.body.clone(),
                    Content::Receipt(r) => format!("[Receipt: {:?}]", r.kind),
                    _ => "[Unknown content]".to_string(),
                };
                self.handle_incoming_message(msg.from, content);
            }
            Err(e) => {
                warn!("Failed to process {} message: {}", source, e);
                self.status = format!("Message decrypt failed: {e}");
            }
        }
    }

    /// Get or create a conversation for a contact, returns the index
    fn get_or_create_conversation(&mut self, public_id: PublicID) -> usize {
        // Check if conversation exists
        if let Some(idx) = self
            .conversations
            .iter()
            .position(|c| c.public_id == public_id)
        {
            return idx;
        }

        // Get contact info from storage (reme-core auto-adds on message receive)
        // Single call to avoid duplicate lookups
        let (contact_id, display_name) = match self.client.get_contact(&public_id) {
            Ok(contact) => {
                let name = format_display_name(contact.name.as_deref(), &public_id);
                (contact.id, name)
            }
            Err(_) => (0, format_display_name(None, &public_id)),
        };

        // Add to tracking
        self.contacts_by_id.insert(public_id, display_name.clone());
        self.conversations.push(Conversation {
            id: contact_id,
            public_id,
            name: display_name,
            last_message: None,
            unread_count: 0,
        });

        self.conversations.len() - 1
    }

    /// Handle incoming message
    fn handle_incoming_message(&mut self, from: PublicID, content: String) {
        // Get or create conversation
        let conv_idx = self.get_or_create_conversation(from);
        let sender_name = self.contacts_by_id.get(&from).cloned().unwrap_or_default();

        // Create message
        let message = Message {
            from_me: false,
            sender_name,
            content: content.clone(),
            timestamp: utc_time_now(),
        };

        // Cache message
        self.cache_message(from, message.clone());

        // Update conversation
        self.conversations[conv_idx].last_message = Some(content);

        // Update UI
        if conv_idx == self.selected_conversation {
            self.messages.push(message);
        } else {
            self.conversations[conv_idx].unread_count += 1;
        }

        self.status = "New message received".to_string();

        // Ring terminal bell for notification (using crossterm for ratatui compatibility)
        let _ = execute!(std::io::stdout(), crossterm::style::Print("\x07"));
    }

    /// Handle key events
    #[allow(clippy::too_many_lines)] // Event handling has many cases
    async fn handle_key_event(&mut self, key: KeyEvent) -> AppResult<()> {
        // Handle popups first if visible
        if self.show_add_contact_popup {
            return self.handle_popup_key_event(key);
        }
        if self.show_my_id_popup {
            return self.handle_my_id_popup_key_event(key);
        }
        if self.show_add_upstream_popup {
            return self.handle_add_upstream_popup_key_event(key).await;
        }
        if self.show_upstreams_popup {
            return self.handle_upstreams_popup_key_event(key);
        }

        // Global shortcuts
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            if let KeyCode::Char('c' | 'q') = key.code {
                self.running = false;
                return Ok(());
            }
        }

        // Global shortcuts (Alt+key) - work from any focus
        // Note: Handle both lowercase and uppercase since some terminals send different cases
        if key.modifiers.contains(KeyModifiers::ALT) {
            match key.code {
                KeyCode::Char('a' | 'A') => {
                    // Alt+A: Add contact
                    self.show_add_contact_popup = true;
                    self.add_contact_popup.reset();
                    self.status =
                        "Add Contact (Tab: switch, Enter: confirm, Esc: cancel)".to_string();
                    return Ok(());
                }
                KeyCode::Char('i' | 'I') => {
                    // Alt+I: Show identity
                    self.show_my_id_popup = true;
                    return Ok(());
                }
                KeyCode::Char('u' | 'U') => {
                    // Alt+U: Add upstream
                    self.show_add_upstream_popup = true;
                    self.add_upstream_popup.reset();
                    self.status = "Add Upstream (Tab: switch, ←/→: type, Enter: add, Esc: cancel)"
                        .to_string();
                    return Ok(());
                }
                KeyCode::Char('v' | 'V') => {
                    // Alt+V: View upstreams
                    self.show_upstreams_popup = true;
                    return Ok(());
                }
                KeyCode::Char('h' | 'H') => {
                    // Alt+H: Show help
                    self.status = HELP_TEXT.to_string();
                    return Ok(());
                }
                _ => {}
            }
        }

        // Function key fallbacks for terminals where Alt doesn't work properly
        match key.code {
            KeyCode::F(2) => {
                // F2: Add contact (fallback for Alt+A)
                self.show_add_contact_popup = true;
                self.add_contact_popup.reset();
                self.status = "Add Contact (Tab: switch, Enter: confirm, Esc: cancel)".to_string();
                return Ok(());
            }
            KeyCode::F(3) => {
                // F3: Show identity (fallback for Alt+I)
                self.show_my_id_popup = true;
                return Ok(());
            }
            KeyCode::F(4) => {
                // F4: Add upstream (fallback for Alt+U)
                self.show_add_upstream_popup = true;
                self.add_upstream_popup.reset();
                self.status =
                    "Add Upstream (Tab: switch, ←/→: type, Enter: add, Esc: cancel)".to_string();
                return Ok(());
            }
            KeyCode::F(5) => {
                // F5: View upstreams (fallback for Alt+V)
                self.show_upstreams_popup = true;
                return Ok(());
            }
            _ => {}
        }

        match key.code {
            KeyCode::Esc => {
                if self.focus == Focus::Input {
                    self.focus = Focus::Messages;
                } else {
                    self.running = false;
                }
            }
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Conversations => Focus::Messages,
                    Focus::Messages => Focus::Input,
                    Focus::Input => Focus::Conversations,
                };
            }
            KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::Conversations => Focus::Input,
                    Focus::Messages => Focus::Conversations,
                    Focus::Input => Focus::Messages,
                };
            }
            _ => match self.focus {
                Focus::Conversations => self.handle_conversation_key(key).await?,
                Focus::Messages => self.handle_message_key(key),
                Focus::Input => self.handle_input_key(key).await?,
            },
        }

        Ok(())
    }

    /// Handle key events in conversation list
    #[allow(clippy::unused_async)] // Async for interface consistency with other handlers
    async fn handle_conversation_key(&mut self, key: KeyEvent) -> AppResult<()> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_conversation > 0 {
                    self.selected_conversation -= 1;
                    self.load_conversation_messages();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_conversation < self.conversations.len().saturating_sub(1) {
                    self.selected_conversation += 1;
                    self.load_conversation_messages();
                }
            }
            KeyCode::Enter => {
                self.focus = Focus::Input;
                // Clear unread count
                if let Some(conv) = self.conversations.get_mut(self.selected_conversation) {
                    conv.unread_count = 0;
                }
            }
            KeyCode::Char('h') => {
                // Show help (same as Alt+H)
                self.status = HELP_TEXT.to_string();
            }
            _ => {}
        }
        Ok(())
    }

    /// Handle key events in message view
    fn handle_message_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.message_scroll = self.message_scroll.saturating_add(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.message_scroll = self.message_scroll.saturating_sub(1);
            }
            KeyCode::PageUp => {
                self.message_scroll = self.message_scroll.saturating_add(10);
            }
            KeyCode::PageDown => {
                self.message_scroll = self.message_scroll.saturating_sub(10);
            }
            KeyCode::Enter | KeyCode::Char('i') => {
                self.focus = Focus::Input;
            }
            _ => {}
        }
    }

    /// Handle key events in input area
    async fn handle_input_key(&mut self, key: KeyEvent) -> AppResult<()> {
        if key.code == KeyCode::Enter {
            // Send message
            let text = self.input.lines().join("\n");
            if !text.trim().is_empty() {
                if let Some(conv) = self.conversations.get(self.selected_conversation) {
                    let public_id = conv.public_id;
                    match self.client.send_text(&public_id, &text).await {
                        Ok(_) => {
                            // Create message object
                            let message = Message {
                                from_me: true,
                                sender_name: "You".to_string(),
                                content: text,
                                timestamp: utc_time_now(),
                            };

                            // Cache the message
                            self.cache_message(public_id, message.clone());

                            // Add to visible messages
                            self.messages.push(message);

                            self.input = TextArea::default();
                            self.input.set_placeholder_text("Type a message...");
                            self.status = "Message sent!".to_string();
                        }
                        Err(e) => {
                            self.status = format!("Send failed: {e}");
                        }
                    }
                }
            }
        } else {
            // Forward to textarea
            let input = Input::from(key);
            self.input.input(input);
        }
        Ok(())
    }

    /// Cache a message with size limit (O(1) eviction using `VecDeque`)
    fn cache_message(&mut self, contact: PublicID, message: Message) {
        let cache = self.message_cache.entry(contact).or_default();
        cache.push_back(message);
        if cache.len() > MAX_CACHED_MESSAGES_PER_CONTACT {
            cache.pop_front();
        }
    }

    /// Load messages for the selected conversation
    fn load_conversation_messages(&mut self) {
        self.messages.clear();
        self.message_scroll = 0;

        // Load from in-memory cache
        if let Some(conv) = self.conversations.get(self.selected_conversation) {
            if let Some(cached) = self.message_cache.get(&conv.public_id) {
                self.messages = cached.iter().cloned().collect();
            }
        }
        // TODO: Also load from storage when retrieval API is implemented
    }

    /// Handle key events when add contact popup is visible
    fn handle_popup_key_event(&mut self, key: KeyEvent) -> AppResult<()> {
        match key.code {
            KeyCode::Esc => {
                // Cancel and close popup
                self.show_add_contact_popup = false;
                self.add_contact_popup.reset();
                self.status = "Add contact cancelled".to_string();
            }
            KeyCode::Tab | KeyCode::BackTab => {
                // Switch between fields
                self.add_contact_popup.toggle_field();
                let field_name = match self.add_contact_popup.focused_field {
                    AddContactField::PublicId => "Public ID",
                    AddContactField::Name => "Name",
                };
                self.status = format!("Focus: {field_name} field");
            }
            KeyCode::Enter => {
                // Attempt to add contact
                self.try_add_contact()?;
            }
            _ => {
                // Forward to appropriate textarea
                let input = Input::from(key);
                match self.add_contact_popup.focused_field {
                    AddContactField::PublicId => {
                        self.add_contact_popup.public_id_input.input(input);
                    }
                    AddContactField::Name => {
                        self.add_contact_popup.name_input.input(input);
                    }
                }
                // Clear error when user starts typing
                self.add_contact_popup.error = None;
            }
        }
        Ok(())
    }

    /// Attempt to add contact from popup data
    #[allow(clippy::unnecessary_wraps)] // Returns Result for consistency with other handlers
    fn try_add_contact(&mut self) -> AppResult<()> {
        // Validate public ID
        let public_id = match self.add_contact_popup.validate_public_id() {
            Ok(id) => id,
            Err(e) => {
                self.add_contact_popup.error = Some(e);
                return Ok(());
            }
        };

        // Get optional name
        let name = self.add_contact_popup.get_name();

        // Check if trying to add self
        if &public_id == self.client.public_id() {
            self.add_contact_popup.error = Some("Cannot add yourself as a contact".to_string());
            return Ok(());
        }

        // Check if contact already exists
        if self.client.get_contact(&public_id).is_ok() {
            self.add_contact_popup.error = Some("Contact already exists".to_string());
            return Ok(());
        }

        // Add contact via client API
        match self.client.add_contact(&public_id, name.as_deref()) {
            Ok(_) => {
                // Reuse get_or_create_conversation to add to UI (avoids duplication)
                let conv_idx = self.get_or_create_conversation(public_id);
                let display_name = self.conversations[conv_idx].name.clone();

                // Select the new contact and move to input
                self.selected_conversation = conv_idx;
                self.load_conversation_messages();
                self.focus = Focus::Input;

                // Close popup and show success
                self.show_add_contact_popup = false;
                self.add_contact_popup.reset();
                self.status = format!("Added contact: {display_name}");
            }
            Err(e) => {
                self.add_contact_popup.error = Some(format!("Failed to add contact: {e}"));
            }
        }

        Ok(())
    }

    /// Handle key events when my ID popup is visible
    #[allow(clippy::unnecessary_wraps)] // Returns Result for consistency with other handlers
    fn handle_my_id_popup_key_event(&mut self, key: KeyEvent) -> AppResult<()> {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q' | 'i') => {
                // Close popup
                self.show_my_id_popup = false;
            }
            _ => {}
        }
        Ok(())
    }

    /// Handle key events when view upstreams popup is visible
    #[allow(clippy::unnecessary_wraps)] // Returns Result for consistency with other handlers
    fn handle_upstreams_popup_key_event(&mut self, key: KeyEvent) -> AppResult<()> {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q' | 'v') => {
                // Close popup
                self.show_upstreams_popup = false;
            }
            _ => {}
        }
        Ok(())
    }

    /// Handle key events when add upstream popup is visible
    async fn handle_add_upstream_popup_key_event(&mut self, key: KeyEvent) -> AppResult<()> {
        match key.code {
            KeyCode::Esc => {
                // Cancel
                self.show_add_upstream_popup = false;
                self.add_upstream_popup.reset();
                self.status = HELP_HINT.to_string();
            }
            KeyCode::Tab => {
                // Toggle field focus
                self.add_upstream_popup.toggle_field();
            }
            KeyCode::Left | KeyCode::Right => {
                match self.add_upstream_popup.focused_field {
                    AddUpstreamField::Type => {
                        // Toggle transport type
                        self.add_upstream_popup.transport_type.toggle();
                        self.add_upstream_popup.error = None;
                        // Update placeholder based on type
                        let placeholder = match self.add_upstream_popup.transport_type {
                            UpstreamType::Http => "http://192.168.1.50:23003",
                            UpstreamType::Mqtt => "mqtt://192.168.1.50:1883",
                        };
                        self.add_upstream_popup
                            .url_input
                            .set_placeholder_text(placeholder);
                    }
                    AddUpstreamField::Tier => {
                        // Toggle delivery tier
                        self.add_upstream_popup.toggle_tier();
                        self.add_upstream_popup.error = None;
                    }
                    AddUpstreamField::Url => {
                        // Pass to text input
                        self.add_upstream_popup.url_input.input(Input::from(key));
                    }
                }
            }
            KeyCode::Enter => {
                // Try to add the upstream
                match self.add_upstream_popup.validate_url() {
                    Ok(url) => {
                        let result = self.add_upstream(&url).await;
                        match result {
                            Ok(()) => {
                                let transport_type = self.add_upstream_popup.transport_type;
                                self.show_add_upstream_popup = false;
                                self.add_upstream_popup.reset();
                                self.status = format!(
                                    "Added {} upstream: {}",
                                    match transport_type {
                                        UpstreamType::Http => "HTTP",
                                        UpstreamType::Mqtt => "MQTT",
                                    },
                                    url
                                );
                            }
                            Err(e) => {
                                self.add_upstream_popup.error = Some(e);
                            }
                        }
                    }
                    Err(e) => {
                        self.add_upstream_popup.error = Some(e);
                    }
                }
            }
            _ => {
                // Pass other keys to URL input when focused
                if self.add_upstream_popup.focused_field == AddUpstreamField::Url {
                    self.add_upstream_popup.url_input.input(Input::from(key));
                    self.add_upstream_popup.error = None;
                }
            }
        }
        Ok(())
    }

    /// Add an upstream transport at runtime
    async fn add_upstream(&mut self, url: &str) -> Result<(), String> {
        let transport_type = self.add_upstream_popup.transport_type;
        let tier = self.add_upstream_popup.tier;

        match transport_type {
            UpstreamType::Http => {
                // TODO: Add UI fields for username/password when adding ephemeral HTTP upstreams
                let config =
                    HttpTargetConfig::ephemeral(url).with_request_timeout(Duration::from_secs(10));
                let target = HttpTarget::new(config)
                    .map_err(|e| format!("Failed to create HTTP transport: {e}"))?;
                let id = target.id().clone();

                // Add to coordinator's HTTP pool
                self.coordinator.add_http_target(target);

                // Register in metadata for display
                self.registry.register_ephemeral(id, None, tier);

                info!(url = %url, "Added ephemeral HTTP upstream");
            }
            UpstreamType::Mqtt => {
                // TODO: Add UI fields for username/password when adding ephemeral MQTT upstreams
                let mqtt_config = MqttTargetConfig::new(url);
                let target = MqttTarget::connect(mqtt_config)
                    .await
                    .map_err(|e| format!("Failed to connect to MQTT broker: {e}"))?;

                let id = target.id().clone();

                // Add to MQTT pool via registry (which shares the pool with coordinator)
                self.registry
                    .mqtt_pool()
                    .expect("MQTT pool always initialized")
                    .add_target(target);

                // Register in metadata for display
                self.registry.register_ephemeral(id, None, tier);

                info!(url = %url, "Added ephemeral MQTT upstream");
            }
        }

        Ok(())
    }
}

/// Get current UTC time as HH:MM string (avoids chrono dependency)
fn utc_time_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    format!("{hours:02}:{mins:02}")
}

/// Format a display name from optional name and public ID
///
/// Uses the provided name if available, otherwise returns truncated hex of the public ID.
fn format_display_name(name: Option<&str>, public_id: &PublicID) -> String {
    name.map_or_else(
        || {
            let hex = hex::encode(public_id.to_bytes());
            format!("{}...", &hex[..8])
        },
        String::from,
    )
}
