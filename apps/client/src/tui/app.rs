//! Application state and main loop

use crate::config::AppConfig;
use crate::discovery;
use crate::tui::conversation_list::{Conversation, ConversationList};
use crate::tui::event::{Event, EventHandler};
use crate::tui::http_server;
use crate::tui::ui;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use ember_config::{ParsedHttpPeer, ParsedMqttPeer};
use ember_core::{AddContactOutcome, Client, ReceivedMessage};
use ember_discovery::DiscoveryBackend as _;
use ember_identity::{Identity, PublicID};
use ember_message::Content;
use ember_node_core::{
    EmbeddedNode, EmbeddedNodeHandle, NodeEvent, PersistentMailboxStore, PersistentStoreConfig,
};
use ember_outbox::{OutboxConfig, TieredDeliveryPhase, TransportRetryPolicy};
use ember_storage::{Storage, TrustLevel};
use ember_transport::http_target::{HttpTarget, HttpTargetConfig};
use ember_transport::pool::TransportPool;
use ember_transport::target::TargetKind;
use ember_transport::{
    CoordinatorConfig, CoordinatorHandle, DeliveryTier, MqttTarget, MqttTargetConfig, TargetId,
    TransportCoordinator, TransportEvent, TransportRegistry, TransportTarget,
};
use ratatui::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use tui_textarea::{Input, TextArea};
use zeroize::Zeroizing;

pub type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Length of a `PublicID` when encoded as hexadecimal (32 bytes = 64 hex chars)
const PUBLIC_ID_HEX_LENGTH: usize = 64;

/// Help text shown in status bar (Alt+H or initial startup)
const HELP_TEXT: &str =
    "Alt+A/F2: add | Alt+U/F4: upstream | Alt+V/F5: view | Alt+I/F3: identity | Alt+L: layout | Ctrl+Q: quit";

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
            Self::Http => Self::Mqtt,
            Self::Mqtt => Self::Http,
        };
    }

    /// Display label for status messages
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Mqtt => "MQTT",
        }
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

        // hex::decode of 64-char hex string always produces exactly 32 bytes
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "hex::decode of 64-char hex did not produce 32 bytes".to_string())?;

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

/// Delivery status for sent messages. Displayed as a visual indicator in the TUI.
/// This is a UI-only type — not persisted or sent over the wire.
#[derive(Debug, Clone, Default)]
pub enum DeliveryStatus {
    /// No status to display (received messages, history)
    #[default]
    None,
    /// Optimistic display — send task is in flight
    Sending,
    /// Delivery succeeded — carries human-readable phase description
    Sent(String),
    /// All delivery tiers failed — carries error description
    Failed(String),
}

/// Source of an incoming message (for logging/debugging).
#[derive(Debug, Clone, Copy)]
pub enum MessageSource {
    Coordinator,
    EmbeddedNode,
}

/// All events that can affect application state.
///
/// This is the single integration point for the TUI. Background tasks,
/// UI events, and spawned I/O all communicate through this type.
#[allow(dead_code)] // Variant fields (e.g. Resize dimensions, send_id) are API surface, not all are consumed yet
pub enum Action {
    /// Keyboard input
    Key(KeyEvent),
    /// Terminal resize
    Resize(u16, u16),

    /// A spawned send task completed
    SendComplete {
        /// Reserved for per-message delivery status correlation (not yet wired to UI)
        send_id: u64,
        result: Result<TieredDeliveryPhase, String>,
    },

    /// A background drainer processed an incoming message
    MessageProcessed {
        result: Result<ReceivedMessage, String>,
        source: MessageSource,
    },

    /// Periodic outbox tick completed
    OutboxTick(Result<(usize, usize, u64), String>),

    /// Embedded node error
    NodeError(String),

    /// MQTT upstream connection completed
    UpstreamAdded {
        url: String,
        transport_type: UpstreamType,
        result: Result<(), String>,
    },
}

/// A message in the conversation
#[derive(Debug, Clone)]
pub struct Message {
    pub from_me: bool,
    pub sender_name: String,
    pub content: String,
    pub timestamp: String,
    pub status: DeliveryStatus,
    /// Monotonic ID for correlating with background send results. None for received messages.
    pub send_id: Option<u64>,
}

/// Application state
#[allow(clippy::struct_excessive_bools)] // UI state naturally has many boolean flags
pub struct App<'a> {
    /// Is the application running?
    pub running: bool,
    /// Current focus
    pub focus: Focus,
    /// Conversation list component (selection, display mode, sorting)
    pub conversation_list: ConversationList,
    /// Messages in current conversation
    pub messages: Vec<Message>,
    /// Message scroll offset
    pub message_scroll: u16,
    /// Input text area
    pub input: TextArea<'a>,
    /// Status message
    pub status: String,
    /// The messenger client (uses `TransportCoordinator` for sending via HTTP and/or MQTT).
    /// Arc-wrapped so the outbox tick can run in a background task without blocking the UI.
    client: Arc<Client<TransportCoordinator>>,
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
    /// In-memory message cache per contact
    message_cache: HashMap<PublicID, VecDeque<Message>>,
    /// Tracks contacts whose message history has been loaded from storage
    history_loaded: std::collections::HashSet<PublicID>,
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
    pub registry: Arc<TransportRegistry>,
    /// Outbox tick interval from config
    outbox_tick_interval: Duration,
    /// LAN discovery subsystem state (mDNS backend, cancel token, controller task)
    discovery: Option<discovery::DiscoveryState>,
    /// Shared counter of currently discovered LAN peers (updated by controller).
    pub lan_peer_count: Arc<AtomicUsize>,
    /// Whether LAN discovery is enabled in config (for status bar display).
    pub lan_discovery_enabled: bool,
    /// Action sender — cloned into background tasks for result delivery.
    action_tx: mpsc::UnboundedSender<Action>,
    /// Action receiver — drained in the main loop.
    action_rx: mpsc::UnboundedReceiver<Action>,
    /// Monotonic counter for correlating send results to optimistic messages.
    next_send_id: u64,
}

impl App<'_> {
    /// Create a new app instance
    ///
    /// # Arguments
    /// * `config` - Application configuration
    /// * `identity` - The loaded/decrypted identity
    #[expect(
        clippy::too_many_lines,
        reason = "startup wiring spans storage, transports, discovery, and outbox setup"
    )]
    pub async fn new(config: AppConfig, identity: Identity) -> AppResult<Self> {
        // Ensure data directory exists
        fs::create_dir_all(&config.data_dir)?;

        // Create storage
        let db_path = config.data_dir.join("messages.db");
        let db_path_str = db_path
            .to_str()
            .ok_or("Database path contains invalid UTF-8 characters")?;
        let storage = Arc::new(Storage::open(db_path_str)?);

        // Parse and validate all HTTP peers
        let parsed_http_peers: Vec<ParsedHttpPeer> = config
            .peers
            .http
            .iter()
            .map(|peer| ParsedHttpPeer::try_from(peer.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse HTTP peer configuration: {e}"))?;

        let http_pool = build_http_pool(&parsed_http_peers)?;

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
        let (embedded_node_handle, embedded_node_task, node_event_rx) =
            setup_embedded_node(&config, &identity, &identity_bytes).await?;

        // Build transport coordinator with 2s poll interval
        let coordinator_config = CoordinatorConfig {
            poll_interval: Duration::from_secs(2),
            ..CoordinatorConfig::default()
        };
        let mut coordinator = TransportCoordinator::new(coordinator_config);

        // Add HTTP pool to coordinator.
        // Always create a pool so runtime HTTP upstream adds and subscribe() work
        // even when no HTTP nodes are configured at startup.
        if let Some(http) = http_pool {
            coordinator.set_http_pool_arc(http);
        } else {
            coordinator.set_http_pool(TransportPool::new());
        }

        // Create MQTT pool and connect configured brokers in parallel.
        let mqtt_pool_arc = build_mqtt_pool(&parsed_mqtt_peers).await;
        coordinator.set_mqtt_pool_arc(mqtt_pool_arc.clone());

        // Note: Embedded node is intentionally NOT added to the coordinator.
        // The embedded node stores messages locally, but recipients fetch via HTTP server
        // (started above if http_bind is configured). Direct P2P messaging uses the
        // direct_peers config to send TO contacts, and HTTP server to receive FROM them.

        // Add direct peers as ephemeral HTTP targets
        // TODO: Avoid creating a polling subscription when pool has only SEND-capable
        // targets (no FETCH targets) — currently produces harmless "no fetchable targets" logs

        let direct_peer_ids = add_direct_peers(&config, &coordinator);
        validate_transports(&config, &coordinator)?;

        // Subscribe to incoming messages before wrapping in Arc
        let our_routing_key = identity.public_id().routing_key();
        let (coordinator_events, coordinator_handle) = coordinator.subscribe(our_routing_key);

        let coordinator = Arc::new(coordinator);

        // Create transport registry as read-only view of coordinator pools
        let registry = Arc::new(TransportRegistry::with_coordinator(&coordinator));

        register_configured_targets(
            &registry,
            &parsed_http_peers,
            &parsed_mqtt_peers,
            direct_peer_ids,
        );

        // --- LAN Discovery ---
        let lan_discovery_enabled = config.lan_discovery.enabled;
        let (discovery_state, lan_peer_count, discovery_status_msg) = init_discovery(
            &config,
            &identity,
            Arc::clone(&storage),
            coordinator.clone(),
            registry.clone(),
        )
        .await;

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
        let mut client_inner = Client::with_config(
            identity,
            coordinator.clone(),
            Arc::clone(&storage),
            outbox_config,
        );

        // Set HTTP transport retry policy
        client_inner.set_transport_policy("http:", retry_policy);
        let client = Arc::new(client_inner);

        // Store tick interval from config
        let outbox_tick_interval = Duration::from_secs(config.outbox.tick_interval_secs);

        // Create action channel for background task result delivery
        let (action_tx, action_rx) = mpsc::unbounded_channel();

        // Create input area
        let mut input = TextArea::default();
        input.set_placeholder_text("Type a message...");
        input.set_cursor_line_style(Style::default());

        let mut app = Self {
            running: true,
            focus: Focus::Conversations,
            conversation_list: ConversationList::new(config.ui.conversation_display),
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
            history_loaded: std::collections::HashSet::new(),
            show_add_contact_popup: false,
            add_contact_popup: AddContactPopup::default(),
            show_my_id_popup: false,
            show_add_upstream_popup: false,
            add_upstream_popup: AddUpstreamPopup::default(),
            show_upstreams_popup: false,
            registry,
            outbox_tick_interval,
            discovery: discovery_state,
            lan_peer_count,
            lan_discovery_enabled,
            action_tx,
            action_rx,
            next_send_id: 0,
        };

        // Surface mDNS init failure in TUI status bar (M14)
        if let Some(msg) = discovery_status_msg {
            app.status = msg;
        }

        // Load contacts and seed the initially selected conversation
        app.load_contacts()?;
        app.load_conversation_messages();

        Ok(app)
    }

    /// Spawn all background tasks that feed results into the action channel.
    fn spawn_background_tasks(&mut self) {
        self.spawn_coordinator_drainer();
        self.spawn_node_drainer();
        self.spawn_outbox_tick();
    }

    /// Spawn the coordinator event drainer task.
    fn spawn_coordinator_drainer(&mut self) {
        let client = self.client.clone();
        let tx = self.action_tx.clone();
        let mut coordinator_events =
            std::mem::replace(&mut self.coordinator_events, mpsc::unbounded_channel().1);
        tokio::spawn(async move {
            while let Some(event) = coordinator_events.recv().await {
                if let TransportEvent::Message(envelope) = event {
                    if process_and_notify(&client, &tx, &envelope, MessageSource::Coordinator)
                        .is_err()
                    {
                        break;
                    }
                }
            }
        });
    }

    /// Spawn the embedded node event drainer task.
    fn spawn_node_drainer(&mut self) {
        let Some(mut node_rx) = self.node_event_rx.take() else {
            return;
        };
        let client = self.client.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            while let Some(event) = node_rx.recv().await {
                match event {
                    NodeEvent::MessageReceived(envelope) => {
                        debug!("Received message from embedded node");
                        if process_and_notify(&client, &tx, &envelope, MessageSource::EmbeddedNode)
                            .is_err()
                        {
                            break;
                        }
                    }
                    NodeEvent::Error(e) => {
                        tracing::error!("Embedded node error: {}", e);
                        if tx.send(Action::NodeError(e)).is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }

    /// Spawn the periodic outbox tick task.
    fn spawn_outbox_tick(&self) {
        // --- Outbox tick ---
        let outbox_client = self.client.clone();
        let outbox_interval = self.outbox_tick_interval;
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(outbox_interval);
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                let result = outbox_client.tiered_outbox_tick().await;
                if tx
                    .send(Action::OutboxTick(result.map_err(|e| e.to_string())))
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    /// Load contacts from storage, including the most recent message preview
    fn load_contacts(&mut self) -> AppResult<()> {
        let contacts = self.client.list_contacts()?;
        self.contacts_by_id.clear();

        // Collect contact IDs for batch last-message lookup
        let contact_ids: Vec<i64> = contacts.iter().map(|c| c.id).collect();
        let last_messages = self
            .client
            .get_last_message_per_contact(&contact_ids)
            .unwrap_or_else(|e| {
                tracing::warn!("Failed to load last message previews: {e}");
                HashMap::new()
            });

        let mut convs = Vec::with_capacity(contacts.len());
        for contact in contacts {
            let name = format_display_name(contact.name.as_deref(), &contact.public_id);

            self.contacts_by_id.insert(contact.public_id, name.clone());

            let last_message_preview = last_messages.get(&contact.id);
            let last_message = last_message_preview.map(|p| p.body.clone());
            let last_message_time = last_message_preview.map(|p| p.created_at);

            convs.push(Conversation {
                id: contact.id,
                public_id: contact.public_id,
                name,
                last_message,
                last_message_time,
                unread_count: 0,
                trust_level: contact.trust_level,
            });
        }

        self.conversation_list.set_conversations(convs);
        self.conversation_list.sort_by_recent();

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

    /// Get the current count of discovered LAN peers.
    pub fn lan_peer_count(&self) -> usize {
        self.lan_peer_count.load(Ordering::Relaxed)
    }

    /// Run the application main loop
    pub async fn run(&mut self, terminal: &mut Terminal<impl Backend>) -> AppResult<()> {
        let mut event_handler = EventHandler::new();
        let mut needs_render = true;
        self.spawn_background_tasks();

        while self.running {
            if needs_render {
                terminal.draw(|frame| ui::render(frame, self))?;
                needs_render = false;
            }

            tokio::select! {
                event = event_handler.next() => {
                    let action = match event? {
                        Event::Key(k) => Action::Key(k),
                        Event::Resize(w, h) => Action::Resize(w, h),
                    };
                    needs_render |= self.apply_action(action);
                }
                Some(action) = self.action_rx.recv() => {
                    needs_render |= self.apply_action(action);
                }
            }

            // Drain any additional queued actions (stop if shutdown requested)
            while self.running {
                match self.action_rx.try_recv() {
                    Ok(action) => needs_render |= self.apply_action(action),
                    Err(_) => break,
                }
            }
        }

        self.shutdown_discovery().await;
        self.shutdown_embedded_node().await;

        Ok(())
    }

    /// Apply a single action and report whether it should trigger a redraw.
    fn apply_action(&mut self, action: Action) -> bool {
        let needs_render = action_requires_render(&action);
        self.update(action);
        needs_render
    }

    /// Process a single action, updating application state.
    ///
    /// This method is intentionally synchronous — all I/O happens in
    /// spawned tasks that send results back as [`Action`] variants.
    fn update(&mut self, action: Action) {
        match action {
            Action::Key(key_event) => {
                if let Err(e) = self.handle_key_event(key_event) {
                    self.status = format!("Error: {e}");
                }
            }
            Action::Resize(_, _) => {}
            Action::SendComplete { send_id, result } => {
                self.handle_send_complete(send_id, &result);
            }
            Action::MessageProcessed { result, source } => {
                self.handle_message_processed(result, source);
            }
            Action::OutboxTick(result) => {
                handle_outbox_tick(result);
            }
            Action::NodeError(e) => {
                self.status = format!("Node error: {e}");
            }
            Action::UpstreamAdded {
                url,
                transport_type,
                result,
            } => {
                self.handle_upstream_added(&url, transport_type, result);
            }
        }
    }

    /// Handle a completed send operation by updating delivery status in messages and cache.
    fn handle_send_complete(&mut self, send_id: u64, result: &Result<TieredDeliveryPhase, String>) {
        let status = match result {
            Ok(phase) => DeliveryStatus::Sent(format_delivery_status(phase)),
            Err(e) => DeliveryStatus::Failed(e.clone()),
        };

        self.status = match &status {
            DeliveryStatus::Sent(s) => s.clone(),
            DeliveryStatus::Failed(e) => format!("Send failed: {e}"),
            DeliveryStatus::None | DeliveryStatus::Sending => {
                unreachable!("SendComplete always produces Sent or Failed")
            }
        };

        // Update the optimistic message in visible messages
        for msg in &mut self.messages {
            if msg.send_id == Some(send_id) {
                msg.status = status.clone();
                break;
            }
        }

        // Also update in cache (so switching conversations preserves status)
        for cache in self.message_cache.values_mut() {
            for msg in cache.iter_mut() {
                if msg.send_id == Some(send_id) {
                    msg.status = status;
                    return;
                }
            }
        }
    }

    /// Handle a processed incoming message or processing error.
    fn handle_message_processed(
        &mut self,
        result: Result<ReceivedMessage, String>,
        source: MessageSource,
    ) {
        match result {
            Ok(msg) => {
                let content = match &msg.content {
                    Content::Text(t) => t.body.clone(),
                    Content::Receipt(r) => format!("[Receipt: {:?}]", r.kind),
                    _ => "[Unknown content]".to_string(),
                };
                self.handle_incoming_message(msg.from, content);
            }
            Err(e) => {
                let label = match source {
                    MessageSource::Coordinator => "coordinator",
                    MessageSource::EmbeddedNode => "embedded node",
                };
                warn!("Failed to process {} message: {}", label, e);
                self.status = format!("Message decrypt failed: {e}");
            }
        }
    }

    /// Handle the result of an upstream add operation.
    fn handle_upstream_added(
        &mut self,
        url: &str,
        transport_type: UpstreamType,
        result: Result<(), String>,
    ) {
        match result {
            Ok(()) => {
                self.show_add_upstream_popup = false;
                self.add_upstream_popup.reset();
                self.status = format!("Added {} upstream: {url}", transport_type.as_str());
            }
            Err(e) => {
                self.add_upstream_popup.error = Some(e);
            }
        }
    }

    /// Shutdown the discovery subsystem gracefully.
    ///
    /// Cancels the discovery controller, awaits its task, then shuts down
    /// the mDNS backend to release network resources.
    async fn shutdown_discovery(&mut self) {
        let Some(state) = self.discovery.take() else {
            return;
        };
        shutdown_discovery_state(state).await;
    }

    /// Shutdown the embedded node gracefully.
    ///
    /// First signals the node to shutdown via the handle, then awaits
    /// the background task to ensure it has fully completed.
    async fn shutdown_embedded_node(&mut self) {
        signal_node_shutdown(self.embedded_node_handle.as_ref()).await;
        await_optional_task(self.embedded_node_task.take(), "embedded node").await;
    }

    /// Get or create a conversation for a contact, returns the index
    fn get_or_create_conversation(&mut self, public_id: PublicID) -> usize {
        // Get contact info from storage (ember-core auto-adds on message receive)
        // Single call to avoid duplicate lookups
        let (contact_id, display_name, trust_level) = match self.client.get_contact(&public_id) {
            Ok(contact) => {
                let name = format_display_name(contact.name.as_deref(), &public_id);
                (contact.id, name, contact.trust_level)
            }
            Err(_) => (
                0,
                format_display_name(None, &public_id),
                TrustLevel::Stranger,
            ),
        };

        self.contacts_by_id.insert(public_id, display_name.clone());
        if let Some(idx) = self.conversation_list.find_by_public_id(&public_id) {
            if let Some(conversation) = self.conversation_list.get_mut(idx) {
                conversation.id = contact_id;
                conversation.name = display_name;
            }
            return idx;
        }

        self.conversation_list.push(Conversation {
            id: contact_id,
            public_id,
            name: display_name,
            last_message: None,
            last_message_time: None,
            unread_count: 0,
            trust_level,
        })
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
            status: DeliveryStatus::None,
            send_id: None,
        };

        // Cache message
        self.cache_message(from, message.clone());

        // Update conversation
        let is_selected = self.conversation_list.selected_index() == Some(conv_idx);
        if let Some(conv) = self.conversation_list.get_mut(conv_idx) {
            conv.last_message = Some(content);
            conv.last_message_time = Some(now_secs());

            // Update UI
            if is_selected {
                self.messages.push(message);
            } else {
                conv.unread_count += 1;
            }
        }

        self.conversation_list.sort_by_recent();

        self.status = "New message received".to_string();

        // Ring terminal bell for notification (using crossterm for ratatui compatibility)
        let _ = execute!(std::io::stdout(), crossterm::style::Print("\x07"));
    }

    /// Handle key events
    #[expect(
        clippy::too_many_lines,
        reason = "top-level key routing is easier to audit as a single dispatch table"
    )]
    fn handle_key_event(&mut self, key: KeyEvent) -> AppResult<()> {
        // Handle popups first if visible
        if self.show_add_contact_popup {
            return self.handle_popup_key_event(key);
        }
        if self.show_my_id_popup {
            return self.handle_my_id_popup_key_event(key);
        }
        if self.show_add_upstream_popup {
            return self.handle_add_upstream_popup_key_event(key);
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
            #[allow(clippy::wildcard_enum_match_arm)] // KeyCode has 27+ variants
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
                KeyCode::Char('l' | 'L') => {
                    // Alt+L: Toggle conversation list layout
                    self.conversation_list.toggle_display_mode();
                    let mode = match self.conversation_list.display_mode() {
                        crate::config::DisplayMode::TwoLine => "two-line",
                        crate::config::DisplayMode::Compact => "compact",
                    };
                    self.status = format!("Display mode: {mode}");
                    return Ok(());
                }
                _ => {}
            }
        }

        // Function key fallbacks for terminals where Alt doesn't work properly
        #[allow(clippy::wildcard_enum_match_arm)] // KeyCode has 27+ variants
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

        #[allow(clippy::wildcard_enum_match_arm)] // KeyCode has 27+ variants
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
                Focus::Conversations => self.handle_conversation_key(key)?,
                Focus::Messages => self.handle_message_key(key),
                Focus::Input => self.handle_input_key(key)?,
            },
        }

        Ok(())
    }

    /// Handle key events in conversation list
    #[allow(clippy::unnecessary_wraps)] // Returns Result for consistency with other handlers
    fn handle_conversation_key(&mut self, key: KeyEvent) -> AppResult<()> {
        #[allow(clippy::wildcard_enum_match_arm)] // KeyCode has 27+ variants
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.conversation_list.select_previous();
                self.load_conversation_messages();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.conversation_list.select_next();
                self.load_conversation_messages();
            }
            KeyCode::Enter => {
                self.focus = Focus::Input;
                // Clear unread count
                if let Some(conv) = self.conversation_list.selected_mut() {
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
        #[allow(clippy::wildcard_enum_match_arm)] // KeyCode has 27+ variants
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
    #[allow(clippy::unnecessary_wraps)] // Returns Result for consistency with other handlers
    fn handle_input_key(&mut self, key: KeyEvent) -> AppResult<()> {
        if key.code == KeyCode::Enter {
            let text = self.input.lines().join("\n");
            if !text.trim().is_empty() {
                if let Some(conv) = self.conversation_list.selected() {
                    let public_id = conv.public_id;
                    let content = Content::Text(ember_message::TextContent { body: text.clone() });

                    match self.client.prepare_message(&public_id, content, false) {
                        Ok(prepared) => {
                            let send_id = self.next_send_id;
                            self.next_send_id += 1;

                            let message = Message {
                                from_me: true,
                                sender_name: "You".to_string(),
                                content: text.clone(),
                                timestamp: utc_time_now(),
                                status: DeliveryStatus::Sending,
                                send_id: Some(send_id),
                            };

                            self.cache_message(public_id, message.clone());
                            self.messages.push(message);
                            self.input = TextArea::default();
                            self.input.set_placeholder_text("Type a message...");
                            self.status = "Sending...".to_string();

                            // Update conversation preview and timestamp
                            if let Some(sel) = self.conversation_list.selected_mut() {
                                sel.last_message = Some(text);
                                sel.last_message_time = Some(now_secs());
                            }
                            self.conversation_list.sort_by_recent();

                            let client = self.client.clone();
                            let tx = self.action_tx.clone();
                            tokio::spawn(async move {
                                let result = client.submit_prepared_tiered(&prepared).await;
                                let _ = tx.send(Action::SendComplete {
                                    send_id,
                                    result: result.map_err(|e| e.to_string()),
                                });
                            });
                        }
                        Err(e) => {
                            self.status = format!("Send failed: {e}");
                        }
                    }
                }
            }
        } else {
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

    /// Load messages for the selected conversation.
    ///
    /// On first load (empty cache), seeds from persistent storage.
    /// Subsequent loads use the in-memory cache which includes new
    /// messages received/sent during this session.
    fn load_conversation_messages(&mut self) {
        self.messages.clear();
        self.message_scroll = 0;

        if let Some(conv) = self.conversation_list.selected() {
            let public_id = conv.public_id;
            let contact_id = conv.id;

            // Seed cache from storage if history hasn't been loaded yet.
            // Uses a separate flag so that in-session messages (which create
            // cache entries via cache_message()) don't prevent loading history.
            if self.history_loaded.insert(public_id) {
                match self.client.get_messages(contact_id, 50, None) {
                    Ok(stored) => {
                        let cache = self.message_cache.entry(public_id).or_default();
                        let sender_name = self
                            .contacts_by_id
                            .get(&public_id)
                            .cloned()
                            .unwrap_or_default();
                        // Prepend stored messages before any in-session messages
                        let existing = std::mem::take(cache);
                        for msg in &stored {
                            if msg.content_type != "text" {
                                continue;
                            }
                            let content = msg.body.clone().unwrap_or_default();
                            let is_sent = msg.direction == ember_storage::MessageDirection::Sent;
                            cache.push_back(Message {
                                from_me: is_sent,
                                sender_name: if is_sent {
                                    "You".to_string()
                                } else {
                                    sender_name.clone()
                                },
                                content,
                                timestamp: format_unix_timestamp(msg.created_at),
                                status: DeliveryStatus::None,
                                send_id: None,
                            });
                        }
                        // Re-append any in-session messages after the stored history
                        cache.extend(existing);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load message history for contact {contact_id}: {e}"
                        );
                    }
                }
            }

            if let Some(cached) = self.message_cache.get(&public_id) {
                self.messages = cached.iter().cloned().collect();
            }
        }
    }

    /// Handle key events when add contact popup is visible
    fn handle_popup_key_event(&mut self, key: KeyEvent) -> AppResult<()> {
        #[allow(clippy::wildcard_enum_match_arm)] // KeyCode has 27+ variants
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

        // Add contact via client API
        match self.client.add_contact(&public_id, name.as_deref()) {
            Ok(outcome) => {
                let (contact, status_prefix, notify_discovery) = match outcome {
                    AddContactOutcome::Created(contact) => (contact, "Added contact", true),
                    AddContactOutcome::Promoted(contact) => (contact, "Promoted contact", true),
                    AddContactOutcome::AlreadyPresent(contact) => {
                        (contact, "Contact already present", false)
                    }
                };

                // Notify the discovery controller about the new contact (M12)
                if notify_discovery {
                    if let Some(ref state) = self.discovery {
                        if let Some(ref tx) = state.contact_tx {
                            let rk: [u8; 16] = *contact.routing_key.as_bytes();
                            if let Err(e) = tx.send((contact.public_id, rk)) {
                                debug!("Discovery contact channel closed: {e}");
                            }
                        }
                    }
                }

                let conv_idx = self.get_or_create_conversation(contact.public_id);
                let display_name = self
                    .conversation_list
                    .get(conv_idx)
                    .map(|c| c.name.clone())
                    .unwrap_or_default();

                // Select the new or updated contact and move to input
                self.conversation_list.select(conv_idx);
                self.load_conversation_messages();
                self.focus = Focus::Input;

                // Close popup and show success
                self.show_add_contact_popup = false;
                self.add_contact_popup.reset();
                self.status = format!("{status_prefix}: {display_name}");
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
        #[allow(clippy::wildcard_enum_match_arm)] // KeyCode has 27+ variants
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
        #[allow(clippy::wildcard_enum_match_arm)] // KeyCode has 27+ variants
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
    #[allow(clippy::unnecessary_wraps)] // Returns Result for consistency with other handlers
    fn handle_add_upstream_popup_key_event(&mut self, key: KeyEvent) -> AppResult<()> {
        #[allow(clippy::wildcard_enum_match_arm)] // KeyCode has 27+ variants
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
                        let transport_type = self.add_upstream_popup.transport_type;
                        match transport_type {
                            UpstreamType::Http => match self.add_upstream_http(&url) {
                                Ok(()) => {
                                    self.show_add_upstream_popup = false;
                                    self.add_upstream_popup.reset();
                                    self.status = format!("Added HTTP upstream: {url}");
                                }
                                Err(e) => {
                                    self.add_upstream_popup.error = Some(e);
                                }
                            },
                            UpstreamType::Mqtt => {
                                // MQTT connect is async — spawn and send result back
                                let tier = self.add_upstream_popup.tier;
                                let registry = self.registry.clone();
                                let tx = self.action_tx.clone();
                                self.status = "Connecting to MQTT...".to_string();
                                tokio::spawn(async move {
                                    let result = connect_mqtt_upstream(&url, tier, &registry).await;
                                    let _ = tx.send(Action::UpstreamAdded {
                                        url,
                                        transport_type: UpstreamType::Mqtt,
                                        result,
                                    });
                                });
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

    /// Add an HTTP upstream synchronously (no network I/O required).
    fn add_upstream_http(&self, url: &str) -> Result<(), String> {
        let tier = self.add_upstream_popup.tier;
        // TODO: Add UI fields for username/password when adding ephemeral HTTP upstreams
        // TODO: Create stable (FETCH + QUORUM_CREDIT) targets when user selects Quorum tier,
        // not always ephemeral (SEND-only) — currently tier selection is cosmetic
        let config = HttpTargetConfig::ephemeral(url).with_request_timeout(Duration::from_secs(10));
        let target =
            HttpTarget::new(config).map_err(|e| format!("Failed to create HTTP transport: {e}"))?;
        let id = target.id().clone();
        self.coordinator.add_http_target(target);
        self.registry.register_ephemeral(id, None, tier);
        info!(url = %url, "Added ephemeral HTTP upstream");
        Ok(())
    }
}

const fn action_requires_render(action: &Action) -> bool {
    match action {
        Action::OutboxTick(_) => false,
        Action::Key(_)
        | Action::Resize(_, _)
        | Action::SendComplete { .. }
        | Action::MessageProcessed { .. }
        | Action::NodeError(_)
        | Action::UpstreamAdded { .. } => true,
    }
}

/// Handle the result of an outbox tick (logging only, no UI state change).
fn handle_outbox_tick(result: Result<(usize, usize, u64), String>) {
    match result {
        Err(e) => warn!("Outbox tick failed: {e}"),
        Ok(counts) => log_outbox_tick_counts(counts),
    }
}

/// Log outbox tick counts (no-op when all zero).
fn log_outbox_tick_counts((retried, maintenance, expired): (usize, usize, u64)) {
    if retried == 0 && maintenance == 0 && expired == 0 {
        return;
    }
    info!("Outbox tick completed: retried={retried} maintenance={maintenance} expired={expired}");
}

/// Signal the embedded node to shutdown via its handle.
async fn signal_node_shutdown(handle: Option<&EmbeddedNodeHandle>) {
    let Some(handle) = handle else { return };
    debug!("Shutting down embedded node...");
    let result = handle.shutdown().await;
    log_node_shutdown_result(result);
}

/// Log the embedded node shutdown result.
fn log_node_shutdown_result(result: Result<(), ember_node_core::NodeError>) {
    if let Err(e) = result {
        warn!("Failed to signal embedded node shutdown: {e}");
    }
}

/// Shutdown a discovery state: cancel controller, await task, shutdown backend.
async fn shutdown_discovery_state(state: discovery::DiscoveryState) {
    debug!("Cancelling discovery controller...");
    state.cancel.cancel();
    await_optional_task(state.controller_task, "discovery controller").await;
    shutdown_mdns_backend(state.backend).await;
}

/// Await an optional task handle, logging panics.
async fn await_optional_task(task: Option<tokio::task::JoinHandle<()>>, label: &str) {
    let Some(handle) = task else { return };
    debug!(task = label, "Waiting for task to stop");
    log_task_join_result(handle.await, label);
}

/// Log the result of joining a task handle.
fn log_task_join_result(result: Result<(), tokio::task::JoinError>, label: &str) {
    if let Err(e) = result {
        log_task_panic(label, &e);
    } else {
        log_task_stopped(label);
    }
}

fn log_task_panic(label: &str, e: &tokio::task::JoinError) {
    warn!(task = label, error = %e, "Task panicked during shutdown");
}

fn log_task_stopped(label: &str) {
    info!(task = label, "Task shutdown complete");
}

/// Shutdown the mDNS backend, logging any errors.
async fn shutdown_mdns_backend(backend: Arc<ember_discovery::mdns_sd::MdnsSdBackend>) {
    debug!("Shutting down mDNS backend");
    log_mdns_shutdown_result(backend.shutdown().await);
}

/// Log the result of mDNS backend shutdown.
fn log_mdns_shutdown_result(result: Result<(), ember_discovery::DiscoveryError>) {
    if let Err(e) = result {
        log_mdns_shutdown_error(&e);
    } else {
        log_mdns_shutdown_ok();
    }
}

fn log_mdns_shutdown_error(e: &ember_discovery::DiscoveryError) {
    warn!(error = %e, "Failed to shutdown mDNS backend");
}

fn log_mdns_shutdown_ok() {
    info!("mDNS backend shutdown complete");
}

/// Add direct peers as ephemeral HTTP targets, returning their IDs for registry.
fn add_direct_peers(
    config: &crate::config::AppConfig,
    coordinator: &TransportCoordinator,
) -> Vec<(TargetId, Option<String>)> {
    config
        .direct_peers
        .iter()
        .filter_map(|peer| add_single_direct_peer(peer, coordinator))
        .collect()
}

/// Add a single direct peer, returning its ID and name on success.
///
/// Delegates construction to [`build_direct_peer_target`] and registers
/// the result with the coordinator.
fn add_single_direct_peer(
    peer: &crate::config::DirectPeerConfig,
    coordinator: &TransportCoordinator,
) -> Option<(TargetId, Option<String>)> {
    let target = build_direct_peer_target(peer)?;

    log_direct_peer_added(&peer.address, peer.name.as_deref());
    let id = (target.id().clone(), peer.name.clone());
    coordinator.add_http_target(target);
    Some(id)
}

/// Build an [`HttpTarget`] from a [`DirectPeerConfig`], parsing and wiring
/// the optional `public_id` into `node_pubkey`.
///
/// Returns `None` (with a warning) if `public_id` is present but invalid,
/// or if the target cannot be constructed.
fn build_direct_peer_target(peer: &crate::config::DirectPeerConfig) -> Option<HttpTarget> {
    let Ok(node_pubkey) = parse_direct_peer_pubkey(peer) else {
        return None;
    };

    let target_config = HttpTargetConfig::new(&peer.address, TargetKind::Ephemeral)
        .with_label(peer.name.as_deref().unwrap_or(&peer.address))
        .with_node_pubkey_opt(node_pubkey);

    match HttpTarget::new(target_config) {
        Ok(t) => Some(t),
        Err(e) => {
            warn!("Failed to add direct peer {}: {e}", peer.address);
            None
        }
    }
}

/// Parse the optional `public_id` field from a [`DirectPeerConfig`] into a
/// [`PublicID`].
///
/// Returns `Ok(None)` when no `public_id` is configured, `Ok(Some(pk))` on
/// valid parse, or `Err(())` (with a warning logged) when parsing fails.
fn parse_direct_peer_pubkey(
    peer: &crate::config::DirectPeerConfig,
) -> Result<Option<PublicID>, ()> {
    let Some(id_str) = peer.public_id.as_deref() else {
        return Ok(None);
    };

    match ember_config::parse_node_pubkey(id_str) {
        Ok(pk) => Ok(Some(pk)),
        Err(e) => {
            // TODO: emit UI notification event once app-level event bus exists
            warn!(
                "Skipping direct peer {}: invalid public_id: {e}",
                peer.address
            );
            Err(())
        }
    }
}

/// Log successful direct peer addition.
fn log_direct_peer_added(address: &str, name: Option<&str>) {
    info!(
        "Added direct peer: {} ({})",
        address,
        name.unwrap_or("unnamed")
    );
}

/// Validate that at least one transport is configured (or discovery can provide one).
fn validate_transports(
    config: &crate::config::AppConfig,
    coordinator: &TransportCoordinator,
) -> AppResult<()> {
    if coordinator.has_transports() {
        return Ok(());
    }
    if config.lan_discovery.enabled && config.lan_discovery.auto_direct_known_contacts {
        warn!("No transports configured yet — LAN discovery may add peers at runtime");
        return Ok(());
    }
    Err("No transports configured. Add HTTP nodes and/or MQTT brokers.".into())
}

/// Convert a `ConfiguredTier` to `DeliveryTier`.
const fn convert_tier(tier: ember_config::ConfiguredTier) -> DeliveryTier {
    match tier {
        ember_config::ConfiguredTier::Quorum => DeliveryTier::Quorum,
        ember_config::ConfiguredTier::BestEffort => DeliveryTier::BestEffort,
    }
}

/// Register all configured transports in the registry for UI display.
fn register_configured_targets(
    registry: &TransportRegistry,
    http_peers: &[ParsedHttpPeer],
    mqtt_peers: &[ParsedMqttPeer],
    direct_peers: Vec<(TargetId, Option<String>)>,
) {
    for peer in http_peers {
        registry.register_stable(
            TargetId::http(&peer.url),
            peer.common.label.clone(),
            convert_tier(peer.common.tier),
        );
    }
    for peer in mqtt_peers {
        registry.register_stable(
            TargetId::mqtt(&peer.url),
            peer.common.label.clone(),
            convert_tier(peer.common.tier),
        );
    }
    for (id, label) in direct_peers {
        registry.register_stable(id, label, DeliveryTier::Direct);
    }
}

/// Initialize the LAN discovery subsystem, returning state + peer count + optional status message.
async fn init_discovery(
    config: &crate::config::AppConfig,
    identity: &Identity,
    storage: Arc<Storage>,
    coordinator: Arc<TransportCoordinator>,
    registry: Arc<TransportRegistry>,
) -> (
    Option<discovery::DiscoveryState>,
    Arc<AtomicUsize>,
    Option<String>,
) {
    match discovery::initialize(config, identity, storage, coordinator, registry).await {
        discovery::InitResult::Disabled => (None, Arc::new(AtomicUsize::new(0)), None),
        discovery::InitResult::Failed(reason) => (
            None,
            Arc::new(AtomicUsize::new(0)),
            Some(format!("LAN discovery failed: {reason}")),
        ),
        discovery::InitResult::Ok(state) => {
            let peer_count = state.peer_count.clone();
            (Some(state), peer_count, None)
        }
    }
}

/// Build the HTTP transport pool from parsed peer configurations.
fn build_http_pool(
    parsed_peers: &[ParsedHttpPeer],
) -> AppResult<Option<Arc<TransportPool<HttpTarget>>>> {
    if parsed_peers.is_empty() {
        return Ok(None);
    }

    let pool = TransportPool::new();
    for peer in parsed_peers {
        let target = build_http_target_from_config(peer)?;
        pool.add_target(target);
    }
    Ok(Some(Arc::new(pool)))
}

/// Build a single HTTP target from a parsed peer configuration.
fn build_http_target_from_config(peer: &ParsedHttpPeer) -> AppResult<HttpTarget> {
    let mut config = HttpTargetConfig::stable(&peer.url);

    if let Some(ref pin) = peer.cert_pin {
        match ember_transport::CertPin::parse(&pin.to_pin_string()) {
            Ok(transport_pin) => config = config.with_cert_pin(transport_pin),
            Err(e) => {
                warn!(url = %peer.url, error = %e, "Certificate pin conversion failed - this is a bug");
            }
        }
    }

    if let Some(ref label) = peer.common.label {
        config = config.with_label(label.clone());
    }

    config = config.with_priority(clamp_priority(peer.common.priority, &peer.url));
    config = config.with_node_pubkey_opt(peer.node_pubkey);

    if let Some((username, password)) = &peer.auth {
        config = config.with_auth(username, password);
    }

    Ok(HttpTarget::new(config)?)
}

/// Clamp a u16 priority to u8 range, warning on truncation.
fn clamp_priority(priority: u16, url: &str) -> u8 {
    if priority > 255 {
        warn!(url = %url, configured = priority, "Priority exceeds 255, clamping");
        255
    } else {
        #[allow(clippy::cast_possible_truncation)]
        {
            priority as u8
        }
    }
}

/// Build the MQTT transport pool, connecting configured brokers in parallel.
async fn build_mqtt_pool(parsed_peers: &[ParsedMqttPeer]) -> Arc<TransportPool<MqttTarget>> {
    let pool = TransportPool::new();
    connect_mqtt_peers(&pool, parsed_peers).await;
    Arc::new(pool)
}

/// Spawn parallel MQTT connection tasks and collect results into the pool.
async fn connect_mqtt_peers(pool: &TransportPool<MqttTarget>, parsed_peers: &[ParsedMqttPeer]) {
    if parsed_peers.is_empty() {
        return;
    }

    let mut join_set = spawn_mqtt_connections(parsed_peers);
    collect_mqtt_results(pool, &mut join_set).await;
}

/// Spawn MQTT connection tasks for all configured peers.
fn spawn_mqtt_connections(
    parsed_peers: &[ParsedMqttPeer],
) -> tokio::task::JoinSet<(String, Result<MqttTarget, ember_transport::TransportError>)> {
    let mut join_set = tokio::task::JoinSet::new();
    for parsed_peer in parsed_peers.iter().cloned() {
        join_set.spawn(async move {
            let config = build_mqtt_target_config(&parsed_peer);
            (parsed_peer.url.clone(), MqttTarget::connect(config).await)
        });
    }
    join_set
}

/// Collect MQTT connection results into the pool.
async fn collect_mqtt_results(
    pool: &TransportPool<MqttTarget>,
    join_set: &mut tokio::task::JoinSet<(
        String,
        Result<MqttTarget, ember_transport::TransportError>,
    )>,
) {
    while let Some(result) = join_set.join_next().await {
        handle_mqtt_join_result(pool, result);
    }
}

/// Handle a single MQTT connection join result.
fn handle_mqtt_join_result(
    pool: &TransportPool<MqttTarget>,
    result: Result<
        (String, Result<MqttTarget, ember_transport::TransportError>),
        tokio::task::JoinError,
    >,
) {
    let Ok((url, connect_result)) = result else {
        warn!("MQTT connection task panicked");
        return;
    };
    log_mqtt_connect_result(pool, &url, connect_result);
}

/// Log and apply the result of an MQTT connection attempt.
fn log_mqtt_connect_result(
    pool: &TransportPool<MqttTarget>,
    url: &str,
    result: Result<MqttTarget, ember_transport::TransportError>,
) {
    match result {
        Ok(target) => pool.add_target(target),
        Err(e) => warn!(broker = %url, error = %e, "Failed to connect to MQTT broker"),
    }
}

/// Build MQTT target config from parsed peer configuration.
fn build_mqtt_target_config(peer: &ParsedMqttPeer) -> MqttTargetConfig {
    let config = MqttTargetConfig::new(&peer.url)
        .with_priority(clamp_priority(peer.common.priority, &peer.url));
    apply_mqtt_optional_fields(config, peer)
}

/// Apply optional fields to an MQTT target config.
fn apply_mqtt_optional_fields(
    mut config: MqttTargetConfig,
    peer: &ParsedMqttPeer,
) -> MqttTargetConfig {
    if let Some(ref client_id) = peer.client_id {
        config = config.with_client_id(client_id);
    }
    if let Some(ref auth) = peer.auth {
        config = config.with_auth(&auth.0, &auth.1);
    }
    if let Some(ref label) = peer.common.label {
        config = config.with_label(label);
    }
    if let Some(ref prefix) = peer.topic_prefix {
        config = config.with_topic_prefix(prefix);
    }
    config
}

/// Set up the embedded node if enabled, including the HTTP server.
async fn setup_embedded_node(
    config: &crate::config::AppConfig,
    identity: &Identity,
    identity_bytes: &Zeroizing<[u8; 32]>,
) -> AppResult<(
    Option<EmbeddedNodeHandle>,
    Option<tokio::task::JoinHandle<()>>,
    Option<mpsc::Receiver<NodeEvent>>,
)> {
    if !config.embedded_node.enabled {
        return Ok((None, None, None));
    }

    let (handle, join_handle, event_rx) = create_embedded_node(config)?;
    start_embedded_http_server(config, identity, identity_bytes, &handle).await?;

    Ok((Some(handle), Some(join_handle), Some(event_rx)))
}

/// Create and start the embedded node (without HTTP server).
fn create_embedded_node(
    config: &crate::config::AppConfig,
) -> AppResult<(
    EmbeddedNodeHandle,
    tokio::task::JoinHandle<()>,
    mpsc::Receiver<NodeEvent>,
)> {
    info!("Starting embedded node...");

    let store_config = PersistentStoreConfig::new(
        config.embedded_node.max_messages as usize,
        config.embedded_node.default_ttl_secs,
    )
    .map_err(|e| format!("Invalid embedded node config: {e}"))?;

    let mailbox_store = open_mailbox_store(config, store_config)?;

    let (node, handle, event_rx) = EmbeddedNode::new(mailbox_store);
    let join_handle = tokio::spawn(async move { node.run().await });
    info!("Embedded node started");

    Ok((handle, join_handle, event_rx))
}

/// Open the mailbox store from the configured data directory.
fn open_mailbox_store(
    config: &crate::config::AppConfig,
    store_config: PersistentStoreConfig,
) -> AppResult<PersistentMailboxStore> {
    let mailbox_db_path = config.data_dir.join("mailbox.db");
    let mailbox_db_str = mailbox_db_path
        .to_str()
        .ok_or("Mailbox database path contains invalid UTF-8 characters")?;
    PersistentMailboxStore::open(mailbox_db_str, store_config)
        .map_err(|e| format!("Failed to open mailbox store: {e}").into())
}

/// Start the embedded HTTP server for LAN P2P if configured.
async fn start_embedded_http_server(
    config: &crate::config::AppConfig,
    identity: &Identity,
    identity_bytes: &Zeroizing<[u8; 32]>,
    handle: &EmbeddedNodeHandle,
) -> AppResult<()> {
    let Some(ref bind_addr) = config.embedded_node.http_bind else {
        return Ok(());
    };

    let http_handle = handle.clone();
    let our_routing_key = identity.public_id().routing_key();
    let http_identity = Arc::new(Identity::from_bytes(identity_bytes)?);

    let (listener, router) =
        http_server::bind_server(bind_addr, http_handle, our_routing_key, http_identity)
            .await
            .map_err(|e| format!("Failed to start HTTP server: {e}"))?;

    tokio::spawn(async move {
        if let Err(e) = http_server::run_server(listener, router).await {
            tracing::error!(error = %e, "Embedded HTTP server stopped unexpectedly");
        }
    });

    Ok(())
}

/// Process an incoming envelope locally and notify the UI, then fire-and-forget the tombstone.
///
/// Returns `Err(())` if the action channel is closed (caller should break the loop).
fn process_and_notify(
    client: &Arc<Client<TransportCoordinator>>,
    tx: &mpsc::UnboundedSender<Action>,
    envelope: &ember_message::OuterEnvelope,
    source: MessageSource,
) -> Result<(), ()> {
    match client.process_message_local(envelope) {
        Ok(processed) => {
            tx.send(Action::MessageProcessed {
                result: Ok(processed.received),
                source,
            })
            .map_err(|_| ())?;
            if let Some(tombstone) = processed.pending_tombstone {
                let client = client.clone();
                tokio::spawn(async move {
                    if let Err(e) = client.send_tombstone(tombstone).await {
                        warn!(error = %e, "Tombstone send failed");
                    }
                });
            }
            Ok(())
        }
        Err(e) => tx
            .send(Action::MessageProcessed {
                result: Err(e.to_string()),
                source,
            })
            .map_err(|_| ()),
    }
}

/// Connect to an MQTT broker and register it as an ephemeral upstream.
///
/// Extracted from the spawn closure in `handle_add_upstream_popup_key_event` to
/// avoid the `async { ... }.await` block and enable `?` propagation cleanly.
async fn connect_mqtt_upstream(
    url: &str,
    tier: DeliveryTier,
    registry: &TransportRegistry,
) -> Result<(), String> {
    let mqtt_config = MqttTargetConfig::new(url);
    let target = MqttTarget::connect(mqtt_config)
        .await
        .map_err(|e| format!("Failed to connect to MQTT broker: {e}"))?;
    let id = target.id().clone();
    let pool = registry.mqtt_pool().ok_or("MQTT pool not initialized")?;
    pool.add_target(target);
    registry.register_ephemeral(id, None, tier);
    info!(url = %url, "Added ephemeral MQTT upstream");
    Ok(())
}

/// Get current UTC time as HH:MM string (avoids chrono dependency)
fn utc_time_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    #[allow(clippy::cast_possible_wrap)]
    format_unix_timestamp(secs as i64)
}

/// Format a unix timestamp (seconds) as HH:MM UTC
fn format_unix_timestamp(secs: i64) -> String {
    if secs < 0 {
        return "??:??".to_string();
    }
    #[allow(clippy::cast_sign_loss)]
    let secs = secs as u64;
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

/// Format a [`TieredDeliveryPhase`] into a human-readable status message.
fn format_delivery_status(phase: &TieredDeliveryPhase) -> String {
    use ember_transport::DeliveryConfidence;
    match phase {
        TieredDeliveryPhase::Urgent => "Sent (queued, awaiting delivery)".to_string(),
        TieredDeliveryPhase::Distributed { confidence, .. } => match confidence {
            DeliveryConfidence::DirectDelivery { .. } => "Sent (direct delivery)".to_string(),
            DeliveryConfidence::QuorumReached { count, required } => {
                format!("Sent (quorum {count}/{required})")
            }
        },
        TieredDeliveryPhase::Confirmed { .. } => "Sent (confirmed)".to_string(),
    }
}

/// Current wall-clock time as Unix seconds.
fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    #[allow(clippy::cast_possible_wrap)]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::{action_requires_render, build_direct_peer_target, Action};
    use crate::config::DirectPeerConfig;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ember_identity::PublicID;
    use ember_transport::target::TransportTarget;

    #[test]
    fn outbox_tick_does_not_require_render() {
        assert!(!action_requires_render(&Action::OutboxTick(Ok((0, 0, 0)))));
    }

    #[test]
    fn resize_requires_render() {
        assert!(action_requires_render(&Action::Resize(80, 24)));
    }

    #[test]
    fn key_requires_render() {
        assert!(action_requires_render(&Action::Key(KeyEvent::new(
            KeyCode::Char('a'),
            KeyModifiers::NONE,
        ))));
    }

    #[test]
    fn node_error_requires_render() {
        assert!(action_requires_render(&Action::NodeError(
            "boom".to_string(),
        )));
    }

    #[test]
    fn direct_peer_with_valid_public_id_wires_node_pubkey() {
        let pk = PublicID::try_from_bytes(&[7u8; 32]).unwrap();
        let pk_b64 = BASE64_STANDARD.encode(pk.to_bytes());

        let peer = DirectPeerConfig {
            public_id: Some(pk_b64),
            address: "http://127.0.0.1:9999".to_string(),
            name: Some("test-peer".to_string()),
        };

        let target = build_direct_peer_target(&peer).expect("peer should build successfully");
        assert_eq!(target.config().node_pubkey, Some(pk));
    }

    #[test]
    fn direct_peer_without_public_id_has_no_node_pubkey() {
        let peer = DirectPeerConfig {
            public_id: None,
            address: "http://127.0.0.1:9999".to_string(),
            name: None,
        };

        let target = build_direct_peer_target(&peer).expect("peer should build successfully");
        assert_eq!(target.config().node_pubkey, None);
    }

    #[test]
    fn direct_peer_with_invalid_public_id_is_skipped() {
        let peer = DirectPeerConfig {
            public_id: Some("not-valid-base64!!!".to_string()),
            address: "http://127.0.0.1:9999".to_string(),
            name: Some("bad-peer".to_string()),
        };

        assert!(
            build_direct_peer_target(&peer).is_none(),
            "peer with invalid public_id should be skipped"
        );
    }

    #[test]
    fn direct_peer_with_wrong_length_public_id_is_skipped() {
        let short_key = BASE64_STANDARD.encode([1u8; 16]); // 16 bytes, not 32

        let peer = DirectPeerConfig {
            public_id: Some(short_key),
            address: "http://127.0.0.1:9999".to_string(),
            name: None,
        };

        assert!(
            build_direct_peer_target(&peer).is_none(),
            "peer with wrong-length public_id should be skipped"
        );
    }

    #[test]
    fn direct_peer_with_empty_public_id_is_skipped() {
        let peer = DirectPeerConfig {
            public_id: Some(String::new()),
            address: "http://127.0.0.1:9999".to_string(),
            name: None,
        };

        assert!(
            build_direct_peer_target(&peer).is_none(),
            "peer with empty public_id should be treated as invalid, not absent"
        );
    }
}
