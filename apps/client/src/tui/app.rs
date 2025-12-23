//! Application state and main loop

use crate::config::AppConfig;
use crate::tui::event::{Event, EventHandler};
use crate::tui::ui;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use ratatui::prelude::*;
use reme_core::Client;
use reme_identity::{Identity, PublicID};
use reme_message::Content;
use reme_node_core::{EmbeddedNode, EmbeddedNodeHandle, NodeEvent, PersistentMailboxStore, PersistentStoreConfig};
use reme_outbox::{OutboxConfig, TransportRetryPolicy};
use reme_storage::Storage;
use reme_transport::http::NodeSpec;
use reme_transport::http_target::{HttpTarget, HttpTargetConfig};
use reme_transport::pool::TransportPool;
use reme_transport::target::TargetKind;
use reme_transport::{
    CertPin, CompositeTransport, EmbeddedTarget, MessageReceiver, MqttBrokerSpec, MqttTransport,
    ReceiverConfig, TransportEvent,
};
use tokio::sync::mpsc;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};
use tui_textarea::{Input, TextArea};

pub type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Length of a PublicID when encoded as hexadecimal (32 bytes = 64 hex chars)
const PUBLIC_ID_HEX_LENGTH: usize = 64;

/// Help text shown in status bar (Alt+H or initial startup)
const HELP_TEXT: &str = "Alt+A: add | Alt+I: identity | Alt+H: help | Tab: switch | Ctrl+Q: quit";

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

impl<'a> Default for AddContactPopup<'a> {
    fn default() -> Self {
        let mut public_id_input = TextArea::default();
        public_id_input.set_placeholder_text(&format!("{}-character hex string", PUBLIC_ID_HEX_LENGTH));
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

impl<'a> AddContactPopup<'a> {
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

        let bytes = hex::decode(hex_str)
            .map_err(|_| "Invalid hex characters in Public ID".to_string())?;

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

/// A conversation/contact entry
#[derive(Debug, Clone)]
pub struct Conversation {
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
    /// The messenger client (uses CompositeTransport for sending via HTTP and/or MQTT)
    client: Client<CompositeTransport>,
    /// HTTP transport pool for message receiving (HTTP polling-based receiver)
    http_pool: Arc<TransportPool<HttpTarget>>,
    /// Embedded node handle (for shutdown)
    embedded_node_handle: Option<EmbeddedNodeHandle>,
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
    /// Outbox tick interval from config
    outbox_tick_interval: Duration,
}

impl<'a> App<'a> {
    /// Create a new app instance
    ///
    /// # Arguments
    /// * `config` - Application configuration
    /// * `identity` - The loaded/decrypted identity
    pub async fn new(config: AppConfig, identity: Identity) -> AppResult<Self> {
        // Ensure data directory exists
        fs::create_dir_all(&config.data_dir)?;

        // Create storage
        let db_path = config.data_dir.join("messages.db");
        let db_path_str = db_path
            .to_str()
            .ok_or("Database path contains invalid UTF-8 characters")?;
        let storage = Storage::open(db_path_str)?;

        // Create HTTP transport with TLS and certificate pinning support
        let node_specs: Vec<NodeSpec> = config
            .http
            .iter()
            .map(|n| {
                let cert_pin = match &n.cert_pin {
                    Some(pin_str) => {
                        // Fail explicitly if a configured pin is invalid - don't silently disable security
                        let pin = CertPin::parse(pin_str).map_err(|e| {
                            format!(
                                "Invalid certificate pin for node {}: {}. \
                                Fix the pin or remove it to disable pinning for this node.",
                                n.url, e
                            )
                        })?;
                        Some(pin)
                    }
                    None => None,
                };
                Ok(NodeSpec {
                    url: n.url.clone(),
                    cert_pin,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        // Create HTTP transport pool for both sending and receiving
        let http_pool = if !node_specs.is_empty() {
            let pool = TransportPool::from_node_specs(node_specs)?;
            Some(Arc::new(pool))
        } else {
            None
        };

        // Create MQTT transport if brokers are configured
        let mqtt_transport = if !config.mqtt.is_empty() {
            // Convert config brokers to transport broker specs
            let broker_specs: Vec<MqttBrokerSpec> = config
                .mqtt
                .iter()
                .map(|b| MqttBrokerSpec {
                    url: b.url.clone(),
                    client_id: b.client_id.clone(),
                })
                .collect();
            info!("Connecting to {} MQTT broker(s)...", broker_specs.len());
            match MqttTransport::new(broker_specs).await {
                Ok(t) => Some(t),
                Err(e) => {
                    warn!("Failed to connect to MQTT brokers: {}. MQTT transport disabled.", e);
                    None
                }
            }
        } else {
            None
        };

        // Create embedded node if enabled
        let (embedded_node_handle, node_event_rx) = if config.embedded_node.enabled {
            info!("Starting embedded node...");

            // Create persistent store config from app config
            let store_config = PersistentStoreConfig::new(
                config.embedded_node.max_messages as usize,
                config.embedded_node.default_ttl_secs,
            ).map_err(|e| format!("Invalid embedded node config: {}", e))?;

            // Create mailbox store in the same data directory
            let mailbox_db_path = config.data_dir.join("mailbox.db");
            let mailbox_db_str = mailbox_db_path
                .to_str()
                .ok_or("Mailbox database path contains invalid UTF-8 characters")?;
            let mailbox_store = PersistentMailboxStore::open(mailbox_db_str, store_config)
                .map_err(|e| format!("Failed to open mailbox store: {}", e))?;

            // Create and spawn embedded node
            let (node, handle, event_rx) = EmbeddedNode::new(mailbox_store);
            tokio::spawn(async move { node.run().await });

            info!("Embedded node started");
            (Some(handle), Some(event_rx))
        } else {
            (None, None)
        };

        // Build composite transport for sending
        let mut composite = CompositeTransport::new();
        if let Some(ref http) = http_pool {
            composite = composite.with_arc_transport(http.clone());
        }
        if let Some(mqtt) = mqtt_transport {
            composite = composite.with_transport(mqtt);
        }
        // Add embedded node as highest-priority transport if enabled
        if let Some(ref handle) = embedded_node_handle {
            let embedded_target = EmbeddedTarget::new(handle.clone());
            composite = composite.with_transport(embedded_target);
        }

        // Add direct peers as ephemeral targets for LAN P2P messaging
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
                    composite = composite.with_transport(target);
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

        let transport = Arc::new(composite);

        // Ensure we have at least one transport
        if transport.is_empty() {
            return Err("No transports configured. Add HTTP nodes and/or MQTT brokers.".into());
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

        // Create client with custom outbox config
        let mut client = Client::with_config(identity, transport.clone(), storage, outbox_config);

        // Set HTTP transport retry policy
        client.set_transport_policy("http:", retry_policy);

        // Store tick interval from config
        let outbox_tick_interval = Duration::from_secs(config.outbox.tick_interval_secs);

        // Create input area
        let mut input = TextArea::default();
        input.set_placeholder_text("Type a message...");
        input.set_cursor_line_style(Style::default());

        // Ensure we have HTTP transport pool for message receiving
        let http_pool_arc = http_pool.ok_or(
            "No HTTP nodes configured. HTTP is required for message receiving.",
        )?;

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
            http_pool: http_pool_arc,
            embedded_node_handle,
            node_event_rx,
            contacts_by_id: HashMap::new(),
            message_cache: HashMap::new(),
            show_add_contact_popup: false,
            add_contact_popup: AddContactPopup::default(),
            show_my_id_popup: false,
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

        // Setup message receiver for incoming messages (uses HTTP pool for polling)
        let receiver = MessageReceiver::new(self.http_pool.clone());
        let config = ReceiverConfig::with_poll_interval(Duration::from_secs(2));
        let (mut msg_events, _handle) = receiver.subscribe(self.client.routing_key(), config);

        while self.running {
            // Draw UI
            terminal.draw(|frame| ui::render(frame, self))?;

            // Check for incoming messages from HTTP polling (non-blocking)
            while let Ok(event) = msg_events.try_recv() {
                if let TransportEvent::Message(envelope) = event {
                    self.process_incoming_envelope(&envelope, "HTTP").await;
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
                        self.process_incoming_envelope(&envelope, "embedded node").await;
                    }
                    NodeEvent::Error(e) => {
                        tracing::error!("Embedded node error: {}", e);
                        self.status = format!("Node error: {}", e);
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
    async fn shutdown_embedded_node(&self) {
        if let Some(ref handle) = self.embedded_node_handle {
            debug!("Shutting down embedded node...");
            if let Err(e) = handle.shutdown().await {
                warn!(error = %e, "Failed to shutdown embedded node gracefully");
            } else {
                info!("Embedded node shutdown complete");
            }
        }
    }

    /// Process an incoming envelope from any transport source.
    ///
    /// Decrypts the message, extracts content, and updates the UI.
    async fn process_incoming_envelope(&mut self, envelope: &reme_message::OuterEnvelope, source: &str) {
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
                self.status = format!("Message decrypt failed: {}", e);
            }
        }
    }

    /// Get or create a conversation for a contact, returns the index
    fn get_or_create_conversation(&mut self, public_id: PublicID) -> usize {
        // Check if conversation exists
        if let Some(idx) = self.conversations.iter().position(|c| c.public_id == public_id) {
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
    async fn handle_key_event(&mut self, key: KeyEvent) -> AppResult<()> {
        // Handle popups first if visible
        if self.show_add_contact_popup {
            return self.handle_popup_key_event(key);
        }
        if self.show_my_id_popup {
            return self.handle_my_id_popup_key_event(key);
        }

        // Global shortcuts
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('c') | KeyCode::Char('q') => {
                    self.running = false;
                    return Ok(());
                }
                _ => {}
            }
        }

        // Global shortcuts (Alt+key) - work from any focus
        if key.modifiers.contains(KeyModifiers::ALT) {
            match key.code {
                KeyCode::Char('a') => {
                    // Alt+A: Add contact
                    self.show_add_contact_popup = true;
                    self.add_contact_popup.reset();
                    self.status = "Add Contact (Tab: switch, Enter: confirm, Esc: cancel)".to_string();
                    return Ok(());
                }
                KeyCode::Char('i') => {
                    // Alt+I: Show identity
                    self.show_my_id_popup = true;
                    return Ok(());
                }
                KeyCode::Char('h') => {
                    // Alt+H: Show help
                    self.status = HELP_TEXT.to_string();
                    return Ok(());
                }
                _ => {}
            }
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
            _ => {
                match self.focus {
                    Focus::Conversations => self.handle_conversation_key(key).await?,
                    Focus::Messages => self.handle_message_key(key),
                    Focus::Input => self.handle_input_key(key).await?,
                }
            }
        }

        Ok(())
    }

    /// Handle key events in conversation list
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
        match key.code {
            KeyCode::Enter => {
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
                                self.status = format!("Send failed: {}", e);
                            }
                        }
                    }
                }
            }
            _ => {
                // Forward to textarea
                let input = Input::from(key);
                self.input.input(input);
            }
        }
        Ok(())
    }

    /// Cache a message with size limit (O(1) eviction using VecDeque)
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
                self.status = format!("Focus: {} field", field_name);
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
                self.status = format!("Added contact: {}", display_name);
            }
            Err(e) => {
                self.add_contact_popup.error = Some(format!("Failed to add contact: {}", e));
            }
        }

        Ok(())
    }

    /// Handle key events when my ID popup is visible
    fn handle_my_id_popup_key_event(&mut self, key: KeyEvent) -> AppResult<()> {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('i') => {
                // Close popup
                self.show_my_id_popup = false;
            }
            _ => {}
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
    format!("{:02}:{:02}", hours, mins)
}

/// Format a display name from optional name and public ID
///
/// Uses the provided name if available, otherwise returns truncated hex of the public ID.
fn format_display_name(name: Option<&str>, public_id: &PublicID) -> String {
    name.map(String::from).unwrap_or_else(|| {
        let hex = hex::encode(public_id.to_bytes());
        format!("{}...", &hex[..8])
    })
}
