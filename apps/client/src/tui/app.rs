//! Application state and main loop

use crate::config::AppConfig;
use crate::tui::event::{Event, EventHandler};
use crate::tui::ui;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::prelude::*;
use reme_core::Client;
use reme_identity::{Identity, PublicID};
use reme_message::Content;
use reme_storage::Storage;
use reme_transport::http::HttpTransport;
use reme_transport::{MessageReceiver, ReceiverConfig, TransportEvent};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tui_textarea::{Input, TextArea};

pub type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

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
        public_id_input.set_placeholder_text("64-character hex string");
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

        if hex_str.len() != 64 {
            return Err(format!(
                "Public ID must be 64 hex characters (got {})",
                hex_str.len()
            ));
        }

        let bytes = hex::decode(hex_str)
            .map_err(|_| "Invalid hex characters in Public ID".to_string())?;

        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "Internal error: wrong byte length".to_string())?;

        PublicID::try_from_bytes(&bytes)
            .map_err(|_| "Invalid Public ID: rejected by curve validation".to_string())
    }

    /// Get the name input (None if empty)
    pub fn get_name(&self) -> Option<String> {
        let name: String = self.name_input.lines().join("");
        let name = name.trim().to_string();
        if name.is_empty() {
            None
        } else {
            Some(name)
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
    /// The messenger client
    client: Client<HttpTransport>,
    /// Transport for message receiving
    transport: Arc<HttpTransport>,
    /// Contacts by name (for reverse lookup)
    contacts_by_id: HashMap<PublicID, String>,
    /// In-memory message cache per contact (until storage retrieval is implemented)
    message_cache: HashMap<PublicID, Vec<Message>>,
    /// Whether the add contact popup is visible
    pub show_add_contact_popup: bool,
    /// Add contact popup state
    pub add_contact_popup: AddContactPopup<'a>,
    /// Whether the "my identity" popup is visible
    pub show_my_id_popup: bool,
}

impl<'a> App<'a> {
    /// Create a new app instance
    pub async fn new(config: AppConfig) -> AppResult<Self> {
        // Ensure data directory exists
        fs::create_dir_all(&config.data_dir)?;

        // Load or generate identity
        let identity_path = config.data_dir.join("identity.key");
        let identity = if identity_path.exists() {
            let bytes = fs::read(&identity_path)?;
            let key: [u8; 32] = bytes.try_into().map_err(|_| "Invalid identity file")?;
            Identity::from_bytes(&key)
        } else {
            let identity = Identity::generate();
            fs::write(&identity_path, identity.to_bytes())?;
            identity
        };

        // Create storage
        let db_path = config.data_dir.join("messages.db");
        let storage = Storage::open(db_path.to_str().unwrap())?;

        // Create transport
        let transport = Arc::new(HttpTransport::with_nodes(config.node_urls.clone()));

        // Create client
        let client = Client::new(identity, transport.clone(), storage);

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
            status: "Press 'h' for help".to_string(),
            client,
            transport,
            contacts_by_id: HashMap::new(),
            message_cache: HashMap::new(),
            show_add_contact_popup: false,
            add_contact_popup: AddContactPopup::default(),
            show_my_id_popup: false,
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
            let name = contact.name.clone().unwrap_or_else(|| {
                let hex = hex::encode(contact.public_id.to_bytes());
                format!("{}...", &hex[..8])
            });

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

        // Setup message receiver for incoming messages
        let receiver = MessageReceiver::new(self.transport.clone());
        let config = ReceiverConfig::with_poll_interval(Duration::from_secs(2));
        let (mut msg_events, _handle) = receiver.subscribe(self.client.routing_key(), config);

        while self.running {
            // Draw UI
            terminal.draw(|frame| ui::render(frame, self))?;

            // Check for incoming messages (non-blocking)
            while let Ok(event) = msg_events.try_recv() {
                if let TransportEvent::Message(envelope) = event {
                    if let Ok(msg) = self.client.process_message(&envelope).await {
                        let content = match &msg.content {
                            Content::Text(t) => t.body.clone(),
                            Content::Receipt(r) => format!("[Receipt: {:?}]", r.kind),
                            _ => "[Unknown content]".to_string(),
                        };
                        self.handle_incoming_message(msg.from, content);
                    }
                }
            }

            // Handle UI events
            match event_handler.next().await? {
                Event::Tick => {}
                Event::Key(key_event) => self.handle_key_event(key_event).await?,
                Event::Resize(_, _) => {}
            }
        }

        Ok(())
    }

    /// Get or create a conversation for a contact, returns the index
    fn get_or_create_conversation(&mut self, public_id: PublicID) -> usize {
        // Check if conversation exists
        if let Some(idx) = self.conversations.iter().position(|c| c.public_id == public_id) {
            return idx;
        }

        // Create display name
        let display_name = self.client.get_contact(&public_id)
            .ok()
            .and_then(|c| c.name)
            .unwrap_or_else(|| {
                let hex = hex::encode(public_id.to_bytes());
                format!("{}...", &hex[..8])
            });

        // Get contact ID from storage (reme-core auto-adds on message receive)
        let contact_id = self.client.get_contact(&public_id)
            .map(|c| c.id)
            .unwrap_or(0);

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
            timestamp: chrono_lite_now(),
        };

        // Cache message
        self.message_cache
            .entry(from)
            .or_insert_with(Vec::new)
            .push(message.clone());

        // Update conversation
        self.conversations[conv_idx].last_message = Some(content);

        // Update UI
        if conv_idx == self.selected_conversation {
            self.messages.push(message);
        } else {
            self.conversations[conv_idx].unread_count += 1;
        }

        self.status = "New message received".to_string();

        // Ring terminal bell for notification
        use std::io::Write;
        print!("\x07");
        let _ = std::io::stdout().flush();
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
            KeyCode::Char('a') => {
                // Open add contact popup
                self.show_add_contact_popup = true;
                self.add_contact_popup.reset();
                self.status = "Popup opened - Tab to switch, Enter to confirm, Esc to cancel".to_string();
            }
            KeyCode::Char('i') => {
                // Show my identity popup
                self.show_my_id_popup = true;
            }
            KeyCode::Char('h') => {
                self.status = "j/k: navigate | Enter: select | a: add | i: my ID | Tab: switch | Esc: quit".to_string();
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
                                    timestamp: chrono_lite_now(),
                                };

                                // Cache the message
                                self.message_cache
                                    .entry(public_id)
                                    .or_insert_with(Vec::new)
                                    .push(message.clone());

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

    /// Load messages for the selected conversation
    fn load_conversation_messages(&mut self) {
        self.messages.clear();
        self.message_scroll = 0;

        // Load from in-memory cache
        if let Some(conv) = self.conversations.get(self.selected_conversation) {
            if let Some(cached) = self.message_cache.get(&conv.public_id) {
                self.messages = cached.clone();
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

        // Check if contact already exists
        if self.client.get_contact(&public_id).is_ok() {
            self.add_contact_popup.error = Some("Contact already exists".to_string());
            return Ok(());
        }

        // Add contact via client API
        match self.client.add_contact(&public_id, name.as_deref()) {
            Ok(contact) => {
                let display_name = contact.name.clone().unwrap_or_else(|| {
                    let hex = hex::encode(contact.public_id.to_bytes());
                    format!("{}...", &hex[..8])
                });

                // Add to local contacts list
                self.contacts_by_id
                    .insert(contact.public_id, display_name.clone());
                self.conversations.push(Conversation {
                    id: contact.id,
                    public_id: contact.public_id,
                    name: display_name.clone(),
                    last_message: None,
                    unread_count: 0,
                });

                // Select the new contact and move to input
                self.selected_conversation = self.conversations.len() - 1;
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

/// Simple timestamp function (avoid chrono dependency)
fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    format!("{:02}:{:02}", hours, mins)
}
