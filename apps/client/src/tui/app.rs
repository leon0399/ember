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
    /// Config
    config: AppConfig,
    /// Contacts by name (for reverse lookup)
    contacts_by_id: HashMap<PublicID, String>,
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
            config,
            contacts_by_id: HashMap::new(),
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

    /// Handle incoming message
    fn handle_incoming_message(&mut self, from: PublicID, content: String) {
        // Find conversation
        let conv_idx = self.conversations.iter().position(|c| c.public_id == from);

        if let Some(idx) = conv_idx {
            // Update last message
            self.conversations[idx].last_message = Some(content.clone());

            // If this is the selected conversation, add to messages
            if idx == self.selected_conversation {
                let sender_name = self.contacts_by_id.get(&from)
                    .cloned()
                    .unwrap_or_else(|| "Unknown".to_string());

                self.messages.push(Message {
                    from_me: false,
                    sender_name,
                    content,
                    timestamp: chrono_lite_now(),
                });
            } else {
                // Increment unread count
                self.conversations[idx].unread_count += 1;
            }

            self.status = "New message received".to_string();
        }
    }

    /// Handle key events
    async fn handle_key_event(&mut self, key: KeyEvent) -> AppResult<()> {
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
                self.status = "Add contact: Use CLI mode (press 'q' to exit TUI)".to_string();
            }
            KeyCode::Char('i') => {
                // Initialize prekeys
                self.status = "Initializing prekeys...".to_string();
                match self.client.init_prekeys(self.config.num_prekeys as usize).await {
                    Ok(_) => self.status = "Prekeys initialized!".to_string(),
                    Err(e) => self.status = format!("Error: {}", e),
                }
            }
            KeyCode::Char('u') => {
                // Upload prekeys
                self.status = "Uploading prekeys...".to_string();
                match self.client.upload_prekeys().await {
                    Ok(_) => self.status = "Prekeys uploaded!".to_string(),
                    Err(e) => self.status = format!("Error: {}", e),
                }
            }
            KeyCode::Char('h') => {
                self.status = "j/k: navigate | Enter: select | Tab: switch pane | i: init prekeys | u: upload | Esc/Ctrl+C: quit".to_string();
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
                                // Add to local messages
                                self.messages.push(Message {
                                    from_me: true,
                                    sender_name: "You".to_string(),
                                    content: text,
                                    timestamp: chrono_lite_now(),
                                });
                                self.input = TextArea::default();
                                self.input.set_placeholder_text("Type a message...");
                                self.status = "Message sent!".to_string();
                            }
                            Err(e) => {
                                let err_str = e.to_string();
                                if err_str.contains("Not found") {
                                    self.status = "Send failed: no prekeys found".to_string();
                                } else {
                                    self.status = format!("Send failed: {}", e);
                                }
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
        // TODO: Load from storage
        // For now, just show a placeholder
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
