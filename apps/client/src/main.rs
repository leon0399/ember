//! Branch Messenger CLI Client
//!
//! A simple command-line client for testing the messenger.
//!
//! ## Commands
//! - `init` - Generate new identity and prekeys
//! - `id` - Show your public ID
//! - `add <public_id> [name]` - Add a contact
//! - `send <name> <message>` - Send a message to a contact
//! - `fetch` - Fetch pending messages
//! - `contacts` - List contacts
//! - `help` - Show help
//! - `quit` - Exit

use reme_core::Client;
use reme_identity::{Identity, PublicID};
use reme_storage::Storage;
use reme_transport::http::HttpTransport;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};

struct App {
    client: Client<HttpTransport>,
    contacts_by_name: HashMap<String, PublicID>,
    data_dir: PathBuf,
}

impl App {
    async fn new(node_url: &str, data_dir: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        // Ensure data directory exists
        fs::create_dir_all(&data_dir)?;

        // Load or generate identity
        let identity_path = data_dir.join("identity.key");
        let identity = if identity_path.exists() {
            let bytes = fs::read(&identity_path)?;
            let key: [u8; 32] = bytes.try_into().map_err(|_| "Invalid identity file")?;
            info!("Loaded identity from {:?}", identity_path);
            Identity::from_bytes(&key)
        } else {
            let identity = Identity::generate();
            fs::write(&identity_path, identity.to_bytes())?;
            info!("Generated new identity, saved to {:?}", identity_path);
            identity
        };

        // Create storage
        let db_path = data_dir.join("messages.db");
        let storage = Storage::open(db_path.to_str().unwrap())?;

        // Create transport
        let transport = Arc::new(HttpTransport::new(node_url));

        // Create client
        let client = Client::new(identity, transport, storage);

        Ok(Self {
            client,
            contacts_by_name: HashMap::new(),
            data_dir,
        })
    }

    fn public_id(&self) -> String {
        hex::encode(self.client.public_id().to_bytes())
    }

    async fn init_prekeys(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.client.init_prekeys(10).await?;
        Ok(())
    }

    fn add_contact(&mut self, public_id_hex: &str, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = hex::decode(public_id_hex)?;
        if bytes.len() != 32 {
            return Err("Public ID must be 32 bytes (64 hex chars)".into());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        let public_id = PublicID::from_bytes(&key);

        self.client.add_contact(&public_id, Some(name))?;
        self.contacts_by_name.insert(name.to_string(), public_id);

        Ok(())
    }

    async fn send_message(&self, name: &str, text: &str) -> Result<(), Box<dyn std::error::Error>> {
        let public_id = self.contacts_by_name.get(name)
            .ok_or_else(|| format!("Contact '{}' not found", name))?;

        self.client.send_text(public_id, text).await?;
        Ok(())
    }

    async fn fetch_messages(&self) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
        let messages = self.client.fetch_messages().await?;

        let mut result = Vec::new();
        for msg in messages {
            let from = hex::encode(msg.from.to_bytes());
            let from_short = &from[..8];

            let text = match msg.content {
                reme_message::Content::Text(t) => t.body,
                reme_message::Content::Receipt(r) => {
                    format!("[Receipt: {:?}]", r.kind)
                }
                _ => "[Unknown content]".to_string(),
            };

            result.push((from_short.to_string(), text));
        }

        Ok(result)
    }

    fn list_contacts(&self) -> Vec<(String, String)> {
        self.contacts_by_name
            .iter()
            .map(|(name, id)| {
                let id_hex = hex::encode(id.to_bytes());
                (name.clone(), format!("{}...", &id_hex[..16]))
            })
            .collect()
    }
}

fn print_help() {
    println!("Commands:");
    println!("  init                    - Initialize prekeys (required before messaging)");
    println!("  id                      - Show your public ID");
    println!("  add <public_id> <name>  - Add a contact");
    println!("  send <name> <message>   - Send a message");
    println!("  fetch                   - Fetch pending messages");
    println!("  contacts                - List contacts");
    println!("  help                    - Show this help");
    println!("  quit                    - Exit");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Get node URL from args or use default
    let args: Vec<String> = std::env::args().collect();
    let node_url = args.get(1).map(|s| s.as_str()).unwrap_or("http://localhost:23003");

    // Get data directory from args or use default
    let data_dir = args.get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./client_data"));

    println!("Branch Messenger Client v{}", env!("CARGO_PKG_VERSION"));
    println!("Connecting to node: {}", node_url);
    println!("Data directory: {:?}", data_dir);
    println!();

    let mut app = App::new(node_url, data_dir).await?;

    println!("Your ID: {}", app.public_id());
    println!();
    println!("Type 'help' for commands, 'quit' to exit");
    println!();

    let mut rl = DefaultEditor::new()?;

    loop {
        let readline = rl.readline(">> ");

        match readline {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let _ = rl.add_history_entry(line);

                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                let cmd = parts[0];

                match cmd {
                    "help" => print_help(),

                    "quit" | "exit" => {
                        println!("Goodbye!");
                        break;
                    }

                    "id" => {
                        println!("Your ID: {}", app.public_id());
                    }

                    "init" => {
                        match app.init_prekeys().await {
                            Ok(_) => println!("Prekeys initialized and uploaded"),
                            Err(e) => error!("Failed to init prekeys: {}", e),
                        }
                    }

                    "add" => {
                        if parts.len() < 3 {
                            println!("Usage: add <public_id> <name>");
                            continue;
                        }
                        let public_id = parts[1];
                        let name = parts[2];

                        match app.add_contact(public_id, name) {
                            Ok(_) => println!("Added contact: {}", name),
                            Err(e) => error!("Failed to add contact: {}", e),
                        }
                    }

                    "send" => {
                        if parts.len() < 3 {
                            println!("Usage: send <name> <message>");
                            continue;
                        }
                        let name = parts[1];
                        let message = parts[2];

                        match app.send_message(name, message).await {
                            Ok(_) => println!("Message sent to {}", name),
                            Err(e) => error!("Failed to send: {}", e),
                        }
                    }

                    "fetch" => {
                        match app.fetch_messages().await {
                            Ok(messages) => {
                                if messages.is_empty() {
                                    println!("No new messages");
                                } else {
                                    println!("Received {} message(s):", messages.len());
                                    for (from, text) in messages {
                                        println!("  [{}...]: {}", from, text);
                                    }
                                }
                            }
                            Err(e) => error!("Failed to fetch: {}", e),
                        }
                    }

                    "contacts" => {
                        let contacts = app.list_contacts();
                        if contacts.is_empty() {
                            println!("No contacts");
                        } else {
                            println!("Contacts:");
                            for (name, id) in contacts {
                                println!("  {} -> {}", name, id);
                            }
                        }
                    }

                    _ => {
                        println!("Unknown command: {}", cmd);
                        println!("Type 'help' for commands");
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("^D");
                break;
            }
            Err(err) => {
                error!("Error: {:?}", err);
                break;
            }
        }
    }

    Ok(())
}
