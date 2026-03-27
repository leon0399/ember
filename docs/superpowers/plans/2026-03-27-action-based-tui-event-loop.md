# Action-Based TUI Event Loop — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the TUI event loop to the ratatui Action enum pattern so network I/O cannot block rendering.

**Architecture:** All network I/O moves to spawned tokio tasks. A typed `Action` enum is the single integration point — background tasks send results via `UnboundedSender<Action>`. The main loop uses `tokio::select!` to race UI events against action delivery, and a sync `update()` method processes each action. Rendering happens once per loop iteration after all pending actions are drained.

**Tech Stack:** Rust, tokio (spawn, select!, mpsc::unbounded_channel), ratatui, crossterm

**Spec:** `docs/superpowers/specs/2026-03-27-action-based-tui-event-loop.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `apps/client/src/tui/app.rs` | Modify | Action enum, DeliveryStatus, Message struct, App struct fields, `run()` → select! loop, new sync `update()`, background task spawning |
| `apps/client/src/tui/ui.rs` | Modify | Render DeliveryStatus indicators on sent messages |
| `crates/reme-core/src/lib.rs` | Modify | Make `PreparedMessage` pub, make `prepare_message` pub, add `submit_prepared_tiered()` |

---

## Task 1: Expose prepare/submit split on Client

The TUI needs to call `prepare_message()` synchronously (crypto + DB) and then spawn `submit_tiered` + `record_tiered_delivery_result` in a background task. Currently both `PreparedMessage` and `prepare_message` are private.

**Files:**
- Modify: `crates/reme-core/src/lib.rs:146` (`PreparedMessage` struct)
- Modify: `crates/reme-core/src/lib.rs:461` (`prepare_message` method)
- Modify: `crates/reme-core/src/lib.rs:1236` (add new `submit_prepared_tiered` method near `send_text_tiered`)

- [ ] **Step 1: Make `PreparedMessage` public and its fields public**

In `crates/reme-core/src/lib.rs`, change line 146:

```rust
// Before:
struct PreparedMessage {
    outer: OuterEnvelope,
    content_id: ContentId,
    entry_id: OutboxEntryId,
}

// After:
pub struct PreparedMessage {
    /// The outer envelope ready for transmission
    pub outer: OuterEnvelope,
    /// Content ID for DAG tracking
    pub content_id: ContentId,
    /// Message/outbox entry ID (unified identity)
    pub entry_id: OutboxEntryId,
}
```

- [ ] **Step 2: Make `prepare_message` public**

In `crates/reme-core/src/lib.rs`, change line 461:

```rust
// Before:
fn prepare_message(

// After:
pub fn prepare_message(
```

- [ ] **Step 3: Add `submit_prepared_tiered` method**

Add this method to the `impl Client<TransportCoordinator>` block (after `send_text_tiered` around line 1245):

```rust
/// Submit a previously prepared message via tiered delivery and record the result.
///
/// This is the async half of the prepare/submit split. Call `prepare_message()` first
/// (synchronous), then spawn this method in a background task.
pub async fn submit_prepared_tiered(
    &self,
    prepared: &PreparedMessage,
) -> Result<TieredDeliveryPhase, ClientError> {
    let result = self
        .transport
        .submit_tiered(&prepared.outer, &self.tiered_config)
        .await;

    let phase = self
        .outbox
        .record_tiered_delivery_result(prepared.entry_id, &result, &self.tiered_config)
        .map_err(ClientError::Outbox)?;

    match &phase {
        TieredDeliveryPhase::Urgent => {
            warn!(
                message_id = ?prepared.entry_id,
                content_id = ?prepared.content_id,
                success_count = result.success_count(),
                "Message quorum not reached, will retry"
            );
        }
        TieredDeliveryPhase::Distributed { confidence, .. } => {
            if confidence.is_direct() {
                info!(
                    message_id = ?prepared.entry_id,
                    "Message delivered directly (Direct tier)"
                );
            } else {
                debug!(
                    message_id = ?prepared.entry_id,
                    success_count = result.success_count(),
                    "Message distributed, awaiting ACK"
                );
            }
        }
        TieredDeliveryPhase::Confirmed { .. } => {}
    }

    Ok(phase)
}
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check -p reme-core`
Expected: compiles with no errors.

- [ ] **Step 5: Commit**

```bash
git add crates/reme-core/src/lib.rs
git commit -m "refactor(core): expose prepare/submit split for background send

Make PreparedMessage and prepare_message public. Add
submit_prepared_tiered() that wraps submit + record for spawned tasks."
```

---

## Task 2: Add Action enum, DeliveryStatus, and MessageSource types

Add the new types to `app.rs`. These are pure data definitions with no behavior changes yet.

**Files:**
- Modify: `apps/client/src/tui/app.rs` (add types near top of file, after existing type definitions)

- [ ] **Step 1: Add imports that will be needed**

At the top of `apps/client/src/tui/app.rs`, add to the existing import block:

```rust
use reme_core::ReceivedMessage;
```

Verify `ReceivedMessage` is already re-exported from `reme_core`. If not, use `reme_core::ReceivedMessage` — it's `pub struct` in `crates/reme-core/src/lib.rs:82`.

- [ ] **Step 2: Add `DeliveryStatus` enum**

After the `Message` struct (around line 300), add:

```rust
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
```

- [ ] **Step 3: Add `status` field to `Message` struct**

Change the `Message` struct (line 295):

```rust
// Before:
pub struct Message {
    pub from_me: bool,
    pub sender_name: String,
    pub content: String,
    pub timestamp: String,
}

// After:
pub struct Message {
    pub from_me: bool,
    pub sender_name: String,
    pub content: String,
    pub timestamp: String,
    pub status: DeliveryStatus,
}
```

- [ ] **Step 4: Fix all `Message` construction sites**

There are four places that create `Message` structs. Add `status: DeliveryStatus::None` to each:

**Site 1** — `handle_incoming_message` (line 1054):
```rust
let message = Message {
    from_me: false,
    sender_name,
    content: content.clone(),
    timestamp: utc_time_now(),
    status: DeliveryStatus::None,
};
```

**Site 2** — `handle_input_key` (line 1271):
```rust
let message = Message {
    from_me: true,
    sender_name: "You".to_string(),
    content: text,
    timestamp: utc_time_now(),
    status: DeliveryStatus::None, // temporary — will become Sending in Task 5
};
```

**Site 3** — `load_conversation_messages` history loading (line 1345):
```rust
cache.push_back(Message {
    from_me: is_sent,
    sender_name: if is_sent {
        "You".to_string()
    } else {
        sender_name.clone()
    },
    content,
    timestamp: utc_time_now(), // existing code uses timestamp formatting
    status: DeliveryStatus::None,
});
```

Check this site carefully — the actual timestamp formatting may differ. Match the existing code exactly, only adding the `status` field.

- [ ] **Step 5: Add `MessageSource` enum**

After `DeliveryStatus`:

```rust
/// Source of an incoming message (for logging/debugging).
#[derive(Debug, Clone, Copy)]
pub enum MessageSource {
    Coordinator,
    EmbeddedNode,
}
```

- [ ] **Step 6: Add `Action` enum**

After `MessageSource`:

```rust
/// All events that can affect application state.
///
/// This is the single integration point for the TUI. Background tasks,
/// UI events, and spawned I/O all communicate through this type.
pub enum Action {
    /// Keyboard input
    Key(KeyEvent),
    /// Periodic tick (drives UI refresh)
    Tick,
    /// Terminal resize
    Resize(u16, u16),

    /// A spawned send task completed
    SendComplete {
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
```

- [ ] **Step 7: Add `TieredDeliveryPhase` to imports**

Add to the existing `use reme_outbox` import line:

```rust
use reme_outbox::{OutboxConfig, TieredDeliveryPhase, TransportRetryPolicy};
```

`TieredDeliveryPhase` may already be imported — check the existing imports. If it is, skip this step.

- [ ] **Step 8: Verify it compiles**

Run: `cargo check -p client`
Expected: compiles with no errors. All existing code works because `DeliveryStatus::None` is added everywhere.

- [ ] **Step 9: Commit**

```bash
git add apps/client/src/tui/app.rs
git commit -m "refactor(tui): add Action enum, DeliveryStatus, and MessageSource types

Pure type additions with no behavior changes. All Message construction
sites now include status: DeliveryStatus::None."
```

---

## Task 3: Add action channel to App struct and spawn_background_tasks

Wire up the `action_tx`/`action_rx` channel on App and create the `spawn_background_tasks` method that spawns all background drainer tasks.

**Files:**
- Modify: `apps/client/src/tui/app.rs` (App struct fields, `new()`, new `spawn_background_tasks()`)

- [ ] **Step 1: Add action channel fields to App struct**

In the `App` struct (around line 304), add these fields:

```rust
/// Action sender — cloned into background tasks for result delivery.
action_tx: mpsc::UnboundedSender<Action>,
/// Action receiver — drained in the main loop.
action_rx: mpsc::UnboundedReceiver<Action>,
/// Monotonic counter for correlating send results to optimistic messages.
next_send_id: u64,
```

- [ ] **Step 2: Initialize action channel in `App::new()`**

In `App::new()`, before constructing the `App` struct literal, add:

```rust
let (action_tx, action_rx) = mpsc::unbounded_channel();
```

And include the fields in the struct literal:

```rust
action_tx,
action_rx,
next_send_id: 0,
```

- [ ] **Step 3: Create `spawn_background_tasks` method**

Add this method to `impl App<'_>`:

```rust
/// Spawn all background tasks that feed results into the action channel.
///
/// This moves `coordinator_events` and `node_event_rx` into spawned tasks,
/// so they must be taken from `self` before spawning (use `Option::take`).
fn spawn_background_tasks(&mut self) {
    // --- Coordinator event drainer ---
    let client = self.client.clone();
    let tx = self.action_tx.clone();
    let mut coordinator_events = std::mem::replace(
        &mut self.coordinator_events,
        // Replace with a dummy channel that never receives
        mpsc::unbounded_channel().1,
    );
    tokio::spawn(async move {
        while let Some(event) = coordinator_events.recv().await {
            if let TransportEvent::Message(envelope) = event {
                let result = client.process_message(&envelope).await;
                if tx.send(Action::MessageProcessed {
                    result: result.map(|m| m).map_err(|e| e.to_string()),
                    source: MessageSource::Coordinator,
                }).is_err() {
                    break; // receiver dropped
                }
            }
        }
    });

    // --- Node event drainer ---
    if let Some(mut node_rx) = self.node_event_rx.take() {
        let client = self.client.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            while let Some(event) = node_rx.recv().await {
                match event {
                    NodeEvent::MessageReceived(envelope) => {
                        debug!("Received message from embedded node");
                        let result = client.process_message(&envelope).await;
                        if tx.send(Action::MessageProcessed {
                            result: result.map_err(|e| e.to_string()),
                            source: MessageSource::EmbeddedNode,
                        }).is_err() {
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
            if tx.send(Action::OutboxTick(result.map_err(|e| e.to_string()))).is_err() {
                break;
            }
        }
    });
}
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check -p client`
Expected: compiles. The `spawn_background_tasks` method is not called yet — that happens in Task 4.

- [ ] **Step 5: Commit**

```bash
git add apps/client/src/tui/app.rs
git commit -m "refactor(tui): add action channel and spawn_background_tasks

Wire up UnboundedSender/Receiver for Action on App. Background drainer
tasks for coordinator events, node events, and outbox tick now feed
results through the unified action channel."
```

---

## Task 4: Rewrite main loop with tokio::select! and sync update()

This is the core structural change. Replace the existing `run()` loop with the `select!`-based pattern and move all event handling into a sync `update()` method.

**Files:**
- Modify: `apps/client/src/tui/app.rs` (`run()` method, new `update()` method)

- [ ] **Step 1: Create the sync `update()` method**

Add a new method to `impl App<'_>`. This is the handler for all action variants. Start with the non-I/O actions only — send and upstream changes come in later tasks.

```rust
/// Process a single action. This method is synchronous — it never awaits.
///
/// All network I/O is kicked off via `tokio::spawn`, never inline.
/// This is the key structural invariant that prevents rendering lag.
fn update(&mut self, action: Action) {
    match action {
        Action::Key(key_event) => {
            if let Err(e) = self.handle_key_event(key_event) {
                self.status = format!("Error: {e}");
            }
        }
        Action::Tick => {} // UI refresh happens after update
        Action::Resize(_, _) => {} // ratatui handles resize on next draw

        Action::SendComplete { send_id: _, result } => {
            // Update status bar only for now. Task 5 adds send_id-based
            // lookup to update the specific optimistic message.
            self.status = match &result {
                Ok(phase) => format_delivery_status(phase),
                Err(e) => format!("Send failed: {e}"),
            };
        }

        Action::MessageProcessed { result, source } => {
            let source_name = match source {
                MessageSource::Coordinator => "coordinator",
                MessageSource::EmbeddedNode => "embedded node",
            };
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
                    warn!("Failed to process {} message: {}", source_name, e);
                    self.status = format!("Message decrypt failed: {e}");
                }
            }
        }

        Action::OutboxTick(result) => {
            match result {
                Ok((retried, maintenance, expired)) => {
                    if retried > 0 || maintenance > 0 || expired > 0 {
                        info!(retried, maintenance, expired, "Outbox tick completed");
                    } else {
                        debug!("Outbox tick: no pending messages");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Outbox tick failed");
                }
            }
        }

        Action::NodeError(e) => {
            self.status = format!("Node error: {e}");
        }

        Action::UpstreamAdded { url, transport_type, result } => {
            match result {
                Ok(()) => {
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
    }
}
```

- [ ] **Step 2: Make `handle_key_event` synchronous**

Change `handle_key_event` from `async fn` to `fn`. This requires:

a. Change signature:
```rust
// Before:
async fn handle_key_event(&mut self, key: KeyEvent) -> AppResult<()> {

// After:
fn handle_key_event(&mut self, key: KeyEvent) -> AppResult<()> {
```

b. Change `handle_conversation_key` call (line 1197):
```rust
// Before:
Focus::Conversations => self.handle_conversation_key(key).await?,

// After:
Focus::Conversations => self.handle_conversation_key(key)?,
```

c. Change `handle_input_key` call (line 1199):
```rust
// Before:
Focus::Input => self.handle_input_key(key).await?,

// After:
Focus::Input => self.handle_input_key(key)?,
```

d. Change `handle_add_upstream_popup_key_event` call (line 1091):
```rust
// Before:
return self.handle_add_upstream_popup_key_event(key).await;

// After:
return self.handle_add_upstream_popup_key_event(key);
```

- [ ] **Step 3: Make `handle_conversation_key` synchronous**

```rust
// Before:
#[allow(clippy::unused_async)]
async fn handle_conversation_key(&mut self, key: KeyEvent) -> AppResult<()> {

// After:
fn handle_conversation_key(&mut self, key: KeyEvent) -> AppResult<()> {
```

Remove the `#[allow(clippy::unused_async)]` attribute — it's no longer needed.

- [ ] **Step 4: Make `handle_input_key` synchronous (stub send)**

Change the method to synchronous. The send logic will be properly implemented in Task 5 — for now, just keep the existing inline send but note it needs to change:

```rust
// Before:
async fn handle_input_key(&mut self, key: KeyEvent) -> AppResult<()> {

// After:
fn handle_input_key(&mut self, key: KeyEvent) -> AppResult<()> {
```

**Temporarily** replace the `send_text_tiered` block with a spawned task using the new prepare/submit split:

```rust
if key.code == KeyCode::Enter {
    let text = self.input.lines().join("\n");
    if !text.trim().is_empty() {
        if let Some(conv) = self.conversations.get(self.selected_conversation) {
            let public_id = conv.public_id;
            let content = Content::Text(reme_message::TextContent {
                body: text.clone(),
            });

            match self.client.prepare_message(&public_id, content, false) {
                Ok(prepared) => {
                    let message = Message {
                        from_me: true,
                        sender_name: "You".to_string(),
                        content: text,
                        timestamp: utc_time_now(),
                        status: DeliveryStatus::Sending,
                    };

                    self.cache_message(public_id, message.clone());
                    self.messages.push(message);
                    self.input = TextArea::default();
                    self.input.set_placeholder_text("Type a message...");
                    self.status = "Sending...".to_string();

                    let client = self.client.clone();
                    let tx = self.action_tx.clone();
                    let send_id = self.next_send_id;
                    self.next_send_id += 1;
                    tokio::spawn(async move {
                        let result = client.submit_prepared_tiered(&prepared).await;
                        let _ = tx.send(Action::SendComplete {
                            send_id,
                            result: result
                                .map_err(|e| e.to_string()),
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
```

- [ ] **Step 5: Make `handle_add_upstream_popup_key_event` synchronous**

```rust
// Before:
async fn handle_add_upstream_popup_key_event(&mut self, key: KeyEvent) -> AppResult<()> {

// After:
fn handle_add_upstream_popup_key_event(&mut self, key: KeyEvent) -> AppResult<()> {
```

For the MQTT connect path (line 1607), spawn it:

```rust
// Before (in the KeyCode::Enter arm):
let result = self.add_upstream(&url).await;
match result { ... }

// After:
let transport_type = self.add_upstream_popup.transport_type;
match transport_type {
    UpstreamType::Http => {
        let result = self.add_upstream_http(&url);
        match result {
            Ok(()) => {
                self.show_add_upstream_popup = false;
                self.add_upstream_popup.reset();
                self.status = format!("Added HTTP upstream: {}", url);
            }
            Err(e) => {
                self.add_upstream_popup.error = Some(e);
            }
        }
    }
    UpstreamType::Mqtt => {
        let url_owned = url.to_string();
        let coordinator = self.coordinator.clone();
        let registry = self.registry.clone();
        let tier = self.add_upstream_popup.tier;
        let tx = self.action_tx.clone();
        self.status = "Connecting to MQTT...".to_string();
        tokio::spawn(async move {
            let mqtt_config = MqttTargetConfig::new(&url_owned);
            let result = match MqttTarget::connect(mqtt_config).await {
                Ok(target) => {
                    let id = target.id().clone();
                    if let Some(pool) = registry.mqtt_pool() {
                        pool.add_target(target);
                        registry.register_ephemeral(id, None, tier);
                        info!(url = %url_owned, "Added ephemeral MQTT upstream");
                        Ok(())
                    } else {
                        Err("MQTT pool not initialized".to_string())
                    }
                }
                Err(e) => Err(format!("Failed to connect to MQTT broker: {e}")),
            };
            let _ = tx.send(Action::UpstreamAdded {
                url: url_owned,
                transport_type: UpstreamType::Mqtt,
                result,
            });
        });
    }
}
```

Split `add_upstream` into `add_upstream_http` (sync) — extract the HTTP branch of the existing method:

```rust
/// Add an HTTP upstream transport at runtime (synchronous — no network I/O).
fn add_upstream_http(&mut self, url: &str) -> Result<(), String> {
    let tier = self.add_upstream_popup.tier;
    let config =
        HttpTargetConfig::ephemeral(url).with_request_timeout(Duration::from_secs(10));
    let target = HttpTarget::new(config)
        .map_err(|e| format!("Failed to create HTTP transport: {e}"))?;
    let id = target.id().clone();
    self.coordinator.add_http_target(target);
    self.registry.register_ephemeral(id, None, tier);
    info!(url = %url, "Added ephemeral HTTP upstream");
    Ok(())
}
```

Remove the old `async fn add_upstream` method entirely.

- [ ] **Step 6: Remove `process_incoming_envelope` method**

This method is no longer needed — its logic is now in the `Action::MessageProcessed` handler in `update()` and the background drainer task in `spawn_background_tasks`. Delete the entire method (lines ~992-1011).

- [ ] **Step 7: Rewrite `run()` method**

Replace the entire `run()` method body:

```rust
pub async fn run(&mut self, terminal: &mut Terminal<impl Backend>) -> AppResult<()> {
    let mut event_handler = EventHandler::new(100);
    self.spawn_background_tasks();

    while self.running {
        // Wait for next UI event or background action (whichever comes first)
        tokio::select! {
            event = event_handler.next() => {
                let action = match event? {
                    Event::Key(k) => Action::Key(k),
                    Event::Tick => Action::Tick,
                    Event::Resize(w, h) => Action::Resize(w, h),
                };
                self.update(action);
            }
            Some(action) = self.action_rx.recv() => {
                self.update(action);
            }
        }

        // Drain any additional queued actions (non-blocking)
        while let Ok(action) = self.action_rx.try_recv() {
            self.update(action);
        }

        // Render after processing all pending state changes
        terminal.draw(|frame| ui::render(frame, self))?;
    }

    // Graceful shutdown
    self.shutdown_discovery().await;
    self.shutdown_embedded_node().await;

    Ok(())
}
```

- [ ] **Step 8: Verify it compiles**

Run: `cargo check -p client`
Expected: compiles. Fix any remaining type errors from the async→sync conversions.

- [ ] **Step 9: Run clippy**

Run: `cargo clippy -p client`
Expected: no errors. Fix any warnings about unused imports (e.g., old `Instant` import if it was there for outbox tick timing).

- [ ] **Step 10: Commit**

```bash
git add apps/client/src/tui/app.rs
git commit -m "refactor(tui): rewrite event loop with tokio::select! and sync update()

Replace inline async event handlers with Action-based pattern. All
network I/O now runs in spawned tasks. The update() method is
synchronous — structurally impossible to block rendering.

Fixes #99 (send_text_tiered blocks TUI).
Fixes #97 (tombstone send blocks TUI)."
```

---

## Task 5: Wire up send_id tracking for optimistic message updates

The `Action::SendComplete` handler in `update()` needs to find and update the optimistic message. Add send_id tracking.

**Files:**
- Modify: `apps/client/src/tui/app.rs` (Message struct, send tracking)

- [ ] **Step 1: Add `send_id` to Message struct**

```rust
pub struct Message {
    pub from_me: bool,
    pub sender_name: String,
    pub content: String,
    pub timestamp: String,
    pub status: DeliveryStatus,
    /// Monotonic ID for correlating with background send results. None for received messages.
    pub send_id: Option<u64>,
}
```

- [ ] **Step 2: Update all Message construction sites to add `send_id: None`**

There are four sites (same ones from Task 2 step 4). Add `send_id: None` to each.

The send site in `handle_input_key` (from Task 4 step 4) should use `Some(send_id)`:

```rust
let send_id = self.next_send_id;
self.next_send_id += 1;

let message = Message {
    from_me: true,
    sender_name: "You".to_string(),
    content: text,
    timestamp: utc_time_now(),
    status: DeliveryStatus::Sending,
    send_id: Some(send_id),
};
```

- [ ] **Step 3: Implement send_id lookup in `Action::SendComplete` handler**

In the `update()` method, replace the `Action::SendComplete` arm:

```rust
Action::SendComplete { send_id, result } => {
    let status = match &result {
        Ok(phase) => DeliveryStatus::Sent(format_delivery_status(phase)),
        Err(e) => DeliveryStatus::Failed(e.clone()),
    };

    // Update status bar
    self.status = match &status {
        DeliveryStatus::Sent(s) => s.clone(),
        DeliveryStatus::Failed(e) => format!("Send failed: {e}"),
        _ => String::new(),
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
                return; // found it, done
            }
        }
    }
}
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check -p client`
Expected: compiles.

- [ ] **Step 5: Commit**

```bash
git add apps/client/src/tui/app.rs
git commit -m "feat(tui): wire up send_id tracking for optimistic message updates

SendComplete actions now find and update the matching optimistic
message in both visible messages and the per-contact cache."
```

---

## Task 6: Render DeliveryStatus in UI

Add visual indicators for message delivery status.

**Files:**
- Modify: `apps/client/src/tui/ui.rs` (message rendering loop)

- [ ] **Step 1: Read the current message rendering code**

Read `apps/client/src/tui/ui.rs` around lines 148-177 to understand the exact rendering structure.

- [ ] **Step 2: Add delivery status rendering after message content**

After the message content line (line 173: `lines.push(Line::from(Span::styled(&msg.content, content_style)));`), add status rendering for sent messages:

```rust
// Message content
let content_style = Style::default().fg(Color::White);
lines.push(Line::from(Span::styled(&msg.content, content_style)));

// Delivery status indicator (sent messages only)
if msg.from_me {
    match &msg.status {
        DeliveryStatus::None => {}
        DeliveryStatus::Sending => {
            lines.push(Line::from(Span::styled(
                "  sending...",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )));
        }
        DeliveryStatus::Sent(phase) => {
            lines.push(Line::from(Span::styled(
                format!("  \u{2713} {phase}"),
                Style::default().fg(Color::DarkGray),
            )));
        }
        DeliveryStatus::Failed(err) => {
            lines.push(Line::from(Span::styled(
                format!("  ! Failed: {err}"),
                Style::default().fg(Color::Red),
            )));
        }
    }
}
```

- [ ] **Step 3: Add import for DeliveryStatus in ui.rs**

At the top of `ui.rs`, ensure `DeliveryStatus` is imported from the `app` module:

```rust
use super::app::{App, DeliveryStatus, Focus};
```

Check the existing imports and adjust — `App` and `Focus` may already be imported.

- [ ] **Step 4: Verify it compiles**

Run: `cargo check -p client`
Expected: compiles.

- [ ] **Step 5: Run full checks**

Run: `cargo clippy -p client && cargo test -p client`
Expected: clean clippy, tests pass (there are no tests currently but the binary should compile for test target).

- [ ] **Step 6: Commit**

```bash
git add apps/client/src/tui/ui.rs
git commit -m "feat(tui): render delivery status indicators on sent messages

Show 'sending...' (italic gray), checkmark + phase (gray), or
'! Failed: ...' (red) after sent message content."
```

---

## Task 7: Final verification and cleanup

Run all checks, clean up any dead code, verify the full build.

**Files:**
- Modify: `apps/client/src/tui/app.rs` (cleanup only)

- [ ] **Step 1: Remove dead imports**

Check for unused imports after the refactor. Common candidates:
- `std::time::Instant` (was used for `last_outbox_tick`)
- Any direct `TransportEvent` import if it's only used in the spawned task now

Run: `cargo clippy -p client`
Fix all warnings.

- [ ] **Step 2: Remove old `add_upstream` method**

Verify the old `async fn add_upstream` is fully removed (should have been done in Task 4 step 5). If any references remain, remove them.

- [ ] **Step 3: Full workspace build**

Run: `cargo build --workspace`
Expected: clean build.

- [ ] **Step 4: Full workspace clippy**

Run: `cargo clippy --workspace`
Expected: no new warnings.

- [ ] **Step 5: Full workspace tests**

Run: `cargo test --workspace`
Expected: all tests pass.

- [ ] **Step 6: Commit cleanup if any changes were needed**

```bash
git add -A
git commit -m "chore(tui): remove dead code after event loop refactor"
```

---

## Verification Checklist

After all tasks are complete, verify these behaviors manually:

- [ ] `reme` launches and the TUI renders normally
- [ ] Sending a message shows it immediately with "sending..." status
- [ ] Status updates to delivery phase or failure after send completes
- [ ] TUI remains responsive during sends (can type, scroll, switch conversations)
- [ ] Incoming messages still appear in real-time
- [ ] Add HTTP upstream works (instant)
- [ ] Add MQTT upstream shows "Connecting..." then result
- [ ] Ctrl+Q/Esc exits cleanly without panics
- [ ] Outbox retries still work (check logs)
