# Client (TUI Messenger)

Terminal-based messenger with Telegram/WhatsApp-style interface. Built on ratatui + crossterm. Includes an embedded HTTP relay for LAN P2P messaging.

## Running

```bash
cargo run --bin client                                    # Default config
cargo run --bin client -- --http-url https://node:23003   # Custom node
cargo run --bin client -- --data-dir data/clients/alice --config data/clients/alice/config.toml  # Named local instance
```

## Module Map

| File                      | Purpose                                                                            |
|---------------------------|------------------------------------------------------------------------------------|
| `main.rs`                 | Entry point, config loading, log-to-file setup                                     |
| `config.rs`               | CLI args (clap), env vars (`REME_*`), TOML config, layered merge                   |
| `tui/app.rs`              | Main app state, event loop, keyboard handling                                      |
| `tui/ui.rs`               | Ratatui widget rendering (conversations, messages, popups)                         |
| `tui/event.rs`            | Crossterm event polling, background tick timer                                     |
| `tui/http_server.rs`      | Embedded Axum HTTP server for LAN P2P receive                                      |
| `tui/password.rs`         | Secure password input (rpassword)                                                  |
| `discovery/mod.rs`        | mDNS discovery backend initialization                                              |
| `discovery/controller.rs` | Discovery controller: peer matching, identity verification, transport registration |

## Architecture

```
┌──────────────┐     ┌───────────────────┐     ┌──────────────┐
│  TUI (app)   │────▶│  reme-core Client │────▶│  Transports  │
│  ratatui     │     │  (orchestrator)   │     │  HTTP / MQTT │
└──────────────┘     └───────────────────┘     └──────────────┘
       │                                              ▲
       ▼                                              │
┌──────────────┐     ┌───────────────────┐     ┌──────────────┐
│  Embedded    │     │  Discovery        │────▶│  LAN peers   │
│  HTTP server │     │  Controller       │     │  (ephemeral) │
└──────────────┘     └───────────────────┘     └──────────────┘
```

## Keyboard Shortcuts

| Key                 | Action                                           |
|---------------------|--------------------------------------------------|
| `Tab` / `Shift+Tab` | Switch panels (conversations → messages → input) |
| `j`/`k` or arrows   | Navigate lists                                   |
| `Enter`             | Select conversation / send message               |
| `Alt+A` / `F2`      | Add contact popup                                |
| `Alt+U` / `F4`      | Add upstream node popup                          |
| `Alt+V` / `F5`      | View contact details                             |
| `Alt+I` / `F3`      | Show own identity                                |
| `Alt+H`             | Show help                                        |
| `Ctrl+Q` / `Esc`    | Quit                                             |

## Config File

`~/.config/reme/config.toml` — see `config.rs` module docs for full reference including peers, LAN discovery, embedded node.

Env prefix: `REME_*` (e.g., `REME_PEERS`).

## Non-obvious Patterns

- **Logging goes to file**: TUI occupies stdout, so tracing writes to `{data_dir}/client.log`. `RUST_LOG` env var overrides config level.
- **Embedded relay**: The client runs an Axum HTTP server (`tui/http_server.rs`) for receiving LAN P2P messages. Bound address from `embedded_node.http_bind` config.
- **Discovery controller**: When `lan_discovery.auto_direct_known_contacts = true`, discovered mDNS peers are matched against contacts by routing key, verified via challenge-response, and registered as ephemeral Direct-tier targets (SEND-only, no FETCH).
- **Ephemeral circuit breaker**: Peers failing identity verification twice consecutively are removed. `refresh_interval_secs` (default 300) controls re-verification.
- **Message cache cap**: `MAX_CACHED_MESSAGES_PER_CONTACT` (500) prevents unbounded memory growth per conversation.
- **Contact name limit**: `MAX_NAME_LENGTH` (64 chars) for display names.
- **Password input**: Uses `rpassword` for secure terminal input (not via TUI).
