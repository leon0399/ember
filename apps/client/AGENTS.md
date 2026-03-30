# Client (TUI Messenger)

Terminal-based messenger with Telegram/WhatsApp-style interface. Built on ratatui + crossterm. Includes an embedded HTTP relay for LAN P2P messaging.

## CLI Structure

The binary uses clap subcommands. Bare `ember` defaults to the TUI.

```
ember [OPTIONS] [SUBCOMMAND]

Global options (available to all subcommands):
  -d, --data-dir <PATH>    Data directory (env: EMBER_DATA_DIR)
  -c, --config <PATH>      Config file path (env: EMBER_CONFIG)
  -l, --log-level <LEVEL>  Log level (env: EMBER_LOG_LEVEL)

Subcommands:
  tui       Launch the interactive TUI (default when no subcommand)
  export    Export pending messages to a .ember bundle file (stub)
  import    Import messages from a .ember bundle file (stub)
```

TUI-specific flags (`--http-url`, `--mqtt-url`, `--outbox-*`, `--embedded-*`) are only available under the `tui` subcommand.

### Key types in `config.rs`

- `Cli` — top-level parser with `Option<Commands>` and global args
- `Commands` — enum: `Tui(TuiArgs)`, `Export(ExportArgs)`, `Import(ImportArgs)`
- `TuiArgs` — transport URLs, outbox tuning, embedded node flags
- `load_config_from(cli, tui_args)` — config loading; pass `cli.tui_args()` for TUI path, `None` for non-TUI subcommands

## Running

```bash
cargo run --bin client                                                  # TUI with defaults
cargo run --bin client -- tui --http-url https://node:23003             # TUI with custom node
cargo run --bin client -- --data-dir data/clients/alice --config data/clients/alice/config.toml  # Named local instance
cargo run --bin client -- export out.ember                               # Export (stub)
cargo run --bin client -- import bundle.ember                            # Import (stub)
```

## Module Map

| File                      | Purpose                                                                            |
|---------------------------|------------------------------------------------------------------------------------|
| `main.rs`                 | Entry point, CLI parsing, subcommand dispatch                                      |
| `config.rs`               | `Cli`/`Commands`/`TuiArgs` structs, env vars (`EMBER_*`), TOML config, layered merge |
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
│  TUI (app)   │────▶│  ember-core Client │────▶│  Transports  │
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

`~/.config/ember/config.toml` — see `config.rs` module docs for full reference including peers, LAN discovery, embedded node.

Env prefix: `EMBER_*` (e.g., `EMBER_PEERS`).

## Non-obvious Patterns

- **Logging goes to file (TUI only)**: TUI occupies stdout, so tracing writes to `{data_dir}/client.log`. Non-TUI subcommands don't initialize logging yet (stubs). `RUST_LOG` env var overrides config level.
- **Embedded relay**: The client runs an Axum HTTP server (`tui/http_server.rs`) for receiving LAN P2P messages. Bound address from `embedded_node.http_bind` config.
- **Discovery controller**: When `lan_discovery.auto_direct_known_contacts = true`, discovered mDNS peers are matched against contacts by routing key, verified via challenge-response, and registered as ephemeral Direct-tier targets (SEND-only, no FETCH).
- **Ephemeral circuit breaker**: Peers failing identity verification twice consecutively are removed. `refresh_interval_secs` (default 300) controls re-verification.
- **Message cache cap**: `MAX_CACHED_MESSAGES_PER_CONTACT` (500) prevents unbounded memory growth per conversation.
- **Contact name limit**: `MAX_NAME_LENGTH` (64 chars) for display names.
- **Password input**: Uses `rpassword` for secure terminal input (not via TUI).
