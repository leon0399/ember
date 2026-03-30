# Agents instruction for `ember`

This file provides guidance to AI coding agents when working with code in this repository.

## Project Overview

Ember Messenger is an outage-resilient, end-to-end encrypted messaging system built in Rust. It uses a hybrid transport architecture (HTTP mailboxes, future: LoRa/Meshtastic, BLE) with Session V1-style stateless encryption and XEdDSA signatures for secure 1:1 messaging.

## Build Commands

```bash
cargo build                                               # Build all crates and apps
cargo build --release                                     # Build release binaries
cargo test                                                # Run all tests
cargo test -p ember-core                                   # Run tests for a specific crate
cargo test -p ember-core test_two_client_messaging         # Run a single test
cargo test -p ember-core --test integration                # Run integration tests only
cargo fmt --all -- --check                                # Check formatting
cargo clippy --all-targets --all-features -- -D warnings  # Lint
```

## Running the Applications

```bash
# Start a mailbox node (default: http://127.0.0.1:3000)
cargo run --bin node

# Start the CLI client
cargo run --bin client

# With custom config
cargo run --bin node -- --port 3001
cargo run --bin client -- --node-url http://localhost:3001
```

## Architecture

### Crate Structure

```
crates/
├── ember-identity    # Identity (X25519/XEdDSA), PublicID (32-byte address)
├── ember-encryption  # MIK-based stateless encryption (Session V1-style)
├── ember-message     # Wire formats: OuterEnvelope, InnerEnvelope, Tombstone, DAG
├── ember-transport   # Transport trait, HttpTransport, MqttTransport, TransportCoordinator
├── ember-storage     # SQLite persistence for contacts, messages
├── ember-outbox      # Tiered delivery, retry policies, delivery state tracking
├── ember-node-core   # Shared node/relay logic, embedded HTTP server
├── ember-config      # Layered configuration (CLI args > env vars > config file > defaults)
├── ember-discovery   # mDNS/LAN peer discovery (backend trait, TXT helpers, fake + mdns-sd backends)
└── ember-core        # High-level Client API orchestrating all above

apps/
├── node/            # Mailbox server (Axum, store-and-forward)
└── client/          # TUI client (ratatui) with embedded relay capability
```

### LAN Discovery

When `lan_discovery.enabled = true`, the client:

1. Creates an mDNS-SD backend browsing for `_ember._tcp.local.` services
2. Advertises own presence if embedded HTTP server is bound (`embedded_node.http_bind`)
3. If `auto_direct_known_contacts = true` (default): spawns a discovery controller that matches peers by routing key against contacts, verifies identity via HTTP challenge-response, and registers verified peers as ephemeral HTTP targets (SEND-only, no FETCH)
4. If `auto_direct_known_contacts = false`: mDNS browsing/advertising runs but no peers are verified or registered

`max_peers` caps the tracked peer set (default: 256). `refresh_interval_secs` (default: 300) controls periodic re-verification of tracked peers; peers that fail verification twice consecutively are removed (ephemeral circuit breaker).

### Key Data Flow

1. **Sender**: `Client::send_text()` → `encrypt_to_mik()` creates ephemeral keypair, ECDH, encrypts `InnerEnvelope` → wrap in `OuterEnvelope` → `Transport::submit_message()`
2. **Mailbox Node**: stores envelope keyed by `routing_key` (truncated blake3 hash of recipient's PublicID)
3. **Receiver**: `Client::fetch_messages()` → `decrypt_with_mik()` using MIK private key → return `ReceivedMessage`

### Crypto Summary

- **MIK (Master Identity Key)**: Single X25519 key for both ECDH and XEdDSA signatures
- **Encryption**: Stateless sealed box — ephemeral X25519 + BLAKE3 KDF + ChaCha20Poly1305
- **Signatures**: XEdDSA (X25519 key used for Ed25519-compatible signatures)
- **No prekeys, no session state**: Zero-RTT first message, maximum DTN tolerance
- **Serialization**: postcard (serde) for wire formats

### Tombstones

After receiving a message, clients send tombstones for cache clearing and delivery receipts:

- **V2 (current)**: ack_secret-based authorization (derived from ECDH shared secret)
- Includes optional encrypted receipt for sender
- Enables cache clearing on relay nodes and delivery/read receipts

### Tiered Delivery

Messages flow through three delivery tiers with configurable quorum requirements:

- **Tier 1 (Direct)**: Race all ephemeral targets (mDNS, DHT, Iroh), exit on ANY success
- **Tier 2 (Quorum)**: Broadcast to all stable targets (HTTP, MQTT), require configurable quorum
- **Tier 3 (BestEffort)**: Fire-and-forget (future: BLE broadcast, LoRa/Meshtastic). BLE and LoRa can serve any tier depending on context — Direct (recipient discovered), relay (known peer), or BestEffort (blind broadcast). Meshtastic handles its own mesh retransmit; BLE relay uses the same model as LAN HTTP relay.

Three-phase state machine:

- **Phase 1 (Urgent)**: Aggressive retry with exponential backoff until quorum reached
- **Phase 2 (Distributed)**: Periodic maintenance refresh (every 4h) until recipient ACKs
- **Phase 3 (Confirmed)**: Cleanup after DAG acknowledgment or tombstone receipt

### Merkle DAG

Messages include DAG fields for ordering and gap detection:

- `prev_self`: ContentId of sender's previous message
- `observed_heads`: ContentIds of latest messages seen from peer(s)
- `epoch`: Increments on history clear
- `flags`: FLAG_DETACHED for constrained transports (LoRa, BLE)

## Configuration

Both node and client support layered config (CLI args > env vars > config file > defaults):

- Node config: `~/.config/ember/node.toml`
- Client config: `~/.config/ember/config.toml`
- Env prefix: `EMBER_NODE_*` / `EMBER_*`

### Transport Authentication

HTTP and MQTT transports both support username/password auth. Credential precedence: explicit config fields > URL-embedded > none. If only one of username/password is provided, credentials are ignored (lenient fallback).

## Testing Patterns

Integration tests spin up in-process nodes using `TestServer::start()` which binds to port 0:

```rust
let server = TestServer::start().await;
let transport = HttpTransport::new(server.url());
// ... test with real HTTP transport against ephemeral server
```

## Wire Format Notes

- `RoutingKey`: 16 bytes (first 16 bytes of blake3 hash of PublicID)
- `PublicID`: 32 bytes (X25519 public key, also used for XEdDSA signatures)
- `MessageID`: 16 bytes (UUID v4)
- `ContentId`: 8 bytes (truncated BLAKE3 hash for DAG references)
- `ephemeral_key`: 32 bytes (per-message X25519 public key in OuterEnvelope)
- `ack_hash`: 16 bytes (for tombstone V2 authorization)
- Version: `Version { major: 0, minor: 0 }`

## Project Phase

Research/prototype stage — no external users. Breaking changes and public API restructuring are encouraged when they improve the architecture.

## Key Documentation

- `WHITEPAPER.md` — Protocol specification (encryption, wire format, transport design)
- `ROADMAP.md` — Release timeline and feature planning (v0.4 → v1.0)
- `docs/threat-model.md` — Attack scenarios and mitigations
- `docs/tiered-delivery.md` — Three-tier delivery system design
- `docs/lan-discovery.md` — mDNS/LAN peer discovery design

## Security Model

- **No forward secrecy (V1)**: MIK compromise exposes all messages. Acceptable for DTN-first design.
- **DTN tolerance**: No prekeys, no session state — message loss/reordering has no impact.
- **Sender authentication**: XEdDSA signature binds sender identity to message content.
- **Threat model**: See `docs/threat-model.md` for attack scenarios and mitigations. Review and update when adding new transport mechanisms or discovery features.

## Code Style

Adapted from [epage's Rust Style Guide](https://epage.github.io/dev/rust-style/). These are review guidelines, not hard rules — use judgement when they conflict.

### File & Module Layout

- **Type then impl** (M-TYPE-ASSOC): Place a type definition immediately before its `impl` block.
- **Inherent impl before trait impls** (M-ASSOC-TRAIT): `impl Foo {}` comes before `impl Display for Foo {}`.
- **Public before private** (M-PUB-PRIV): Public items precede private ones in modules, structs, and impl blocks.
- **Caller before callee** (M-CALLER-CALLEE): Place callers first; the weaker the callee's abstraction, the closer it should follow its caller.
- **Central item first** (M-ITEM-TOC): The titular type/function for a module appears first — it acts as a table of contents.
- **`lib.rs` / `mod.rs` = re-exports only** (P-DIR-MOD): Keep definitions in topically named files.

### Function Structure

- **Group related logic** (F-GROUP): Use blank lines to separate logical "paragraphs".
- **Pure combinators** (F-COMBINATOR): No side-effects in `map`/`filter`/`fold` closures. Use `for` loops for mutations. Enforced via `clippy.toml` (`disallowed-methods`).
- **Blocks reflect business logic** (F-VISUAL): Use `if`/`else` or `match` for mutually exclusive business paths. Reserve early returns for bookkeeping. Use combinators for transformations.

### Visibility

Use only three levels: private (default), `pub(crate)`, `pub`. Avoid `pub(super)`.

## Development Workflow

When writing or reviewing Rust code, consult these skills:

- `/rust-best-practices` — borrowing vs cloning, error handling, clippy, testing conventions
- `/rust-async-patterns` — Tokio patterns, CancellationToken, channels, graceful shutdown

When creating git commits in this repository:

- Use Conventional Commits for commit subjects (for example `feat(contact): add trust levels` or `fix(discovery): avoid blocking storage write`)
- Keep the subject line imperative and scoped when the affected area is clear
- Preserve any required trailers such as `Co-Authored-By`

## Quality gates

Hard rules:

- No `.unwrap()` or `.expect()` in library crates
- No `todo!()`, `unimplemented!()`, `dbg!()` in merged code
- No `println!()` / `eprintln!()` in library crates (use tracing)
- Cognitive complexity per function ≤ 15
- Function body ≤ 80 lines
- Function arguments ≤ 5
- All dependencies must pass cargo-deny policy

## Pre-commit Checklist

- [ ] `cargo fmt --all -- --check` — formatting
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` — linting
- [ ] `cargo test --workspace --all-features --all-targets` — all tests pass
- [ ] No new `unwrap()` in library crates (use proper error handling)
