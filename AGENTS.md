# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Project Overview

Resilient Messenger (reme) is an outage-resilient, end-to-end encrypted messaging system built in Rust. It uses a hybrid transport architecture (HTTP mailboxes, future: LoRa/Meshtastic, BLE) with Session V1-style stateless encryption and XEdDSA signatures for secure 1:1 messaging.

## Build Commands

```bash
cargo build                                      # Build all crates and apps
cargo build --release                            # Build release binaries
cargo test                                       # Run all tests
cargo test -p reme-core                          # Run tests for a specific crate
cargo test -p reme-core test_two_client_messaging # Run a single test
cargo test -p reme-core --test integration       # Run integration tests only
cargo fmt --all -- --check                       # Check formatting
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
├── reme-identity    # Identity (X25519/XEdDSA), PublicID (32-byte address)
├── reme-encryption  # MIK-based stateless encryption (Session V1-style)
├── reme-message     # Wire formats: OuterEnvelope, InnerEnvelope, Tombstone, DAG
├── reme-transport   # Transport trait, HttpTransport, MqttTransport, TransportCoordinator
├── reme-storage     # SQLite persistence for contacts, messages
├── reme-outbox      # Tiered delivery, retry policies, delivery state tracking
├── reme-node-core   # Shared node/relay logic, embedded HTTP server
├── reme-config      # Layered configuration (CLI args > env vars > config file > defaults)
└── reme-core        # High-level Client API orchestrating all above

apps/
├── node/            # Mailbox server (Axum, store-and-forward)
└── client/          # TUI client (ratatui) with embedded relay capability
```

### Key Data Flow

1. **Sender**: `Client::send_text()` → `encrypt_to_mik()` creates ephemeral keypair, ECDH, encrypts `InnerEnvelope` → wrap in `OuterEnvelope` → `Transport::submit_message()`
2. **Mailbox Node**: stores envelope keyed by `routing_key` (truncated blake3 hash of recipient's PublicID)
3. **Receiver**: `Client::fetch_messages()` → `decrypt_with_mik()` using MIK private key → return `ReceivedMessage`

### Crypto Summary

- **MIK (Master Identity Key)**: Single X25519 key for both ECDH and XEdDSA signatures
- **Encryption**: Stateless sealed box — ephemeral X25519 + BLAKE3 KDF + ChaCha20Poly1305
- **Signatures**: XEdDSA (X25519 key used for Ed25519-compatible signatures)
- **No prekeys, no session state**: Zero-RTT first message, maximum DTN tolerance
- **Serialization**: bincode v2 for wire formats

### Tombstones

After receiving a message, clients send tombstones for cache clearing and delivery receipts:
- **V2 (current)**: ack_secret-based authorization (derived from ECDH shared secret)
- Includes optional encrypted receipt for sender
- Enables cache clearing on relay nodes and delivery/read receipts

### Tiered Delivery

Messages flow through three delivery tiers with configurable quorum requirements:
- **Tier 1 (Direct)**: Race all ephemeral targets (mDNS, DHT, Iroh), exit on ANY success
- **Tier 2 (Quorum)**: Broadcast to all stable targets (HTTP, MQTT), require configurable quorum
- **Tier 3 (BestEffort)**: Fire-and-forget (future: BLE mesh, LoRa/Meshtastic)

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

- Node config: `~/.config/reme/node.toml`
- Client config: `~/.config/reme/config.toml`
- Env prefix: `REME_NODE_*` / `REME_*`

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

## Security Model

- **No forward secrecy (V1)**: MIK compromise exposes all messages. Acceptable for DTN-first design.
- **DTN tolerance**: No prekeys, no session state — message loss/reordering has no impact.
- **Sender authentication**: XEdDSA signature binds sender identity to message content.

## Pre-commit Checklist

- [ ] `cargo fmt --all -- --check` — formatting
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` — linting
- [ ] `cargo test` — all tests pass
- [ ] No new `unwrap()` in library crates (use proper error handling)
