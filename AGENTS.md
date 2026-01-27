# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Resilient Messenger (reme) is an outage-resilient, end-to-end encrypted messaging system built in Rust. It uses a hybrid transport architecture (HTTP mailboxes, future: LoRa/Meshtastic, BLE) with Session V1-style stateless encryption and XEdDSA signatures for secure 1:1 messaging.

## Build Commands

```bash
# Build all crates and apps
cargo build

# Build release binaries
cargo build --release

# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p reme-core

# Run a single test
cargo test -p reme-core test_two_client_messaging

# Run integration tests only
cargo test -p reme-core --test integration
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
└── reme-core        # High-level Client API orchestrating all above

apps/
├── node/            # Mailbox server (Axum, store-and-forward)
└── client/          # TUI client (ratatui) with embedded relay capability
```

### Key Data Flow

1. **Sender**: `Client::send_text()` → `encrypt_to_mik()` creates ephemeral keypair, ECDH, encrypts `InnerEnvelope` → wrap in `OuterEnvelope` → `Transport::submit_message()`
2. **Mailbox Node**: stores envelope keyed by `routing_key` (truncated blake3 hash of recipient's PublicID)
3. **Receiver**: `Client::fetch_messages()` → `decrypt_with_mik()` using MIK private key → return `ReceivedMessage`

### Cryptographic Primitives

- **Identity (MIK)**: Single X25519 key used for both ECDH and XEdDSA signatures
- **Encryption**: Session V1-style stateless sealed box:
  1. Generate ephemeral X25519 keypair per message
  2. ECDH: `shared_secret = X25519(ephemeral_secret, recipient_MIK)`
  3. Key derivation: `encryption_key = BLAKE3_KDF(ephemeral_pub || recipient_pub || shared_secret)`
  4. Encrypt: ChaCha20Poly1305 with nonce derived from MessageID + recipient pubkey
  5. Sign: XEdDSA signature over serialized InnerEnvelope || MessageID (sign-all-bytes)
- **No prekeys, no session state**: Zero-RTT first message, maximum DTN tolerance
- **Serialization**: bincode v2 for wire formats

### XEdDSA

XEdDSA (Signal's scheme) allows using a single X25519 key for both:
- **Diffie-Hellman key exchange** (native X25519)
- **Digital signatures** (via birational map to Ed25519)

This means the MIK (Master Identity Key) serves as both encryption and signing key, simplifying key management while maintaining security.

### Message Flow (Stateless)

Each message is independently encrypted - no session establishment needed:

```
Alice → Bob:
1. Alice generates ephemeral keypair (e, E)
2. Alice computes shared_secret = X25519(e, Bob_MIK)
3. Alice derives encryption_key from shared_secret + both public keys
4. Alice signs InnerEnvelope with her MIK (XEdDSA)
5. Alice encrypts (InnerEnvelope || signature) with encryption_key
6. Alice sends OuterEnvelope{routing_key, ephemeral_key=E, ciphertext, ...}

Bob receives:
1. Bob computes shared_secret = X25519(Bob_MIK_private, E)
2. Bob derives same encryption_key
3. Bob decrypts to get InnerEnvelope || signature
4. Bob verifies XEdDSA signature using Alice's MIK from InnerEnvelope.from
```

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

Both HTTP and MQTT transports support username/password authentication with consistent precedence rules.

**HTTP Transport:**
- Authentication via Basic Auth
- Credentials in config fields: `username` and `password`
- Or URL-embedded: `http://user:pass@example.com:3000`
- Precedence: Explicit config fields > URL-embedded > none

**MQTT Transport:**
- Authentication via MQTT CONNECT packet
- Credentials in config fields: `username` and `password`
- Or URL-embedded: `mqtt://user:pass@broker.example.com:1883`
- Precedence: Explicit config fields > URL-embedded > none

**Configuration example:**

```toml
# Explicit credentials (highest precedence)
[[mqtt_peers]]
label = "Authenticated MQTT Broker"
url = "mqtts://broker.example.com:8883"
username = "alice"
password = "secret123"

# URL-embedded credentials (fallback)
[[mqtt_peers]]
label = "URL Auth MQTT"
url = "mqtt://bob:pass456@broker.local:1883"

# Mixed: explicit username overrides URL username
[[mqtt_peers]]
url = "mqtt://bob:wrongpass@broker.local:1883"
username = "alice"      # Overrides "bob" from URL
password = "correct789" # Overrides "wrongpass" from URL
```

**Incomplete credentials error:** If only `username` or only `password` is provided (either explicitly or from URL), the configuration will fail validation with a clear error message.

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

## Security Model

- **No forward secrecy (V1)**: MIK compromise exposes all messages. Acceptable for DTN-first design.
- **Future (V2)**: Optional rotating session keys for epoch-based forward secrecy
- **DTN tolerance**: #1 ranked approach - no prekeys, no session state, message loss/reordering has no impact
- **Sender authentication**: XEdDSA signature binds sender identity to message content

## References

- [Session Protocol V1](https://getsession.org/session-protocol-technical-information) - Inspiration for stateless approach
- [XEdDSA Specification](https://signal.org/docs/specifications/xeddsa/) - Signature scheme using X25519 keys
- [Noise Protocol Framework](http://noiseprotocol.org/noise.html) - Basis for v1.0 forward secrecy (Async Noise XX)

## Why Not X3DH/Double Ratchet?

X3DH and Double Ratchet require prekey servers and synchronized session state. In DTN scenarios:
- **Prekey servers unreachable** during outages
- **Message loss causes state divergence** (skipped message keys accumulate unboundedly)
- **Reordering breaks ratchet** assumptions

Reme's stateless MIK approach trades per-message forward secrecy for DTN tolerance. v1.0 adds optional Noise XX sessions for forward secrecy when connectivity allows.
