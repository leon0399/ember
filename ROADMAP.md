# Resilient Messenger Roadmap

**Current Version:** v0.3 (Tiered Delivery)  
**Target Version:** v1.0 (Production Ready)

---

## Vision

Build an outage-resilient, end-to-end encrypted messaging system that works when traditional infrastructure fails. Reme prioritizes resilience over convenience so people can communicate during network failures, infrastructure attacks, or censorship.

## Guiding principles

1. **Client-side resilience first**: Messages never disappear silently
2. **DTN tolerance**: No session state, independent message processing
3. **Transport agnostic**: Same encrypted payload across HTTP, BLE, mesh
4. **Cryptographic soundness**: Conservative primitives, defense in depth
5. **Privacy by design**: No IP leakage to DHTs, minimal metadata exposure

---

## Release timeline

```mermaid
flowchart LR
    subgraph "Direct transports"
        v03["v0.3 ✅<br/>Tiered Delivery"]
        v04["v0.4<br/>mDNS Discovery"]
        PC["Postcard<br/>(internal)"]
        v05["v0.5<br/>Sneakernet Export"]
        v06["v0.6<br/>LAN Relay"]
        v07["v0.7<br/>BLE Direct"]
        v08["v0.8<br/>Meshtastic Direct"]
    end

    subgraph "Bridge & relay"
        v09["v0.9<br/>Bridge to Quorum"]
        v010["v0.10<br/>Multi-Transport Relay"]
    end

    v10["v1.0<br/>Forward Secrecy"]

    v03 --> v04 --> PC --> v05 --> v06 --> v07 --> v08 --> v09 --> v010 --> v10
```

---

## Current status (v0.3)

### Core foundation

| Component            | Status     |
|----------------------|------------|
| **Cryptography**     | ✅ Complete |
| **Wire Protocol**    | ✅ Complete |
| **DAG Ordering**     | ✅ Complete |
| **Tiered Delivery**  | ✅ Complete |
| **HTTP Transport**   | ✅ Complete |
| **MQTT Transport**   | ✅ Complete |
| **Outbox**           | ✅ Complete |
| **Storage**          | ✅ Complete |
| **TUI Client**       | ✅ Complete |
| **Node Server**      | ✅ Complete |
| **Embedded Relay**   | ✅ Complete |
| **Receipt Signing**  | ✅ Complete |

**Test coverage:** 385 tests across workspace, all passing.

---

## v0.4: LAN discovery

Automatic peer discovery and verified P2P messaging on local networks.

### mDNS/Bonjour discovery

**Problem:** Manual peer configuration is tedious for LAN scenarios.

**Solution:**
- Advertise client presence via mDNS (`_reme._tcp.local`)
- TXT records: `id=<routing_key>`, `port=<http_port>`
- Background scanning for discovered peers
- Automatic registration as Direct tier targets

**Deliverables:**
- [x] `mdns` crate integration (`mdns-sd`)
- [x] Service advertisement on client startup
- [x] Background discovery task
- [x] Automatic transport registration
- [x] UI indication of discovered peers (LAN peer count in status bar)

### Node identity verification

**Problem:** mDNS discovers peers by IP, but we can't verify identity without pre-shared keys. DHCP reassignment could route messages to the wrong device.

**Solution:**
- Identity endpoint (`GET /api/v1/identity?challenge=<base64>`)
- Challenge-response protocol proves node controls claimed identity
- Background refresh detects IP reassignment (5 min default interval)
- Refresh on delivery failure or network change

**Deliverables:**
- [x] Identity endpoint on main node and embedded node
- [x] Challenge-response verification in discovery flow
- [x] Background identity refresh task
- [x] Refresh triggers (periodic, failure-based circuit breaker)
- [ ] Refresh trigger: network change detection
- [x] Configuration options for refresh interval (`refresh_interval_secs`)

**Success criteria:**
- Two clients on same LAN discover each other within 5 seconds
- Direct messages succeed without manual configuration
- Identity verification prevents messages to wrong device after DHCP change
- Handles network changes without crashing

---

## Internal: Postcard migration (Pre-v0.5)

Simplify serialization code and prepare for stable wire format.

### Migrate from Bincode to Postcard

**Problem:** Current bincode encoding requires manual `impl Encode/Decode` blocks, is Rust-specific, and has limited schema evolution capabilities. This creates maintenance burden and will complicate future cross-platform clients.

**Why now (before v0.5):**
- Sneakernet archive format should use the final encoding approach
- BLE/LoRa transports will build on this foundation
- Cleaner codebase for constrained transport development
- Still at PoC stage (version 0.0) with no deployed clients to break

**Why Postcard:**
| Feature | Bincode | Postcard |
|---------|---------|----------|
| Derive macros | `Encode, Decode` (bincode-specific) | `Serialize, Deserialize` (serde) |
| Manual impls | Required for custom types | Standard serde patterns |
| Wire format spec | Undocumented | [Documented](https://postcard.jamesmunns.com) |
| Size | Compact | Similar (varint encoding) |
| no_std support | Yes | Yes (designed for embedded) |
| Cross-language | Rust only | Serde ecosystem + spec |

**Deliverables:**
- [ ] Replace `bincode` with `postcard` in all crates
- [ ] Convert `#[derive(Encode, Decode)]` to `#[derive(Serialize, Deserialize)]`
- [ ] Remove manual `impl Encode/Decode` blocks (use serde attributes)
- [ ] Bump wire format version to 0.1
- [ ] Update CLAUDE.md and WHITEPAPER.md references
- [ ] Verify message sizes remain within LoRa MTU budget

**Success criteria:**
- All 385+ tests pass
- Wire format size delta < 5%
- No manual serialization impl blocks remaining

**Future:** Postcard learnings will help with v1.0 Protobuf design for cross-language schema with full backward/forward compatibility.

---

## v0.5: Sneakernet export

Air-gapped messaging via file transfer.

### Message archive export/import

**Problem:** Sometimes there's no network at all, not even BLE range. Need a way to physically transport encrypted messages between air-gapped systems.

**Solution:**
- Export pending outbox messages to encrypted archive file
- Import received archives and process as normal messages
- QR code generation for small messages (single text messages)
- Archive format reusable by future transports (BLE, LoRa)

**Deliverables:**
- [ ] Archive format specification (versioned, extensible)
- [ ] Export command in CLI (`reme export --to alice --file msg.reme`)
- [ ] Import command in CLI (`reme import msg.reme`)
- [ ] QR code generation for single messages
- [ ] QR code scanning (camera or image file)
- [ ] TUI integration for export/import flows

**Success criteria:**
- Round-trip export→USB→import works correctly
- QR codes work for messages up to ~500 bytes
- Archive format documented for interoperability
- No data loss or corruption in transfer

**What this enables:**

Send encrypted messages across an air gap: USB drive, printed QR code, or carrier pigeon. The simplest possible offline transport, and foundation for all others.

---

## v0.6: LAN relay

Route messages through LAN peers during partial Internet outages.

### Store-and-forward relay queue

v0.6 introduces the **relay queue**, a store-and-forward component that later versions extend with additional adapters.

```mermaid
flowchart TD
    subgraph "Ingress"
        I1["v0.6: HTTP (LAN peer)"]
        I2["v0.9: + BLE / Meshtastic"]
    end

    Q[(Relay Queue)]

    subgraph "Egress"
        E1["v0.6: HTTP to Quorum"]
        E2["v0.10: + BLE / Meshtastic"]
    end

    I1 --> Q
    I2 --> Q
    Q --> E1
    Q --> E2
```

Encrypted envelopes only, no decryption needed. Queue is persistent and survives restarts.

The queue only handles encrypted `OuterEnvelope` blobs. Relay nodes never decrypt; they move bytes between ingress and egress.

### Peer relay mode

**Problem:** During partial outages, some LAN peers have Internet access and others don't. Peers without Internet should be able to relay through peers that do.

**Solution:**
- Discovered peers can act as **untrusted best-effort relays** for messages to external recipients
- Contact-style identity verification is not required for submit/store relay, but anonymous discovered relays are **not** equivalent to configured Quorum peers
- Opt-in configuration for both accepting and using relay requests
- Relay capability advertised in mDNS TXT records

**Deliverables:**
- [ ] Relay queue with persistent storage and retry logic
- [ ] HTTP ingress adapter (accepts envelopes from LAN peers)
- [ ] HTTP egress adapter (forwards to Quorum nodes)
- [ ] Discovered-peer capability policy (submit/store only, no quorum credit, no replication, no exact-key fetch)
- [ ] Relay capability advertisement in mDNS TXT records
- [ ] Relay accept/use configuration options
- [ ] Relay routing in transport coordinator
- [ ] Relay status in TUI (showing relay path)

**Success criteria:**
- Alice (no Internet) sends to Charlie (external) via Bob (has Internet)
- Message delivered when Bob reconnects to Internet
- Relay path visible in delivery status
- Works transparently with existing outbox retry logic

Your message reaches the outside world through any peer that has connectivity, even if you don't.

---

## v0.7: BLE direct

Point-to-point encrypted messaging over BLE. Two devices in proximity exchange messages directly, no Internet or infrastructure needed.

### BLE proximity exchange

**Problem:** Internet-based transports fail during infrastructure outages or censorship. Need a transport that works with zero infrastructure.

**Solution:**
- BLE GATT server advertising routing key
- Scan for nearby peers, exchange envelopes over BLE characteristics
- Detached messages (no DAG overhead) for constrained payloads

### Transport-layer chunking

BLE MTU (20-512 bytes) may be smaller than an OuterEnvelope (~200+ bytes). Chunking splits envelopes at the transport layer without re-encryption. Any node can split/reassemble (no keys needed).

| Field | Size | Description |
|-------|------|-------------|
| envelope_hash | 8 bytes | Links chunks belonging to the same envelope |
| chunk_index | 1 byte | Position (0, 1, 2...) |
| chunk_total | 1 byte | Total chunk count |
| payload | variable | Raw bytes of the OuterEnvelope fragment |

Reused by Meshtastic transport in v0.8.

**Deliverables:**
- [ ] `btleplug` integration
- [ ] GATT service definition
- [ ] BLE message exchange protocol
- [ ] `TransportChunk` wire format with chunking/reassembly
- [ ] Reassembly buffer with timeout and LRU eviction
- [ ] Detached message support
- [ ] Background scanning/advertising

**Success criteria:**
- Alice and Bob exchange messages over BLE with no Internet
- <30 second exchange time for nearby peers
- Messages larger than BLE MTU transfer correctly via chunking
- Works on Linux/macOS/Windows/Android

---

## v0.8: Meshtastic direct

Point-to-point encrypted messaging over LoRa via Meshtastic. Two devices with Meshtastic hardware exchange messages directly, no Internet needed. Meshtastic handles LoRa radio management; reme treats it as an opaque transport.

### Meshtastic transport

**Problem:** BLE requires physical proximity (~10m). For disaster response, remote areas, or censorship resistance, we need communication over kilometers without any Internet infrastructure.

**Solution:** Integrate with Meshtastic via its serial/BLE API. Reme sends and receives chunked OuterEnvelopes; Meshtastic handles duty cycle, hop counts, and mesh routing.

Reme does **not** implement its own LoRa mesh protocol. Meshtastic already solves this. Plain LoRa (without Meshtastic) is deferred unless there's a concrete need.

**Deliverables:**
- [ ] Meshtastic serial/BLE protocol integration
- [ ] Meshtastic transport adapter (send/receive chunked envelopes)
- [ ] Reuse v0.7 TransportChunk for LoRa MTU (~200 bytes)
- [ ] Detached messages by default (minimize overhead)
- [ ] Integration with existing transport coordinator

**Constraints:**
- Regulatory duty cycle limits (e.g., 1% at EU 868 MHz) mean multi-chunk messages may take several minutes to transmit. LoRa messaging is practical for short texts with minutes of latency, not real-time conversation.

**Success criteria:**
- Alice and Bob exchange messages over Meshtastic in direct line of sight
- Message delivery over 5+ km with line-of-sight
- Works with off-the-shelf Meshtastic hardware (T-Beam, Heltec, etc.)

---

## v0.9: Bridge to Quorum

BLE and Meshtastic devices can bridge messages to Quorum via the v0.6 relay queue. This is ingress only: receive an envelope from BLE or Meshtastic, deposit into the relay queue, forward to Quorum over HTTP.

### BLE/Meshtastic ingress adapters

**Problem:** A device that received a message via BLE or Meshtastic should be able to forward it to Quorum if it has Internet access.

**Solution:** Add BLE and Meshtastic as ingress adapters to the v0.6 relay queue. The egress side (HTTP to Quorum) already exists from v0.6.

**Deliverables:**
- [ ] BLE ingress adapter for relay queue
- [ ] Meshtastic ingress adapter for relay queue
- [ ] Relay capability advertisement in BLE service data

**Success criteria:**
- Alice (BLE only) → Bob's phone (BLE + Internet) → Quorum → Charlie
- Alice (Meshtastic only) → Bob's node (Meshtastic + Internet) → Quorum → Charlie
- Same relay status/tracking as LAN relay

---

## v0.10: Multi-transport relay

Full relay with egress adapters, cross-transport bridging, and multi-hop.

### BLE egress with RSSI-informed relay

Rebroadcast queued messages over BLE to nearby peers. Uses randomized backoff with received signal strength as a scheduling hint: weaker-signal nodes (farther away) bias toward earlier rebroadcast; stronger-signal nodes wait and cancel if they overhear a duplicate. Unlike Meshtastic's LoRa approach, BLE at 2.4 GHz has high RSSI variance indoors (multipath, body absorption, orientation), so RSSI is a probabilistic hint rather than a deterministic timer.

**Deliverables:**
- [ ] BLE egress adapter for relay queue
- [ ] Randomized backoff with RSSI hint
- [ ] Duplicate suppression (heard-before cancellation)

### Meshtastic egress

Forward queued messages over Meshtastic for off-grid recipients. This enables the "Starlink Relay" scenario.

**Deliverables:**
- [ ] Meshtastic egress adapter for relay queue
- [ ] Headless relay mode (no TUI, minimal resources)
- [ ] Relay statistics/monitoring endpoint

### The "Starlink Relay" scenario

You're off-grid during a power outage. Your home has Starlink + a stationary Meshtastic node. Messages arrive for you via Internet, but you have no Internet access.

The home relay node fetches messages from Quorum (HTTP ingress), then sends them out over Meshtastic (Meshtastic egress) without decrypting them.

```mermaid
flowchart LR
    Q[Internet / Quorum] -->|HTTP| S[Starlink Modem]

    subgraph "Your Home"
        S --> R[Meshtastic Node - Relay]
    end

    R -->|"LoRa radio (10km+)"| P[Your Phone - Meshtastic Client]
```

**How it works:**
1. Home node fetches messages from Quorum (HTTP) for your `routing_key`
2. Node **cannot decrypt** (doesn't have your private key)
3. Node uses transport-layer chunking to split OuterEnvelope for LoRa MTU
4. Sends chunks via Meshtastic; Meshtastic handles mesh delivery
5. Your off-grid device receives chunks, reassembles, decrypts

**Community relay network:**
The same scenario works with **any** Internet-connected Meshtastic node running reme bridge software. A neighbor's node, a community relay on a hilltop, or a stranger's device can all bridge your messages. No plaintext trust is required because the payload is end-to-end encrypted, but metadata and availability remain sensitive, so these bridge nodes must stay in an untrusted relay role unless explicitly configured as trusted peers.

**Success criteria:**
- Starlink relay scenario works (HTTP → Meshtastic egress without decryption)
- BLE-to-BLE relay extends range beyond single-hop distance (RSSI as hint, not deterministic)
- Third-party bridge nodes work without prior trust/coordination
- Cross-transport relay works (e.g., BLE → relay queue → Meshtastic)

---

## v1.0: Forward secrecy (breaking release)

Production-ready with session-based forward secrecy and stable wire format.

> **Breaking changes:** v1.0 is the last planned breaking release. Wire format migrates from Postcard to Protobuf for cross-language compatibility and long-term schema evolution. All pre-1.0 clients will be incompatible.

### Wire format: Protobuf migration

**Why Protobuf for v1.0:**
- Cross-language code generation (mobile apps, web clients)
- Field numbers enable backward/forward compatible schema evolution
- Unknown field preservation (old clients pass through new fields)
- Industry standard with good tooling
- `.proto` files are the canonical protocol specification

**Postcard → Protobuf learnings:**
- Size budgets validated on constrained transports (LoRa, BLE)
- Field ordering and optionality patterns established
- Schema evolution needs identified from v0.x development

### Protocol: Async Noise XX handshake

Implements DTN-safe forward secrecy without prekey servers.

### Features

#### 1. Encrypted sender in OuterEnvelope

**Problem:** Recipient can't identify sender when session keys lost.

**Solution:**
- `encrypted_sender: [u8; 48]` in OuterEnvelope
- Always decryptable by recipient MIK
- Enables key-loss recovery

#### 2. Sign-all-bytes

**Problem:** Static field signatures break on version upgrades.

**Solution:**
- Sign all serialized InnerEnvelope bytes
- Forward/backward compatible

#### 3. Noise XX handshake

**Problem:** MIK-only lacks forward secrecy.

**Solution:**
- Mutual authentication with ephemeral DH
- Either party can initiate
- Epoch-based replay protection
- MIK fallback when session unavailable

#### 4. DAG-integrated key lifecycle

**Problem:** When to delete old session keys?

**Solution:**
- Delete key only after all messages acknowledged via DAG
- Conservative retention during gaps
- Bounded memory (max 10 retained keys)

#### 5. Key loss recovery

**Problem:** Recipient loses session keys.

**Solution:**
- Decrypt `encrypted_sender` to identify peer
- Request re-send with MIK encryption
- Automatic without manual intervention

---

## Future considerations (post-v1.0)

### Group messaging
- Sender Keys protocol (O(1) encryption)
- Multi-sender DAG with per-member gap detection
- Admin operations (add/remove/promote)

### Additional transports
- Satellite uplinks
- Ham radio digital modes

### Better privacy
- Fixed-size message padding
- Cover traffic
- Routing key rotation

### State synchronization
- Merkle accumulator sync
- Cross-device state merge

### Security improvements
- Post-quantum cryptography (Kyber)
- Hardware security module support

---

## Rejected approaches

### Iroh/QUIC P2P via DHT

**Status:** Rejected due to privacy concerns

**Problem:** Iroh's DHT-based peer discovery leaks IP addresses to anyone querying the DHT. This conflicts with reme's privacy-by-design principle.

**Alternatives considered:**
- Private DHT with authenticated peers only
- Direct connections via known addresses (no discovery)
- Tor-based discovery

**Decision:** Focus on BLE for zero-infrastructure scenarios. For Internet-based P2P, users can configure direct connections to known peers without DHT discovery.

---

## Success metrics

### v0.4
- <5s peer discovery on LAN
- Zero configuration for LAN messaging
- Identity verification prevents wrong-device delivery

### Postcard migration
- All tests pass with new serialization
- Wire format size delta < 5%
- No manual serialization impl blocks

### v0.5
- Successful export→transfer→import round-trip
- QR codes for small messages
- Archive format documented

### v0.6
- LAN relay works during partial Internet outages
- Relay path visible in delivery status

### v0.7
- BLE direct exchange <30s between two nearby devices
- Works without any Internet connectivity

### v0.8
- Meshtastic direct exchange over 5+ km with line-of-sight
- Works with off-the-shelf Meshtastic hardware

### v0.9
- BLE/Meshtastic → relay queue → Quorum bridging works
- Same relay status/tracking as LAN relay

### v0.10
- Starlink relay scenario works (HTTP → Meshtastic egress)
- BLE-to-BLE relay extends range via RSSI-informed rebroadcast
- Cross-transport relay (e.g., BLE → Meshtastic)

### v1.0
- Protobuf wire format (breaking change)
- Session-based forward secrecy
- Automatic key-loss recovery
- Production-ready security audit
- Mobile apps (Android/iOS)

---

## Development process

### Testing requirements

1. **Unit tests**: Core logic in isolation
2. **Integration tests**: Multi-transport, multi-node scenarios
3. **Property tests**: Invariants (no message loss, no duplicates)
4. **Security review**: Crypto changes require peer review

### Quality gates

| Gate              | Requirement                                   |
|-------------------|-----------------------------------------------|
| **Code review**   | All PRs require review                        |
| **CI passing**    | Tests, clippy, rustfmt                        |
| **Documentation** | Updated CLAUDE.md, WHITEPAPER.md, inline docs |
| **Changelog**     | User-facing changes documented                |

---

## Contributing

Features prioritized by:
1. **Impact**: How many use cases does it enable?
2. **Privacy**: Does it leak metadata or require third-party infrastructure?
3. **Dependencies**: What must be done first?

Security/resilience features have priority over convenience features.
