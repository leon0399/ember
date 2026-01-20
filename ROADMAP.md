# Resilient Messenger Roadmap

**Current Version:** v0.3 (Tiered Delivery)  
**Target Version:** v1.0 (Production Ready)

---

## Vision

Build an outage-resilient, end-to-end encrypted messaging system that works when traditional infrastructure fails. Reme prioritizes resilience over convenience, enabling communication during network failures, infrastructure attacks, or censorship.

## Guiding Principles

1. **Client-Side Resilience First**: Messages never disappear silently
2. **DTN Tolerance**: No session state, independent message processing
3. **Transport Agnostic**: Same encrypted payload across HTTP, BLE, mesh
4. **Cryptographic Soundness**: Conservative primitives, defense in depth
5. **Privacy by Design**: No IP leakage to DHTs, minimal metadata exposure

---

## Release Timeline

```
v0.3 (Current) → v0.4        → [Postcard] → v0.5        → v0.6        → v0.7        → v0.8        → v1.0
Tiered           mDNS           Migration      Sneakernet     LAN            BLE            LoRa           Forward
Delivery         Discovery      (internal)     Export         Relay          Proximity      Mesh           Secrecy
```

---

## Current Status (v0.3)

### Core Foundation

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

**Test Coverage:** 385 tests across workspace, all passing.

---

## v0.4: LAN Discovery

**Theme:** Automatic peer discovery and verified P2P messaging on local networks

### mDNS/Bonjour Discovery

**Problem:** Manual peer configuration is tedious for LAN scenarios.

**Solution:**
- Advertise client presence via mDNS (`_reme._tcp.local`)
- TXT records: `id=<routing_key>`, `port=<http_port>`
- Background scanning for discovered peers
- Automatic registration as Direct tier targets

**Deliverables:**
- [ ] `mdns` crate integration
- [ ] Service advertisement on client startup
- [ ] Background discovery task
- [ ] Automatic transport registration
- [ ] UI indication of discovered peers

### Node Identity Verification

**Problem:** mDNS discovers peers by IP, but we can't verify identity without pre-shared keys. DHCP reassignment could route messages to wrong device.

**Solution:**
- Identity endpoint (`GET /api/v1/identity?challenge=<base64>`)
- Challenge-response protocol proves node controls claimed identity
- Background refresh detects IP reassignment (5 min default interval)
- Refresh on delivery failure or network change

**Deliverables:**
- [ ] Identity endpoint on main node and embedded node
- [ ] Challenge-response verification in discovery flow
- [ ] Background identity refresh task
- [ ] Refresh triggers (periodic, failure, network change)
- [ ] Configuration options for refresh interval

**Success Criteria:**
- Two clients on same LAN discover each other within 5 seconds
- Direct messages succeed without manual configuration
- Identity verification prevents messages to wrong device after DHCP change
- Graceful handling of network changes

---

## Internal: Postcard Migration (Pre-v0.5)

**Theme:** Simplify serialization code and prepare for stable wire format

### Migrate from Bincode to Postcard

**Problem:** Current bincode encoding requires manual `impl Encode/Decode` blocks, is Rust-specific, and has limited schema evolution capabilities. This creates maintenance burden and will complicate future cross-platform clients.

**Why Now (before v0.5):**
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

**Success Criteria:**
- All 385+ tests pass
- Wire format size delta < 5%
- No manual serialization impl blocks remaining

**Future:** Postcard learnings inform v1.0 Protobuf design for cross-language schema with full backward/forward compatibility.

---

## v0.5: Sneakernet Export

**Theme:** Air-gapped messaging via file transfer

### Message Archive Export/Import

**Problem:** Sometimes there's no network at all—not even BLE range. Need a way to physically transport encrypted messages between air-gapped systems.

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

**Success Criteria:**
- Round-trip export→USB→import works correctly
- QR codes work for messages up to ~500 bytes
- Archive format documented for interoperability
- No data loss or corruption in transfer

**Why This Matters:**
> "Send encrypted messages across an air gap—USB drive, printed QR code, or carrier pigeon."

The simplest possible offline transport, and foundation for all others.

---

## v0.6: LAN Relay

**Theme:** Route messages through LAN peers during partial Internet outages

### Peer Relay Mode

**Problem:** During partial outages, some LAN peers have Internet access and others don't. Peers without Internet should be able to relay through peers with Internet.

**Solution:**
- Discovered peers can act as relays for messages to external recipients
- No identity verification needed for relay (E2E encrypted, same trust as Quorum)
- Configuration: opt-in to accept relay requests, opt-in to use LAN relays
- Relay capability advertised in mDNS TXT records

**Deliverables:**
- [ ] Relay capability advertisement in mDNS TXT records
- [ ] Relay accept/use configuration options
- [ ] Relay routing in transport coordinator
- [ ] Store-and-forward for offline external recipients
- [ ] Relay status in TUI (showing relay path)

**Success Criteria:**
- Alice (no Internet) sends to Charlie (external) via Bob (has Internet)
- Message delivered when Bob reconnects to Internet
- Relay path visible in delivery status
- Works transparently with existing outbox retry logic

**Why This Matters:**
> "Your message reaches the outside world through any peer that has connectivity—even if you don't."

**Architecture Note:** This implementation is HTTP-to-HTTP only. Future transports (BLE, LoRa) will reuse the relay queue and egress logic, with transport-specific ingress. Build concrete first, extract abstraction later.

---

## v0.7: BLE Proximity

**Theme:** Zero-infrastructure messaging for maximum resilience and privacy

### BLE Proximity Exchange

**Problem:** Internet-based transports fail during infrastructure outages or censorship. Need a transport that works with zero infrastructure and doesn't leak metadata to third parties.

**Solution:**
- BLE GATT server advertising routing key
- Scan for nearby peers
- Exchange envelopes over BLE characteristics
- Store-and-forward when peers pass each other
- Detached messages (no DAG overhead) for constrained payloads

**Deliverables:**
- [ ] `btleplug` integration
- [ ] GATT service definition
- [ ] BLE message exchange protocol
- [ ] Detached message support
- [ ] Background scanning/advertising
- [ ] Power-efficient operation

### BLE Relay Ingress

**Problem:** A phone with BLE + Internet should relay messages received via BLE to Quorum, just like LAN peers relay HTTP messages.

**Solution:**
- Messages received via BLE are deposited into the same relay queue as HTTP
- Relay egress (HTTP to Quorum) is transport-agnostic
- BLE becomes an alternative ingress path for the v0.6 relay infrastructure

**Deliverables:**
- [ ] BLE ingress adapter for relay queue
- [ ] Relay capability advertisement in BLE service data
- [ ] Unified relay queue (shared with HTTP ingress from v0.6)

**Success Criteria:**
- Alice (BLE only) → Bob's phone (BLE + Internet) → Quorum → Charlie
- Same relay status/tracking as LAN relay

### Transport-Layer Chunking

**Problem:** BLE MTU (20-512 bytes) may be smaller than OuterEnvelope (~200+ bytes). Need to split messages for constrained transports without re-encryption.

**Key Insight:** Chunking happens at the transport layer, not application layer. Relay nodes can split/reassemble encrypted blobs without having decryption keys.

**Solution:**
```
┌─────────────────────────────────────────────────────────────┐
│  TransportChunk (no encryption, just byte splitting)        │
├─────────────────────────────────────────────────────────────┤
│  envelope_hash: [u8; 8]   // Links chunks of same envelope  │
│  chunk_index: u8          // Position (0, 1, 2...)          │
│  chunk_total: u8          // Total count                    │
│  payload: Vec<u8>         // Raw bytes of OuterEnvelope     │
└─────────────────────────────────────────────────────────────┘
```

**Properties:**
- Any node can split/reassemble (no keys needed)
- Original E2E encryption preserved
- Enables the "Starlink Relay" scenario (see v0.8)

**Deliverables:**
- [ ] `TransportChunk` wire format
- [ ] BLE chunking/reassembly in transport layer
- [ ] Reassembly buffer with timeout and LRU eviction
- [ ] Chunk deduplication

**Success Criteria:**
- Message exchange succeeds without Internet
- <30 second exchange time for nearby peers
- Works on Linux/macOS/Windows/Android
- Messages larger than BLE MTU transfer correctly

---

## v0.8: LoRa Mesh

**Theme:** Kilometers-range messaging without Internet infrastructure

### LoRa/Meshtastic Integration

**Problem:** BLE requires physical proximity (~10m). For disaster response, remote areas, or censorship resistance, we need communication over kilometers without any Internet infrastructure.

**Solution:**
- Meshtastic device integration via serial/BLE bridge
- Store-and-forward mesh routing through Meshtastic network
- Transport-layer chunking for LoRa MTU (~200 bytes)
- Detached messages by default (minimize overhead)
- Automatic reassembly on receive

**Deliverables:**
- [ ] Meshtastic serial protocol integration
- [ ] LoRa transport with chunking (reuses v0.7 TransportChunk)
- [ ] LoRa transport implementation
- [ ] Mesh routing awareness (hop count, SNR)
- [ ] Power-efficient transmission scheduling
- [ ] Integration with existing transport coordinator

### LoRa Relay Ingress

**Problem:** A Meshtastic node with Internet (Starlink, home WiFi) should relay messages received over LoRa to Quorum.

**Solution:**
- LoRa ingress deposits reassembled OuterEnvelopes into the relay queue
- Same relay egress as v0.6 (HTTP to Quorum)
- Works on dedicated relay nodes (Raspberry Pi + Meshtastic) or phones with Meshtastic app

**Third-Party Relay Nodes:**
- Any Meshtastic user running reme relay software can contribute relay capacity
- No trust required - they only see encrypted bytes
- Incentive: reciprocal relay services, community resilience

**Deliverables:**
- [ ] LoRa ingress adapter for relay queue
- [ ] Headless relay mode (no TUI, minimal resources)
- [ ] Relay statistics/monitoring endpoint

**Success Criteria:**
- Stranger's Meshtastic node relays your message to Quorum
- Works without any prior relationship or key exchange

### The "Starlink Relay" Scenario

**Problem:** You're off-grid across the city during a power outage. Your home has Starlink + a stationary LoRa node. Messages arrive for you via Internet, but you have no Internet access.

**Solution:** Home relay node fetches messages from Quorum, then re-broadcasts them over LoRa—without decrypting them.

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                    YOUR HOME                            │
                    │  ┌─────────────┐      ┌─────────────┐                   │
Internet ──────────►│  │  Starlink   │─────►│ LoRa Node   │───── LoRa ────────┼───►
  (Quorum)          │  │   Modem     │      │ (Relay)     │      Radio        │
                    │  └─────────────┘      └─────────────┘                   │
                    └─────────────────────────────────────────────────────────┘
                                                                      │
                                                                      │ 10km+
                                                                      │
                    ┌─────────────────────────────────────────────────────────┐
                    │                 YOU (Off-Grid)                          │
                    │            ┌─────────────┐                              │
                    │            │ LoRa Client │◄─── Receives via LoRa        │
                    │            │ (Your Phone)│                              │
                    │            └─────────────┘                              │
                    └─────────────────────────────────────────────────────────┘
```

**How it works:**
1. Home node fetches messages from Quorum (HTTP) for your `routing_key`
2. Node **cannot decrypt** (doesn't have your private key)
3. Node uses transport-layer chunking to split OuterEnvelope for LoRa MTU
4. Broadcasts chunks over LoRa mesh
5. Your off-grid device receives chunks, reassembles, decrypts

**Why This Matters:**
> "Message someone kilometers away without Internet, cell towers, or any infrastructure—just radio waves."
> 
> "Your home relay bridges Internet and radio—you receive messages off-grid without anyone decrypting them."

This is the defining capability that separates reme from conventional messengers.

**Community Relay Network:**
The same scenario works with **any** Internet-connected Meshtastic node running reme relay software—not just your own. A neighbor's node, a community relay on a hilltop, or a stranger's device can all bridge your messages to the Internet. Zero trust required (E2E encryption), zero coordination required (just run the relay daemon).

**Success Criteria:**
- Message delivery over 5+ km with line-of-sight
- Multi-hop mesh routing through intermediate nodes
- Starlink relay scenario works (HTTP→LoRa bridge without decryption)
- Third-party relay nodes work without prior trust/coordination
- Graceful degradation when nodes unavailable
- Works with off-the-shelf Meshtastic hardware (T-Beam, Heltec, etc.)

---

## v1.0: Forward Secrecy (Breaking Release)

**Theme:** Production-ready with session-based forward secrecy and stable wire format

> **Breaking Changes:** v1.0 is the last planned breaking release. Wire format migrates from Postcard to Protobuf for cross-language compatibility and long-term schema evolution. All pre-1.0 clients will be incompatible.

### Wire Format: Protobuf Migration

**Why Protobuf for v1.0:**
- Cross-language code generation (mobile apps, web clients)
- Field numbers enable backward/forward compatible schema evolution
- Unknown field preservation (old clients pass through new fields)
- Industry standard with extensive tooling
- `.proto` files serve as the canonical protocol specification

**Postcard → Protobuf learnings:**
- Size budgets validated on constrained transports (LoRa, BLE)
- Field ordering and optionality patterns established
- Schema evolution needs identified from v0.x development

### Protocol: Async Noise XX Handshake

Implements DTN-safe forward secrecy without prekey servers.

### Features

#### 1. Encrypted Sender in OuterEnvelope

**Problem:** Recipient can't identify sender when session keys lost.

**Solution:**
- `encrypted_sender: [u8; 48]` in OuterEnvelope
- Always decryptable by recipient MIK
- Enables key-loss recovery

#### 2. Sign-All-Bytes

**Problem:** Static field signatures break on version upgrades.

**Solution:**
- Sign all serialized InnerEnvelope bytes
- Forward/backward compatible

#### 3. Noise XX Handshake

**Problem:** MIK-only lacks forward secrecy.

**Solution:**
- Mutual authentication with ephemeral DH
- Either party can initiate
- Epoch-based replay protection
- MIK fallback when session unavailable

#### 4. DAG-Integrated Key Lifecycle

**Problem:** When to delete old session keys?

**Solution:**
- Delete key only after all messages acknowledged via DAG
- Conservative retention during gaps
- Bounded memory (max 10 retained keys)

#### 5. Key Loss Recovery

**Problem:** Recipient loses session keys.

**Solution:**
- Decrypt `encrypted_sender` to identify peer
- Request re-send with MIK encryption
- Automatic without manual intervention

---

## Future Considerations (Post-v1.0)

### Group Messaging
- Sender Keys protocol (O(1) encryption)
- Multi-sender DAG with per-member gap detection
- Admin operations (add/remove/promote)

### Additional Transports
- Satellite uplinks
- Ham radio digital modes

### Advanced Privacy
- Fixed-size message padding
- Cover traffic
- Routing key rotation

### State Synchronization
- Merkle accumulator sync
- Cross-device state merge

### Security Enhancements
- Post-quantum cryptography (Kyber)
- Hardware security module support

---

## Rejected Approaches

### Iroh/QUIC P2P via DHT

**Status:** Rejected due to privacy concerns

**Problem:** Iroh's DHT-based peer discovery leaks IP addresses to anyone querying the DHT. This conflicts with reme's privacy-by-design principle.

**Alternatives considered:**
- Private DHT with authenticated peers only
- Direct connections via known addresses (no discovery)
- Tor-based discovery

**Decision:** Focus on BLE for zero-infrastructure scenarios. For Internet-based P2P, users can configure direct connections to known peers without DHT discovery.

---

## Success Metrics

### v0.4
- <5s peer discovery on LAN
- Zero configuration for LAN messaging
- Identity verification prevents wrong-device delivery

### Postcard Migration
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
- BLE exchange <30s proximity time
- Works without any Internet connectivity

### v0.8
- LoRa message delivery over 5+ km
- Multi-hop mesh routing
- Works with off-the-shelf Meshtastic hardware

### v1.0
- Protobuf wire format (breaking change)
- Session-based forward secrecy
- Automatic key-loss recovery
- Production-ready security audit
- Mobile apps (Android/iOS)

---

## Development Process

### Testing Requirements

1. **Unit Tests**: Core logic in isolation
2. **Integration Tests**: Multi-transport, multi-node scenarios
3. **Property Tests**: Invariants (no message loss, no duplicates)
4. **Security Review**: Crypto changes require peer review

### Quality Gates

| Gate              | Requirement                                   |
|-------------------|-----------------------------------------------|
| **Code Review**   | All PRs require review                        |
| **CI Passing**    | Tests, clippy, rustfmt                        |
| **Documentation** | Updated CLAUDE.md, WHITEPAPER.md, inline docs |
| **Changelog**     | User-facing changes documented                |

---

## Contributing

Features prioritized by:
1. **Impact**: How many use cases does it enable?
2. **Privacy**: Does it leak metadata or require third-party infrastructure?
3. **Dependencies**: What must be done first?

Security/resilience features have priority over convenience features.
