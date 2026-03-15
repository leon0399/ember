# Resilient Messenger (reme)

## A Delay-Tolerant, End-to-End Encrypted Messaging Protocol

**Version 0.3 (Tiered Delivery)**
**January 2026**

---

## Abstract

Resilient Messenger (reme) is an outage-resilient, end-to-end encrypted messaging system for environments where network connectivity is intermittent, constrained, or adversarial. Unlike traditional messengers that depend on always-on Internet connectivity, reme uses a hybrid transport architecture: HTTP mailboxes, LoRa mesh networks, BLE proximity exchange, and other constrained transports.

The protocol uses XEdDSA signatures, X25519 key exchange, and ChaCha20-Poly1305 authenticated encryption, while keeping a minimal wire format suitable for bandwidth-constrained channels. A Merkle DAG message ordering system tracks causal ordering without centralized coordination, allowing gap detection and state recovery across disconnected operation periods.

This paper presents the complete protocol specification, threat model, cryptographic rationale, and comparison with existing secure messaging systems including Signal, Session, Matrix, and Briar.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Problem Statement](#2-problem-statement)
3. [Design Goals and Constraints](#3-design-goals-and-constraints)
4. [System Architecture](#4-system-architecture)
5. [Identity and Key Management](#5-identity-and-key-management)
6. [Cryptographic Design](#6-cryptographic-design)
7. [Message Format and Wire Protocol](#7-message-format-and-wire-protocol)
8. [DAG-Based Message Ordering](#8-dag-based-message-ordering)
9. [Tombstone System](#9-tombstone-system)
10. [Transport Layer](#10-transport-layer)
11. [Security Analysis](#11-security-analysis)
12. [Comparison with Existing Systems](#12-comparison-with-existing-systems)
13. [Future Directions](#13-future-directions)
14. [Conclusion](#14-conclusion)

---

## 1. Introduction

Modern secure messaging systems protect message content well through end-to-end encryption. But they depend on reliable Internet connectivity and centralized infrastructure. This dependency creates real vulnerabilities:

- **Natural disasters** often destroy or overwhelm communication infrastructure when coordination matters most
- **Authoritarian regimes** can block messaging services at will
- **Remote areas** lack reliable connectivity for conventional messaging
- **Infrastructure attacks** can disable communications for entire regions

Reme takes a different approach: designing for intermittent, constrained, and potentially adversarial network conditions from the start, rather than treating them as edge cases.

### 1.1 What's different

1. **Stateless encryption**: Each message is independently decryptable using ephemeral key exchange. No session state synchronization needed across devices or transport failures.

2. **Merkle DAG message ordering**: Content-addressed message identifiers form a directed acyclic graph for causality detection and gap identification without centralized servers.

3. **Transport-agnostic design**: The same encrypted message can traverse HTTP, LoRa, BLE, or any future transport, with bandwidth-appropriate metadata for constrained channels.

4. **Cryptographic tombstones**: Signed acknowledgments allow cache management and delivery confirmation while hiding sender-receiver relationships from relay nodes.

---

## 2. Problem Statement

### 2.1 Limitations of existing systems

Traditional secure messengers have architectural limitations that reme addresses:

| System  | Limitation                                                   | reme Solution                                             |
|---------|--------------------------------------------------------------|-----------------------------------------------------------|
| Signal  | Requires server-mediated key exchange, phone number identity | Self-sovereign identity, stateless encryption             |
| Session | Onion routing adds latency, large node requirements          | Direct mailbox routing with privacy-preserving addressing |
| Matrix  | Federation complexity, metadata leakage                      | Simple store-forward, coarse timestamps                   |
| Briar   | Tor dependency, no offline operation                         | Multi-transport, DTN-compatible design                    |

### 2.2 Threat model

reme is designed to resist these adversaries:

**Network-level adversaries:**
- Passive observers attempting traffic analysis
- Active attackers injecting or modifying messages
- Infrastructure operators attempting message suppression

**Endpoint adversaries:**
- Compromised relay nodes
- Malicious senders attempting impersonation
- Attackers attempting replay or reordering

**Key compromise:**
- Loss of device does not compromise past messages
- Future security after key compromise (with session ratcheting in v2)

### 2.3 Security goals

1. **Confidentiality**: Only intended recipients can read message content
2. **Authenticity**: Recipients can verify sender identity
3. **Integrity**: Any modification to messages is detectable
4. **Forward secrecy**: Compromise of long-term keys does not expose past messages
5. **Metadata minimization**: Relay nodes learn minimal information about communication patterns
6. **Repudiation**: Third parties cannot cryptographically prove who sent a message (deniability)

---

## 3. Design Goals and Constraints

### 3.1 Primary goals

1. **Outage resilience**: Continue functioning during network partitions, infrastructure failures, or deliberate blocking
2. **Transport flexibility**: Support multiple transport mechanisms with graceful degradation
3. **Minimal state**: Reduce synchronization requirements between devices and across transport failures
4. **Bandwidth efficiency**: Operate on severely constrained channels (LoRa: ~200 bytes/message)
5. **Cryptographic soundness**: Use well-analyzed primitives with conservative security margins

### 3.2 Design constraints

**Wire format constraints:**
- Outer envelope: ~102 bytes minimum overhead
- Inner envelope: Scales with content (~62 bytes minimum for empty text)
- LoRa MTU: ~200 bytes (requires fragmentation for larger messages)
- Total encrypted text message: ~180-220 bytes typical

**Operational constraints:**
- No mandatory central servers (mailboxes are optional relays)
- No phone numbers or external identifiers required
- Single persistent identity across all transports
- Offline-first message composition

---

## 4. System Architecture

### 4.1 Crate structure

```
crates/
├── reme-identity    # X25519/XEdDSA identity, PublicID (32-byte address)
├── reme-encryption  # ChaCha20Poly1305 AEAD + ephemeral ECDH
├── reme-message     # Wire formats, DAG structures, tombstones
├── reme-transport   # Transport trait, HTTP/MQTT, TransportCoordinator
├── reme-storage     # SQLite persistence
├── reme-outbox      # Tiered delivery, retry policies, delivery tracking
├── reme-node-core   # Shared node/relay logic, embedded HTTP server
└── reme-core        # High-level Client API

apps/
├── node/            # Mailbox server (store-and-forward)
└── client/          # TUI client with embedded relay capability
```

### 4.2 Message flow

```
┌──────────┐     ┌──────────────┐     ┌──────────┐
│  Sender  │────▶│   Mailbox    │────▶│ Receiver │
│  Client  │     │    Node      │     │  Client  │
└──────────┘     └──────────────┘     └──────────┘
     │                  │                   │
     │  OuterEnvelope   │  OuterEnvelope    │
     │  (encrypted)     │  (stored)         │
     │                  │                   │
     │                  │   TombstoneEnvelope
     │                  │◀──────────────────│
     │                  │  (acknowledges)   │
```

**Send path:**
1. Client creates `InnerEnvelope` with content and DAG references
2. Signs with sender's XEdDSA key
3. Encrypts to recipient's MIK (Master Identity Key) using ephemeral ECDH
4. Wraps in `OuterEnvelope` with routing metadata
5. Submits to transport (HTTP mailbox, LoRa, etc.)

**Receive path:**
1. Client fetches messages by routing key
2. Decrypts using MIK private key
3. Verifies sender signature
4. Processes DAG references for gap detection
5. Sends tombstone to acknowledge receipt

### 4.3 Addressing model

**PublicID (32 bytes):** The user's X25519 public key, used as both address and encryption target.

**RoutingKey (16 bytes):** First 16 bytes of BLAKE3 hash of PublicID. Used for mailbox addressing without revealing the full identity.

```
routing_key = BLAKE3(public_id)[0:16]
```

This gives us:
- **Privacy**: Routing key cannot be reversed to PublicID
- **Collision resistance**: 128-bit space is sufficient for addressing
- **Efficiency**: Compact lookup keys for relay storage

---

## 5. Identity and Key Management

### 5.1 Single-key identity

reme uses a single X25519 key for both encryption and signatures (via XEdDSA). This means:

- **32-byte addresses**: Compact, human-verifiable identities
- **Simplified backup**: Single secret key backs up entire identity
- **Cross-curve compatibility**: XEdDSA provides Ed25519-compatible signatures from X25519 keys

```rust
pub struct Identity {
    public_id: PublicID,    // X25519 public key (32 bytes)
    x25519_secret: StaticSecret,  // X25519 private key (32 bytes)
}
```

### 5.2 XEdDSA signatures

XEdDSA (eXtended EdDSA) allows signing with X25519 keys through the birational map between Montgomery (Curve25519) and Twisted Edwards (Ed25519) forms:

```
Ed25519_pubkey = birational_map(X25519_pubkey, sign_bit=0)
```

Properties:
- Deterministic signatures using nonce derived from message and key
- Ed25519-compatible verification
- 64-byte signatures

### 5.3 Low-order point validation

All public keys are validated against small-order points that would produce predictable shared secrets:

```rust
const LOW_ORDER_POINTS: [[u8; 32]; 7] = [
    [0x00, ...],  // Order 4
    [0x01, ...],  // Order 1 (identity)
    // ... 5 more small-order points
];

fn is_low_order_point(key: &[u8; 32]) -> bool {
    LOW_ORDER_POINTS.iter().any(|p| p == key)
}
```

Defense-in-depth against invalid key attacks per RFC 7748 recommendations.

---

## 6. Cryptographic Design

### 6.1 Encryption model: MIK-only (v0.2)

The current version uses stateless encryption where each message includes its own key exchange material:

```
┌─────────────────────────────────────────────────────────┐
│                    OuterEnvelope                        │
├─────────────────────────────────────────────────────────┤
│  ephemeral_key: [u8; 32]    // Fresh X25519 pubkey     │
│  inner_ciphertext: Vec<u8>  // Encrypted InnerEnvelope │
└─────────────────────────────────────────────────────────┘
```

**Encryption (sender):**
```
1. Generate ephemeral keypair (e, E)
2. shared_secret = X25519(e, recipient_MIK)
3. enc_key = BLAKE3_KDF("reme-encryption-key-v0", E || recipient_MIK || shared_secret)
4. nonce = BLAKE3_KDF("reme-nonce-v0", message_id || recipient_MIK)[0:12]
5. ciphertext = ChaCha20Poly1305_Encrypt(enc_key, nonce, plaintext, AAD=message_id)
```

**Decryption (recipient):**
```
1. shared_secret = X25519(mik_private, ephemeral_key)
2. enc_key = BLAKE3_KDF("reme-encryption-key-v0", ephemeral_key || mik_public || shared_secret)
3. nonce = BLAKE3_KDF("reme-nonce-v0", message_id || mik_public)[0:12]
4. plaintext = ChaCha20Poly1305_Decrypt(enc_key, nonce, ciphertext, AAD=message_id)
```

### 6.2 Triple binding

Each message cryptographically binds three elements:

1. **Nonce derivation**: `nonce = f(message_id, recipient_pk)` - binds message to recipient
2. **AAD verification**: `message_id` as additional authenticated data - binds ciphertext to message
3. **Signature**: `sign(from || timestamp || content || DAG_fields || message_id)` - binds sender to content

This prevents:
- Message forwarding attacks (recipient binding)
- Message ID manipulation (AAD binding)
- Sender impersonation (signature binding)

### 6.3 Key derivation

All key derivation uses BLAKE3 in KDF mode with context strings:

```rust
fn derive_key_from_shared(
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
    shared_secret: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("reme-encryption-key-v0");
    hasher.update(ephemeral_public);
    hasher.update(recipient_public);
    hasher.update(shared_secret);
    *hasher.finalize().as_bytes()
}
```

Including both public keys prevents key confusion attacks where an attacker might claim a ciphertext was intended for a different recipient.

### 6.4 Future: Async Noise handshake (v1.0)

Version 1.0 will add the **Async DTN-Safe Noise XX Handshake** for forward secrecy and post-compromise security:

```
┌─────────────────────────────────────────────────────────┐
│  Noise XX Handshake (DTN-Safe)                         │
│  ─────────────────────────────────────────────────────  │
│  1. Encrypted sender in OuterEnvelope (+16 bytes)      │
│  2. Either party can initiate (deterministic roles)    │
│  3. Epoch-based replay protection                      │
│  4. DAG-integrated key lifecycle (delete after ACK)    │
│  5. MIK fallback when session unavailable              │
└─────────────────────────────────────────────────────────┘
```

---

## 7. Message Format and Wire Protocol

### 7.1 OuterEnvelope

The outer envelope contains routing metadata visible to relay nodes:

```rust
pub struct OuterEnvelope {
    version: Version,           // 2 bytes (major.minor)
    routing_key: [u8; 16],      // 16 bytes (truncated BLAKE3)
    timestamp_hours: u32,       // 4 bytes (hour granularity)
    ttl_hours: Option<u16>,     // 0 or 3 bytes
    message_id: MessageID,      // 16 bytes (UUID v4)
    ephemeral_key: [u8; 32],    // 32 bytes (X25519 pubkey)
    inner_ciphertext: Vec<u8>,  // Variable (encrypted InnerEnvelope)
}
```

**Size analysis:**
- Fixed overhead: ~73 bytes
- Ciphertext overhead: +16 bytes (Poly1305 tag)
- Total minimum: ~89 bytes + content

### 7.2 InnerEnvelope

The inner envelope contains authenticated message data:

```rust
pub struct InnerEnvelope {
    from: PublicID,                    // 32 bytes
    created_at_ms: u64,                // 8 bytes (precise timestamp)
    content: Content,                  // Variable
    signature: Option<[u8; 64]>,       // 0 or 64 bytes

    // DAG fields
    prev_self: Option<ContentId>,      // 0 or 8 bytes
    observed_heads: Vec<ContentId>,    // Variable (usually 0-16 bytes)
    epoch: u16,                        // 2 bytes
    flags: u8,                         // 1 byte
}
```

### 7.3 Content types

```rust
pub enum Content {
    Text(TextContent),       // UTF-8 string
    Receipt(ReceiptContent), // Delivery/read receipt
}

pub struct TextContent {
    body: String,
}

pub struct ReceiptContent {
    target_message_id: MessageID,
    kind: ReceiptKind,  // Delivered | Read
}
```

### 7.4 Wire type discrimination

Messages and tombstones share the transport with a 1-byte discriminator:

```
0x00: Message (OuterEnvelope)
0x01: Tombstone (TombstoneEnvelope)
```

### 7.5 Timestamp design

reme uses a dual-timestamp model for privacy:

- **Outer envelope**: Hour-granularity (`u32`, ~490,000 year range)
- **Inner envelope**: Millisecond precision (`u64`)

Hour granularity on the outer envelope:
- Limits timing analysis by relay nodes
- Saves 4 bytes vs. millisecond timestamps
- Sufficient for TTL enforcement

---

## 8. DAG-Based Message Ordering

### 8.1 Content-addressed identifiers

Each message has a content-addressed ID computed from immutable fields:

```rust
pub fn content_id(&self) -> ContentId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"reme-content-id-v1");
    hasher.update(&self.from.to_bytes());       // Sender identity
    hasher.update(&self.created_at_ms.to_le_bytes());  // Timestamp
    hasher.update(&content_bytes);              // Content
    hash[..8].try_into().unwrap()  // 8-byte truncation
}
```

**Design rationale:**
- 8 bytes provides ~4 billion messages before birthday collision
- BLAKE3 truncation is safe (XOF design)
- DAG fields excluded so resends maintain same content_id

### 8.2 DAG structure

Messages form a directed acyclic graph through references:

```
┌─────────────────────────────────────────────────────────┐
│  Alice's view of conversation with Bob                 │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  A1 ──────────── A2 ──────────── A3                    │
│   \              / \                                    │
│    \            /   observed_heads                      │
│     \          /                                        │
│      ▼        ▼                                         │
│       B1 ──── B2                                        │
│                                                         │
│  prev_self: Links own messages (A1→A2→A3)              │
│  observed_heads: Links to peer's messages seen         │
└─────────────────────────────────────────────────────────┘
```

**Fields:**
- `prev_self`: Reference to sender's previous message (chain continuity)
- `observed_heads`: References to peer's latest messages seen (acknowledgment)
- `epoch`: Conversation epoch (increments on history clear)
- `flags`: Message flags (e.g., `FLAG_DETACHED` for constrained transports)

### 8.3 Gap detection

**Receiver gap detector** tracks incoming message ancestry:

```rust
pub fn on_receive(
    &mut self,
    content_id: ContentId,
    prev_self: Option<ContentId>,
    received_at_ms: u64,
) -> GapResult {
    match prev_self {
        None => GapResult::Complete { resolved_orphans: vec![] },
        Some(parent_id) => {
            if self.complete.contains(&parent_id) {
                GapResult::Complete { resolved_orphans: self.try_resolve_orphans(content_id) }
            } else {
                GapResult::Gap { missing: vec![parent_id] }
            }
        }
    }
}
```

**Sender gap detector** tracks what peer has seen:

```rust
pub fn find_missing(&self, peer_observed: &[ContentId]) -> Vec<ContentId> {
    // Returns messages peer hasn't acknowledged
}
```

### 8.4 Multi-head support

The DAG supports multiple heads (fork scenarios):

- **Multi-device**: Same user sending from phone + laptop
- **Concurrent sends**: Race conditions creating parallel branches

```rust
pub struct SenderGapDetector {
    sent: HashMap<ContentId, Option<ContentId>>,
    heads: HashSet<ContentId>,  // Multiple heads supported
}
```

### 8.5 State reset detection

Three anomaly conditions are detected:

1. **Sender state reset**: Peer sends `prev_self=None` without `FLAG_DETACHED` when we have history
2. **Local state behind**: Peer's `observed_heads` contains IDs we don't recognize
3. **Epoch mismatch**: Peer advanced epoch (intentional history clear)

### 8.6 Detached messages

For constrained transports (LoRa, BLE), messages can be sent without DAG linkage:

```rust
pub const FLAG_DETACHED: u8 = 0x01;

// Detached message has:
// - prev_self: None
// - observed_heads: []
// - flags: FLAG_DETACHED
```

Detached messages:
- Save ~16 bytes of DAG overhead
- Can be linked later when followed by a linked message
- Don't trigger state reset detection

---

## 9. Tombstone System

### 9.1 Purpose

Tombstones have two purposes:

1. **Network layer**: Cache clearing and duplicate delivery prevention
2. **Application layer**: Optional delivery/read receipts

### 9.2 TombstoneEnvelope

```rust
pub struct TombstoneEnvelope {
    version: Version,
    target_message_id: MessageID,   // Message being acknowledged
    routing_key: RoutingKey,        // Mailbox where message was stored
    recipient_id_pub: [u8; 32],     // For signature verification
    device_id: [u8; 16],            // Per-device sequence management
    timestamp_hours: u32,           // Hour granularity
    sequence: u64,                  // Monotonic per device
    signature: [u8; 64],            // XEdDSA signature
    encrypted_receipt: Option<Vec<u8>>,  // Optional sender-visible receipt
}
```

### 9.3 Security properties

**Signed by recipient**: Only the legitimate recipient can create valid tombstones

**Replay prevention**:
- `timestamp_hours` limits validity window (10 days max)
- `sequence` allows ordering detection
- `device_id` isolates sequences per device

**Verifiable by relays**: Any node can verify tombstone authenticity without decrypting messages

### 9.4 Encrypted receipt (optional)

Detailed receipts encrypted for sender:

```rust
pub struct DetailedReceipt {
    precise_timestamp_secs: u64,
    status: TombstoneStatus,  // Delivered | Read | Deleted
    proof_of_content: Option<[u8; 32]>,  // HMAC proving decryption
}
```

Encrypted using ephemeral X25519 + ChaCha20-Poly1305 to sender's public key.

---

## 10. Transport Layer

### 10.1 Transport trait

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    async fn submit_message(&self, envelope: OuterEnvelope) -> Result<(), TransportError>;
    async fn submit_tombstone(&self, tombstone: TombstoneEnvelope) -> Result<(), TransportError>;
}
```

### 10.2 HTTP transport

Primary transport for reliable connectivity:

- **Endpoint**: `POST /api/v1/messages` (submit)
- **Endpoint**: `GET /api/v1/messages/:routing_key` (fetch)
- **Endpoint**: `POST /api/v1/tombstones` (acknowledge)

### 10.3 Future transports

**LoRa/Meshtastic:**
- MTU: ~200 bytes
- Requires fragmentation for larger messages
- Uses detached messages to minimize overhead
- Store-and-forward through mesh network

**BLE proximity:**
- Direct device-to-device exchange
- Background scanning for contacts
- Useful for censorship-resistant scenarios

**Sneakernet:**
- QR code or file-based message transfer
- Complete offline operation

### 10.4 Mailbox node

Simple store-and-forward relay:

```rust
// Storage: routing_key -> Vec<OuterEnvelope>
// TTL enforcement: Remove expired messages
// Tombstone handling: Clear acknowledged messages
```

Nodes learn only:
- Routing keys (not full identities)
- Message sizes
- Coarse timestamps (hour granularity)
- When tombstones clear messages

### 10.5 Node identity verification (v0.4)

For dynamically discovered peers (mDNS), identity verification ensures messages reach the intended recipient.

**Challenge-response protocol:**
```
Client                              Node
   |                                  |
   |  GET /identity?challenge=<C>     |
   |--------------------------------->|
   |                                  |
   |  { node_pubkey, routing_keys,    |
   |    signature: XEdDSA(C || pk) }  |
   |<---------------------------------|
   |                                  |
   |  Verify signature                |
   |  Check routing_key in list       |
```

**Two operating modes:**

| Mode | Use Case | Identity Required |
|------|----------|-------------------|
| **Direct** | Peer IS the recipient | Yes - verify `routing_key` matches |
| **Relay** | Peer forwards to external recipient | No - E2E encrypted payload |

**Background refresh:**
- Periodic identity refresh (5 min default) detects DHCP reassignment
- Refresh on delivery failure or network change
- Stale identities removed from Direct tier automatically

---

## 11. Security Analysis

### 11.1 Confidentiality

**Message content**: Protected by ChaCha20-Poly1305 authenticated encryption with per-message ephemeral keys.

**Metadata**: Coarse timestamps, routing keys (not full identities), and message sizes are visible to relays.

### 11.2 Authenticity

**Sender verification**: XEdDSA signature in `InnerEnvelope` proves sender identity.

**Message integrity**: Poly1305 MAC prevents modification.

**Recipient binding**: ECDH ensures only intended recipient can decrypt.

### 11.3 Forward secrecy

**MIK-only (v0.3)**: Limited forward secrecy - compromise of MIK reveals all messages encrypted to it.

**Async Noise (v1.0)**: Will provide per-session forward secrecy through Noise XX handshake with DAG-integrated key lifecycle. Keys deleted after DAG acknowledgment.

### 11.4 Replay protection

**Messages**: UUID message_id provides uniqueness.

**Tombstones**: Timestamp + sequence + device_id prevents replay.

### 11.5 Denial of service

**Message flooding**: Rate limiting at relay nodes.

**Storage exhaustion**: TTL enforcement, tombstone clearing.

**Invalid key attacks**: Low-order point validation.

### 11.6 Side channels

**Timing**: Hour-granularity outer timestamps limit timing analysis.

**Message size**: No padding in v0.2; fixed-size padding planned for v1.0.

---

## 12. Comparison with Existing Systems

### 12.1 Signal Protocol

| Aspect            | Signal                            | reme                                           |
|-------------------|-----------------------------------|------------------------------------------------|
| Key Exchange      | X3DH with server-mediated prekeys | Direct MIK encryption, Noise XX (v1.0)         |
| Forward Secrecy   | Double Ratchet                    | Per-ephemeral-key, per-session Noise XX (v1.0) |
| Identity          | Phone number                      | Self-sovereign 32-byte key                     |
| Server Dependency | Required for delivery             | Optional mailboxes                             |
| Offline First     | No                                | Yes                                            |

### 12.2 Session Protocol

| Aspect           | Session                         | reme                |
|------------------|---------------------------------|---------------------|
| Routing          | Onion request via service nodes | Direct to mailbox   |
| Latency          | Higher (onion routing)          | Lower (direct)      |
| Decentralization | Oxen network required           | Any mailbox, or P2P |
| Message Ordering | Server timestamps               | Merkle DAG          |

### 12.3 Matrix Protocol

| Aspect       | Matrix                 | reme                 |
|--------------|------------------------|----------------------|
| Architecture | Federated servers      | Optional mailboxes   |
| Room Model   | Multi-user rooms       | 1:1 (groups planned) |
| Encryption   | Megolm + Olm           | X25519 + ChaCha20    |
| Metadata     | Significant to servers | Minimal to relays    |

### 12.4 Briar

| Aspect       | Briar            | reme                      |
|--------------|------------------|---------------------------|
| Network      | Tor, BT, WiFi    | HTTP, LoRa, BLE (planned) |
| Desktop      | Android only     | Cross-platform (Rust)     |
| Offline      | Requires restart | Continuous operation      |
| Message Sync | Per-contact DAG  | Per-contact DAG           |

---

## 13. Future Directions

### 13.1 Version 1.0: Async Noise handshake

- Noise XX session establishment (no prekey servers)
- Encrypted sender field for key-loss recovery
- DAG-integrated key lifecycle (delete after ACK)
- Per-session forward secrecy

### 13.2 Group messaging

- Sender Keys for efficient group encryption
- Group membership DAG
- Admin operations (add/remove/promote)

### 13.3 Alternative transports

- Satellite uplinks
- Ham radio digital modes

### 13.4 Privacy improvements

- Fixed-size message padding
- Cover traffic
- Routing key rotation
- Mixnet integration

### 13.5 State recovery

- Merkle accumulator sync
- Selective message resync
- Cross-device state merge

---

## 14. Conclusion

Reme is a different approach to secure messaging for adversarial network conditions. It combines stateless encryption (each message is independently processable), Merkle DAG ordering (decentralized causality), transport-agnostic design (constrained channels work), and cryptographic tombstones (verifiable acknowledgments).

The current MIK-only implementation provides a solid foundation, with a clear upgrade path to Async Noise XX handshake for forward secrecy. The modular Rust implementation can be embedded in command-line tools, mobile apps, and embedded devices.

The tradeoff is explicit: reme prioritizes resilience and DTN tolerance over the per-message forward secrecy that Double Ratchet provides. For users who need messaging when infrastructure fails, this tradeoff makes sense.

---

## Appendices

### A. Cryptographic primitive summary

| Primitive    | Algorithm         | Parameters                             |
|--------------|-------------------|----------------------------------------|
| Key Exchange | X25519            | Curve25519, 32-byte keys               |
| Signatures   | XEdDSA            | Ed25519-compatible, 64-byte signatures |
| Encryption   | ChaCha20-Poly1305 | 256-bit key, 96-bit nonce, 128-bit tag |
| Hashing      | BLAKE3            | Variable output, XOF mode              |
| KDF          | BLAKE3-KDF        | Context strings for domain separation  |
| Message ID   | UUID v4           | 128-bit random                         |
| Content ID   | BLAKE3 truncated  | 64-bit (8 bytes)                       |

### B. Wire format sizes

| Component              | Size                         |
|------------------------|------------------------------|
| PublicID               | 32 bytes                     |
| RoutingKey             | 16 bytes                     |
| MessageID              | 16 bytes                     |
| ContentId              | 8 bytes                      |
| Signature              | 64 bytes                     |
| Poly1305 tag           | 16 bytes                     |
| OuterEnvelope overhead | ~73 bytes                    |
| InnerEnvelope minimum  | ~107 bytes (with signature)  |
| Tombstone              | ~155 bytes (without receipt) |

### C. References

1. Perrin, T., & Marlinspike, M. (2016). The X3DH Key Agreement Protocol.
2. Perrin, T., & Marlinspike, M. (2016). The Double Ratchet Algorithm.
3. Hamburg, M. (2015). The XEdDSA and VXEdDSA Signature Schemes.
4. Bernstein, D.J. (2006). Curve25519: new Diffie-Hellman speed records.
5. Nir, Y., & Langley, A. (2018). RFC 8439: ChaCha20 and Poly1305.
6. O'Connor, J., et al. (2020). BLAKE3: one function, fast everywhere.

---

*This document describes Resilient Messenger version 0.3 (Tiered Delivery). The protocol is under active development; specifications may change.*

## Appendix D. Current implementation status (v0.3)

### Completed features

**Core cryptography & protocol (v0.2):**
- X25519/XEdDSA identity system
- MIK-based stateless encryption
- ChaCha20-Poly1305 AEAD with per-message ephemeral keys
- BLAKE3 key derivation with domain separation
- XEdDSA signatures for message authentication
- Low-order point validation
- Tombstone V2 (ack_secret-based authorization)
- Merkle DAG message ordering with gap detection

**Transport & delivery (v0.3):**
- HTTP transport with TLS/certificate pinning
- MQTT transport (pub/sub)
- TransportCoordinator for multi-transport routing
- Tiered delivery (Direct/Quorum/BestEffort)
- Three-phase delivery state machine (Urgent/Distributed/Confirmed)
- Configurable quorum strategies (Any/Count/Fraction/All)
- Per-transport retry policies with exponential backoff
- Embedded HTTP server for LAN P2P messaging
- Node-to-node authentication with XEdDSA signatures

**Storage & state:**
- SQLite persistence for messages and contacts
- Outbox with delivery state tracking
- Receiver gap detector (orphan tracking)
- Sender gap detector (epoch-based)
- DAG-based implicit acknowledgments

**Security & hardening:**
- HTTP Basic Auth for node access
- Rate limiting (per-IP and per-routing-key)
- Body size limits (256 KiB max)
- Memory zeroization for credentials
- Constant-time comparisons for auth

**Applications:**
- TUI client with ratatui
- Mailbox node server
- Client-as-relay capability (embedded node)

### In progress

**Current development (v0.4):**
- mDNS/Bonjour LAN discovery
- Discovery-flow integration for challenge-response node identity verification
- Background identity refresh for Direct tier targets

### Planned features (see ROADMAP.md)

**v0.5:**
- Sneakernet export/import (archive files, QR codes)
- Air-gapped message transfer

**v0.6:**
- LAN relay mode for partial outage scenarios
- Route messages through peers with Internet connectivity

**v0.7:**
- BLE proximity exchange
- Message fragmentation for constrained transports

**v0.8:**
- LoRa/Meshtastic mesh integration
- Multi-hop store-and-forward routing
- Kilometers-range messaging without Internet

**v1.0 (breaking release):**
- Protobuf wire format for cross-language compatibility
- Async Noise XX handshake for forward secrecy
- DAG-integrated key lifecycle

**Post-v1.0:**
- Group messaging (Sender Keys)
- Cross-device state synchronization
- Privacy improvements (padding, cover traffic)
