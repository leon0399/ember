# Group Chat Integration Research

> Research document analyzing approaches to integrate public group chats into reme, a DTN-first outage-resilient encrypted messenger.

## Executive Summary

This document evaluates four main approaches for adding group chat functionality to reme:

| Approach | DTN Suitability | Security | Complexity | Recommendation |
|----------|-----------------|----------|------------|----------------|
| Matrix Protocol | ❌ Poor | ✅ Strong (Megolm) | High | Not recommended |
| Signal Sender Keys | ⚠️ Needs adaptation | ⚠️ Weak PCS | Low-Medium | Good baseline |
| MLS (OpenMLS) | ❌ Poor | ✅ Strong | High | Not recommended |
| Custom Briar-inspired | ✅ Excellent | Configurable | Medium | **Recommended** |

**Recommendation**: Build a custom group messaging layer inspired by Briar's Bramble protocol, using Sender Keys for efficiency with CRDT-based state synchronization for DTN resilience.

---

## Table of Contents

1. [Current reme Architecture](#current-reme-architecture)
2. [Requirements for Group Chat](#requirements-for-group-chat)
3. [Matrix Protocol Analysis](#matrix-protocol-analysis)
4. [Signal Sender Keys Analysis](#signal-sender-keys-analysis)
5. [MLS Protocol Analysis](#mls-protocol-analysis)
6. [Custom DTN-First Approach](#custom-dtn-first-approach)
7. [Implementation Recommendations](#implementation-recommendations)
8. [References](#references)

---

## Current reme Architecture

### Relevant Characteristics

- **1:1 messaging only** (current scope)
- **Stateless encryption**: X25519/XEdDSA/ChaCha20-Poly1305
- **Merkle DAG ordering**: Causal message ordering via `prev_self` and `observed_heads`
- **Transport-agnostic**: HTTP, MQTT, (future: LoRa, BLE, Meshtastic)
- **DTN-first design**: No session establishment, zero-RTT first message
- **Identity**: Single MIK (Master Identity Key) for both ECDH and signatures

### Key Constraints for Group Messaging

1. **No persistent sessions** - stateless by design
2. **Multi-transport delivery** - must work over constrained transports (LoRa: 1-2KB payloads)
3. **Delay tolerance** - messages may arrive out of order, days/weeks apart
4. **No central server** - relay nodes are untrusted store-and-forward
5. **Offline-first** - clients may be disconnected for extended periods

---

## Requirements for Group Chat

### Functional Requirements

| Requirement | Priority | Notes |
|-------------|----------|-------|
| Public group creation | P0 | Anyone can create a group |
| Member management | P0 | Add/remove members |
| Message broadcast | P0 | Send to all members |
| Offline message sync | P0 | **Critical for DTN** |
| Message ordering | P1 | Causal ordering via DAG |
| Message history | P1 | New members can/cannot see history |
| Group metadata sync | P1 | Name, description, member list |
| Large group support | P2 | 100+ members |
| Admin roles | P2 | Elevated permissions |

### Security Requirements

| Requirement | Priority | Notes |
|-------------|----------|-------|
| End-to-end encryption | P0 | Server cannot read messages |
| Forward secrecy | P1 | Past messages protected if key compromised |
| Post-compromise security | P1 | Recovery after key compromise |
| Member authentication | P0 | Verify sender identity |
| Replay protection | P0 | Prevent message replay |
| Membership verification | P1 | Cryptographic proof of membership |

### DTN-Specific Requirements

| Requirement | Priority | Notes |
|-------------|----------|-------|
| No continuous connectivity | P0 | Must work offline |
| Store-and-forward compatible | P0 | Works with relay nodes |
| Partition tolerance | P0 | Groups can split and rejoin |
| Bandwidth efficiency | P1 | LoRa: ~250 bytes/message |
| Battery efficiency | P1 | Symmetric crypto preferred |
| Conflict resolution | P1 | Handle concurrent edits |

---

## Matrix Protocol Analysis

### Overview

Matrix is a federated, open-standard communication protocol with end-to-end encryption via Megolm.

### Rust SDK Availability

- **matrix-rust-sdk**: Production-ready, maintained by Element
- **ruma**: Low-level types and API bindings

### Encryption (Megolm)

```
Megolm Architecture:
- Each group session has a sender key
- Hash ratchet provides forward secrecy
- AES-256 + HMAC-SHA-256 for encryption
```

**Strengths:**
- Mature implementation
- Forward secrecy via ratcheting
- Scales to large groups

**Weaknesses:**
- No strong post-compromise security
- Complex key distribution
- Recent vulnerabilities discovered (Nebuchadnezzar study)

### DTN Suitability: ❌ Poor

**Critical Issues:**

1. **No client-side offline queuing**: Matrix assumes continuous connectivity
2. **Synchronous API**: Request-response pattern incompatible with DTN
3. **Federation overhead**: Server-to-server sync adds complexity
4. **No local-first design**: Requires homeserver connection

### Verdict

Matrix is **not recommended** for reme. The protocol fundamentally assumes online connectivity and would require extensive custom offline layers, negating the benefits of using an existing protocol.

---

## Signal Sender Keys Analysis

### Overview

Signal's Sender Keys protocol distributes symmetric keys for efficient group encryption. Each sender has a unique key shared with all group members.

### How It Works

```
1. Sender generates random 32-byte Chain Key
2. Chain Key → Message Key via hash derivation (forward secrecy)
3. Message encrypted with AES-256-CBC
4. Ciphertext signed with Signature Key
5. Sender Key distributed to members via 1:1 channels
```

### Rust Implementation

**libsignal-protocol-rust** (official Signal implementation):
- `SenderKeyMessage` type for group messages
- `InMemSenderKeyStore` for key storage
- Full protocol state management

### Cryptographic Properties

| Property | Rating | Notes |
|----------|--------|-------|
| Forward Secrecy | ✅ Strong | Hash ratchet mechanism |
| Post-Compromise Security | ⚠️ Weak | No automatic healing |
| Computational Efficiency | ✅ Excellent | Symmetric crypto only |
| Bandwidth Efficiency | ✅ Good | Single encryption per message |

### DTN Suitability: ⚠️ Needs Adaptation

**Advantages for DTN:**
- Low computational overhead (battery-friendly)
- Compatible with store-and-forward
- Single encryption per message (bandwidth-efficient)

**Challenges for DTN:**
- Key rotation only on membership changes
- No periodic re-keying for isolated nodes
- Weak PCS becomes critical in extended isolation
- No mechanism for partition recovery

### Required Adaptations for reme

```rust
// Proposed adaptations for DTN
struct DtnSenderKey {
    chain_key: [u8; 32],
    message_index: u32,
    // DTN adaptations:
    epoch: u16,                    // Time-based rotation
    last_rotation_timestamp: u64,  // For time-based rotation
    version: u16,                  // For partition recovery
}
```

1. **Time-based key rotation**: Rotate keys every N hours even without membership changes
2. **Epoch-based versioning**: Track key versions across partitions
3. **Gossip-based refresh**: Opportunistic key updates when nodes reconnect
4. **Graceful degradation**: Fall back to 1:1 encryption if group keys stale

### Verdict

Sender Keys is a **reasonable baseline** but requires significant adaptation for DTN. Consider as foundation with custom extensions.

---

## MLS Protocol Analysis

### Overview

MLS (Messaging Layer Security, RFC 9420) is an IETF standard using tree-based key management for O(log n) scaling.

### Rust Implementation

**OpenMLS** (production-ready):
- Full RFC 9420 implementation
- Safe API hiding cryptographic complexity
- Active development

### Cryptographic Properties

| Property | Rating | Notes |
|----------|--------|-------|
| Forward Secrecy | ✅ Strong | Per-update FS |
| Post-Compromise Security | ✅ Strong | Tree-based healing |
| Scalability | ✅ Excellent | O(log n) updates |
| Membership Verification | ✅ Strong | Cryptographic binding |

### DTN Suitability: ❌ Poor

**Critical Issues:**

1. **Requires Authentication Service**: Trusted service for key-to-identity binding
2. **Requires Delivery Service**: Reliable message delivery assumed
3. **Bi-directional paths**: Key exchange requires round-trips
4. **No offline support**: Designed for continuous online operation

### Verdict

MLS is **not recommended** for reme. Despite superior security properties, its architectural requirements are fundamentally incompatible with DTN.

---

## Custom DTN-First Approach

### Inspiration: Briar's Bramble Protocol

Briar is a battle-tested messenger designed for censorship-resistant, offline-first communication.

**Key Design Principles:**
- Fully peer-to-peer (no central servers)
- Offline sync via Bluetooth/Wi-Fi Direct + Tor
- Forums survive as long as one subscriber holds data
- No single points of failure

### Proposed Architecture for reme

```
┌─────────────────────────────────────────────────────────┐
│                    GROUP LAYER                          │
├─────────────────────────────────────────────────────────┤
│  GroupIdentity                                          │
│  ├── group_id: [u8; 32]        (BLAKE3 hash of params) │
│  ├── name: String                                       │
│  ├── creator: PublicID                                  │
│  └── created_at: u64                                    │
├─────────────────────────────────────────────────────────┤
│  GroupMembership (CRDT-based)                          │
│  ├── members: LWWMap<PublicID, MemberState>            │
│  ├── admins: LWWSet<PublicID>                          │
│  ├── epoch: HLC (Hybrid Logical Clock)                 │
│  └── merkle_root: [u8; 32]                             │
├─────────────────────────────────────────────────────────┤
│  GroupEncryption (Sender Keys variant)                 │
│  ├── sender_keys: Map<PublicID, SenderKeyState>        │
│  ├── rotation_interval_hours: u32                      │
│  └── epoch_keys: Map<u16, ChainKey>                    │
├─────────────────────────────────────────────────────────┤
│  GroupDAG (extends existing ConversationDag)           │
│  ├── messages: MerkleDag<GroupMessage>                 │
│  ├── membership_events: MerkleDag<MembershipChange>    │
│  └── sync_state: Map<PublicID, SyncCheckpoint>         │
└─────────────────────────────────────────────────────────┘
```

### Component 1: Group Identity

```rust
/// Unique group identifier and metadata
pub struct GroupIdentity {
    /// BLAKE3(creator_pubid || created_at || random_nonce)
    pub group_id: GroupId,
    /// Human-readable name
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Creator's PublicID
    pub creator: PublicID,
    /// Creation timestamp (milliseconds)
    pub created_at_ms: u64,
    /// Random nonce for uniqueness
    pub nonce: [u8; 16],
}

/// 32-byte group identifier
pub type GroupId = [u8; 32];
```

### Component 2: CRDT-Based Membership

Using CRDTs for membership state enables:
- Conflict-free merge after network partitions
- No coordination required for concurrent updates
- Deterministic state across all members

```rust
use crdts::{LWWReg, Map, VClock};

/// CRDT-based group membership
pub struct GroupMembership {
    /// Member states (add/remove are LWW operations)
    pub members: Map<PublicID, LWWReg<MemberState, HLC>>,
    /// Admin set
    pub admins: Map<PublicID, LWWReg<bool, HLC>>,
    /// Vector clock for ordering
    pub vclock: VClock<PublicID>,
}

#[derive(Clone, Debug)]
pub enum MemberState {
    Active,
    Removed { at: u64, by: PublicID },
    Left { at: u64 },
}

/// Hybrid Logical Clock for ordering in DTN
pub struct HLC {
    pub wall_time_ms: u64,
    pub logical: u32,
    pub node_id: PublicID,
}
```

### Component 3: DTN-Adapted Sender Keys

```rust
/// Extended Sender Keys for DTN environments
pub struct DtnSenderKey {
    /// Current chain key
    pub chain_key: [u8; 32],
    /// Message index (ratchets forward)
    pub message_index: u32,
    /// Key epoch (increments on rotation)
    pub epoch: u16,
    /// Last rotation timestamp
    pub rotated_at_ms: u64,
    /// Signature key for this sender
    pub signature_key: Ed25519PublicKey,
}

/// Key rotation triggers
pub enum RotationTrigger {
    /// Member removed from group
    MemberRemoved(PublicID),
    /// Time-based rotation (e.g., every 24 hours)
    TimeBasedRotation { interval_hours: u32 },
    /// Manual rotation requested
    ManualRotation,
    /// Partition recovery (nodes rejoining)
    PartitionRecovery { partition_id: u64 },
}
```

### Component 4: Group Message Format

```rust
/// Wire format for group messages
pub struct GroupOuterEnvelope {
    pub version: Version,
    /// Group routing key (BLAKE3 prefix of group_id)
    pub group_routing_key: RoutingKey,
    pub timestamp_hours: u32,
    pub ttl_hours: Option<u32>,
    pub message_id: MessageID,
    /// Sender's ephemeral key for this message
    pub ephemeral_key: [u8; 32],
    /// Sender's public ID (for sender key lookup)
    pub sender_id: PublicID,
    /// Sender key epoch used
    pub sender_key_epoch: u16,
    /// Encrypted inner envelope
    pub inner_ciphertext: Vec<u8>,
}

pub struct GroupInnerEnvelope {
    pub sender: PublicID,
    pub created_at_ms: u64,
    pub content: GroupContent,
    /// DAG linkage
    pub prev_self: Option<ContentId>,
    pub observed_heads: Vec<ContentId>,
    /// Membership state hash (for consistency check)
    pub membership_hash: [u8; 16],
}

pub enum GroupContent {
    /// Regular text message
    Text { body: String },
    /// Membership change event
    MembershipChange(MembershipEvent),
    /// Key rotation announcement
    KeyRotation(KeyRotationEvent),
    /// Sync request/response
    Sync(SyncPayload),
}
```

### Component 5: Sync Protocol

```rust
/// Sync protocol for DTN group state recovery
pub enum SyncPayload {
    /// Request state from peers
    StateRequest {
        /// My current membership hash
        my_membership_hash: [u8; 16],
        /// My sender key epochs
        my_key_epochs: Vec<(PublicID, u16)>,
        /// Messages I have (bloom filter)
        message_bloom: BloomFilter,
    },
    /// Respond with missing state
    StateResponse {
        /// Membership deltas
        membership_ops: Vec<MembershipOp>,
        /// Updated sender keys (encrypted to requester)
        sender_keys: Vec<EncryptedSenderKey>,
        /// Missing messages
        messages: Vec<GroupOuterEnvelope>,
    },
}

/// Compact bloom filter for message sync
pub struct BloomFilter {
    pub bits: Vec<u8>,
    pub hash_count: u8,
}
```

### Public Group Considerations

For **public groups** (anyone can join/read):

```rust
pub struct PublicGroupConfig {
    /// Group is publicly discoverable
    pub discoverable: bool,
    /// Join policy
    pub join_policy: JoinPolicy,
    /// Message retention policy
    pub retention: RetentionPolicy,
    /// Whether to encrypt messages (for deniability even if public)
    pub encrypt_messages: bool,
}

pub enum JoinPolicy {
    /// Anyone with group_id can join
    Open,
    /// Requires approval from admin
    ApprovalRequired,
    /// Requires invite link
    InviteOnly { link_id: [u8; 16] },
}
```

### Bandwidth Optimization for LoRa

For constrained transports (LoRa: ~250 bytes/message):

```rust
/// Compact message format for constrained transports
pub struct CompactGroupMessage {
    /// Truncated group ID (8 bytes)
    pub group_id_short: [u8; 8],
    /// Message ID (8 bytes, truncated UUID)
    pub message_id_short: [u8; 8],
    /// Sender key epoch (2 bytes)
    pub epoch: u16,
    /// Message index (4 bytes)
    pub message_index: u32,
    /// Ciphertext (remaining ~230 bytes)
    pub ciphertext: Vec<u8>,
}
// Total: ~250 bytes for LoRa compatibility
```

---

## Implementation Recommendations

### Phase 1: Foundation (Minimal Viable Group)

1. **Create `reme-group` crate** with:
   - `GroupIdentity` and `GroupId` types
   - Basic membership tracking (non-CRDT initially)
   - Sender Keys encryption (adapted from libsignal)
   - Group message envelope format

2. **Extend storage schema**:
   ```sql
   CREATE TABLE groups (
       group_id BLOB PRIMARY KEY,
       name TEXT NOT NULL,
       creator_id BLOB NOT NULL,
       created_at INTEGER NOT NULL,
       metadata BLOB  -- bincode-serialized
   );

   CREATE TABLE group_members (
       group_id BLOB NOT NULL,
       member_id BLOB NOT NULL,
       state TEXT NOT NULL,  -- active/removed/left
       updated_at INTEGER NOT NULL,
       PRIMARY KEY (group_id, member_id)
   );

   CREATE TABLE group_sender_keys (
       group_id BLOB NOT NULL,
       sender_id BLOB NOT NULL,
       epoch INTEGER NOT NULL,
       chain_key BLOB NOT NULL,
       message_index INTEGER NOT NULL,
       PRIMARY KEY (group_id, sender_id, epoch)
   );
   ```

3. **Basic API**:
   ```rust
   impl Client {
       pub fn create_group(&self, name: &str) -> Result<GroupId>;
       pub fn join_group(&self, group_id: GroupId) -> Result<()>;
       pub fn leave_group(&self, group_id: GroupId) -> Result<()>;
       pub fn send_group_message(&self, group_id: GroupId, content: &str) -> Result<MessageId>;
       pub fn fetch_group_messages(&self, group_id: GroupId) -> Result<Vec<GroupMessage>>;
   }
   ```

### Phase 2: CRDT Membership & Sync

1. **Add CRDT dependency**: `automerge` or `crdts` crate
2. **Implement CRDT membership** with HLC ordering
3. **Build sync protocol** for partition recovery
4. **Add bloom filter-based message sync**

### Phase 3: Advanced Features

1. **Time-based key rotation**
2. **Admin roles and permissions**
3. **Public group discovery**
4. **Large group optimizations** (key trees)

### Rust Dependencies

```toml
[dependencies]
# Existing reme dependencies
blake3 = "1"
chacha20poly1305 = "0.10"
x25519-dalek = "2"
ed25519-dalek = "2"

# New for group chat
libsignal-protocol = "0.1"  # For Sender Keys reference
automerge = "0.5"           # For CRDT state
crdts = "7"                 # Alternative CRDT library
uuid = { version = "1", features = ["v4"] }
```

---

## References

### Protocols & Standards
- [Signal Protocol - Wikipedia](https://en.wikipedia.org/wiki/Signal_Protocol)
- [RFC 9420 - MLS Protocol](https://datatracker.ietf.org/doc/rfc9420/)
- [Matrix Specification](https://spec.matrix.org/latest/)
- [Briar Protocol Specs](https://code.briarproject.org/briar/briar-spec)

### Academic Papers
- [Signal Sender Keys Analysis](https://ir.library.oregonstate.edu/downloads/xd07h076n)
- [WhatsUpp with Sender Keys](https://eprint.iacr.org/2023/1385.pdf)
- [Asynchronous Group Messaging](https://eprint.iacr.org/2017/666.pdf)
- [Megolm Vulnerabilities (Nebuchadnezzar)](https://nebuchadnezzar-megolm.github.io/static/paper.pdf)

### Rust Implementations
- [libsignal-protocol-rust](https://github.com/signalapp/libsignal)
- [OpenMLS](https://github.com/openmls/openmls)
- [matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk)
- [Automerge](https://github.com/automerge/automerge)
- [DTN7-rs](https://github.com/dtn7/dtn7-rs)

### Related Projects
- [Briar](https://briarproject.org/)
- [Meshtastic](https://meshtastic.org/)

---

## Appendix: Comparison Matrix

| Feature | Matrix | Sender Keys | MLS | Custom (Recommended) |
|---------|--------|-------------|-----|----------------------|
| **DTN Support** | ❌ | ⚠️ | ❌ | ✅ |
| **Offline Sync** | ❌ | ⚠️ | ❌ | ✅ |
| **Forward Secrecy** | ✅ | ✅ | ✅ | ✅ |
| **Post-Compromise** | ⚠️ | ❌ | ✅ | ⚠️ |
| **Scalability** | ✅ | ✅ | ✅✅ | ✅ |
| **LoRa Compatible** | ❌ | ✅ | ❌ | ✅ |
| **Implementation Effort** | Low | Medium | Low | High |
| **Rust Ecosystem** | ✅✅ | ✅ | ✅✅ | Custom |
| **Battle-Tested** | ✅✅ | ✅✅ | ✅ | ❌ |

---

*Document created: 2026-02-22*
*Author: Research Agent*
*Branch: claude/research-group-chat-integration-RqQyP*
