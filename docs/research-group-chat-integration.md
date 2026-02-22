# Research: Public Group Chat Integration for reme

**Date:** February 2026
**Version:** v0.3 (Tiered Delivery) → Planning for post-v1.0

---

## Executive Summary

This document analyzes approaches for integrating public group chat functionality into Resilient Messenger (reme). Based on the project's goals of **outage resilience**, **DTN tolerance**, **metadata minimization**, and **transport agnosticism**, we evaluate three main approaches:

1. **Matrix Protocol Integration** - Bridging to the Matrix ecosystem
2. **Signal Sender Keys** - Native implementation (already in roadmap)
3. **MLS (Messaging Layer Security)** - IETF standardized protocol

**Recommendation:** Implement a **custom Sender Keys-based protocol** (as planned in ROADMAP.md) with architectural patterns borrowed from MLS for scalability. Matrix integration is **not recommended** due to fundamental architectural incompatibilities.

---

## 1. Current State Analysis

### 1.1 reme's Architecture (from WHITEPAPER.md)

| Aspect | Current State |
|--------|---------------|
| Messaging model | **1:1 only** |
| Encryption | MIK-only (stateless, ephemeral X25519 + ChaCha20-Poly1305) |
| Ordering | Merkle DAG with `prev_self` and `observed_heads` |
| Transports | HTTP, MQTT, planned BLE/LoRa |
| State model | **Stateless** - each message independently decryptable |
| Metadata exposure | Minimal (hour-granular timestamps, routing keys only) |

### 1.2 Group Messaging in Roadmap (ROADMAP.md lines 463-468)

Currently planned for **post-v1.0**:
- Sender Keys protocol (O(1) encryption)
- Multi-sender DAG with per-member gap detection
- Admin operations (add/remove/promote)

### 1.3 Design Constraints for Groups

Any group chat solution must satisfy reme's core principles:

1. **DTN tolerance** - Work without always-on connectivity
2. **Transport agnostic** - Same encrypted payload across HTTP, BLE, LoRa
3. **Minimal metadata** - Relays shouldn't learn group membership
4. **Bandwidth efficient** - LoRa MTU ~200 bytes limits overhead
5. **No mandatory servers** - Groups should work with optional mailboxes only

---

## 2. Option Analysis

### 2.1 Matrix Protocol Integration

#### Overview

Matrix is a federated, open-standard protocol for real-time communication. It uses:
- **Olm** for 1:1 E2E encryption (Double Ratchet)
- **Megolm** for group encryption (hash ratchet)
- **Federation** via homeservers

#### How It Would Work

```
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│ reme Client │──────▶│ Bridge Node │──────▶│ Matrix      │
│             │◀──────│ (Synapse)   │◀──────│ Ecosystem   │
└─────────────┘       └─────────────┘       └─────────────┘
```

A bridge would:
1. Run a Matrix homeserver (Synapse, Dendrite, or Conduit)
2. Translate reme messages to Matrix events
3. Re-encrypt using Megolm for Matrix rooms
4. Maintain federation with other homeservers

#### Pros
- Access to existing Matrix user base
- Mature room management (admin, moderation, permissions)
- Cross-platform clients already exist
- Future MLS adoption (MSC2883)

#### Cons

| Issue | Impact | Severity |
|-------|--------|----------|
| **Always-on servers required** | Federation requires active homeservers | **Critical** |
| **Metadata leakage** | Homeservers see room membership, event graphs, IP addresses | **Critical** |
| **No DTN support** | Matrix sync requires persistent connections | **Critical** |
| **Re-encryption overhead** | Messages must be re-encrypted at bridge | High |
| **Bandwidth inefficient** | Matrix events are large (~1KB+), incompatible with LoRa | High |
| **Dependency on external infrastructure** | Conflicts with self-sovereign design | Medium |

#### Verdict: NOT RECOMMENDED

Matrix's architecture fundamentally conflicts with reme's design goals:
- Matrix is **federation-first**; reme is **DTN-first**
- Matrix requires **always-on infrastructure**; reme uses **optional mailboxes**
- Matrix exposes **significant metadata to servers**; reme **minimizes metadata**

From WHITEPAPER.md section 12.3:
> | Aspect | Matrix | reme |
> |--------|--------|------|
> | Architecture | Federated servers | Optional mailboxes |
> | Metadata | Significant to servers | Minimal to relays |

---

### 2.2 Signal Sender Keys Protocol

#### Overview

Sender Keys is Signal's approach to efficient group encryption:
- Each member has their own "sender key" (symmetric key + chain)
- Sender key is distributed to all group members via pairwise encryption
- Messages encrypted once with sender key, delivered to all members

#### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                      Group Creation                              │
├─────────────────────────────────────────────────────────────────┤
│  1. Admin generates group metadata (ID, name, members)          │
│  2. Each member generates their Sender Key (chain_key, seed)    │
│  3. Sender Keys distributed via pairwise encrypted messages     │
│  4. Group membership stored locally                             │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      Message Send (O(1))                         │
├─────────────────────────────────────────────────────────────────┤
│  1. Ratchet sender key chain forward                            │
│  2. Encrypt message once with current chain key                 │
│  3. Deliver same ciphertext to all members                      │
│  4. Members decrypt using sender's cached sender key            │
└─────────────────────────────────────────────────────────────────┘
```

#### Pros

| Advantage | Description |
|-----------|-------------|
| **O(1) encryption** | Single encryption regardless of group size |
| **DTN compatible** | No session state synchronization required |
| **Fits existing architecture** | Extends current 1:1 pairwise encryption |
| **Already in roadmap** | Post-v1.0 feature (ROADMAP.md) |
| **Bandwidth efficient** | Single ciphertext + key distribution overhead |
| **Transport agnostic** | Same payload works on all transports |

#### Cons

| Issue | Description | Mitigation |
|-------|-------------|------------|
| **No forward secrecy within chain** | Compromised sender key exposes that sender's history | Periodic key rotation |
| **Key distribution overhead** | New member joins = O(n) pairwise messages | Amortize with bundled announcements |
| **No post-compromise security** | Until rotation, attacker can decrypt | DAG-integrated key lifecycle |
| **Large groups = large key distribution** | 1000 members = 999 pairwise sends | Fan-out via mailbox |

#### reme-Specific Adaptations

The roadmap mentions "Multi-sender DAG with per-member gap detection" which suggests:

```
┌─────────────────────────────────────────────────────────────────┐
│  Group DAG Structure (Extension of 1:1 DAG)                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Alice: A1 ────── A2 ────── A3                                  │
│          \         \                                             │
│           \         \── observed_heads                          │
│            \                                                     │
│  Bob:       B1 ────── B2                                        │
│              \                                                   │
│               \── observed_heads                                │
│                                                                  │
│  Carol:            C1 ────── C2                                 │
│                                                                  │
│  Each member maintains their own prev_self chain                │
│  observed_heads references any member's latest message          │
└─────────────────────────────────────────────────────────────────┘
```

**Gap detection per member:**
- Track each member's chain independently
- Detect missing messages from any sender
- Request retransmission via any available transport

#### Verdict: RECOMMENDED (with MLS enhancements)

Sender Keys aligns well with reme's architecture and is already planned. Enhance with:
- **TreeKEM-style key trees** for efficient member add/remove (from MLS)
- **Epoch-based rotation** aligned with DAG acknowledgments
- **Detached mode** for constrained transports (LoRa)

---

### 2.3 MLS (Messaging Layer Security)

#### Overview

MLS is the IETF-standardized protocol for secure group messaging (RFC 9420). Key innovations:
- **Ratchet tree** for O(log n) member operations
- **Continuous group key agreement** with forward secrecy
- **Transport agnostic** design
- **Asynchronous** (works without all members online)

#### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                      Ratchet Tree (4 members)                    │
├─────────────────────────────────────────────────────────────────┤
│                           [Root]                                 │
│                          /      \                                │
│                    [Node1]      [Node2]                          │
│                    /    \       /    \                           │
│                Alice   Bob   Carol  Dave                         │
│                                                                  │
│  - Each node has a key pair                                     │
│  - Leaf keys are member keys                                    │
│  - Internal nodes derive from children                          │
│  - Update one member = O(log n) node updates                    │
└─────────────────────────────────────────────────────────────────┘
```

#### Pros

| Advantage | Description |
|-----------|-------------|
| **O(log n) member operations** | Adding/removing members is efficient |
| **Forward secrecy per epoch** | Key compromise doesn't expose past messages |
| **Post-compromise security** | New epoch = attacker locked out |
| **IETF standardized** | Well-analyzed, production-ready |
| **Industry adoption** | Wire, Google Messages, Matrix (planned) |
| **Asynchronous** | Works without all members online |

#### Cons

| Issue | Impact | Severity |
|-------|--------|----------|
| **Complexity** | Significant implementation effort | High |
| **State requirements** | Must track tree state | Medium |
| **Commit latency** | Member ops require message round-trip | Medium |
| **Not designed for DTN** | Assumes relatively reliable delivery | Medium |
| **Library maturity** | `openmls` and `mls-rs` are usable but evolving | Medium |

#### MLS vs reme's Constraints

| reme Requirement | MLS Support |
|------------------|-------------|
| DTN tolerance | Partial - commits require delivery confirmation |
| Transport agnostic | Yes - wire format is transport-independent |
| Minimal metadata | Partial - group structure visible at delivery layer |
| Bandwidth efficiency | Moderate - tree operations are compact |
| Stateless messages | No - tree state must be maintained |

#### Verdict: CONSIDER FOR v2.0+

MLS is well-designed but adds significant complexity. Consider for:
- **Very large groups** (100+ members) where O(log n) matters
- **Future versions** where state management is more mature
- **Interoperability** with other MLS-supporting systems

For reme v1.x, the simpler Sender Keys approach with MLS-inspired enhancements is more appropriate.

---

## 3. Recommended Approach

### 3.1 Architecture: Enhanced Sender Keys

Implement Sender Keys with selective MLS-inspired enhancements:

```
┌─────────────────────────────────────────────────────────────────┐
│                  reme Group Chat Architecture                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐                                               │
│  │ Group State  │ ◄── Local storage only (no server state)     │
│  ├──────────────┤                                               │
│  │ - group_id   │ 16-byte random                                │
│  │ - epoch      │ Monotonic counter                             │
│  │ - members    │ Vec<PublicID>                                 │
│  │ - admins     │ Vec<PublicID>                                 │
│  │ - sender_keys│ HashMap<PublicID, SenderKey>                  │
│  │ - my_key     │ Current sender key + chain state              │
│  └──────────────┘                                               │
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│  │ Member Ops   │────▶│ Group DAG    │────▶│ Gap Detect   │    │
│  │ (add/remove) │     │ (multi-sender)    │ (per-member)  │    │
│  └──────────────┘     └──────────────┘     └──────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Wire Format Extensions

#### GroupEnvelope (wraps OuterEnvelope)

```rust
pub struct GroupOuterEnvelope {
    version: Version,
    group_id: [u8; 16],           // Group identifier
    epoch: u32,                    // Key epoch for rotation
    sender_index: u16,             // Sender's position in member list
    routing_key: [u8; 16],         // For mailbox routing (hash of group_id)
    timestamp_hours: u32,
    message_id: MessageID,
    inner_ciphertext: Vec<u8>,     // Sender Key encrypted
}
```

#### GroupInnerEnvelope

```rust
pub struct GroupInnerEnvelope {
    from: PublicID,
    created_at_ms: u64,
    content: GroupContent,
    signature: [u8; 64],

    // Group DAG fields
    prev_self: Option<ContentId>,        // Sender's own chain
    observed_heads: Vec<ContentId>,      // Any member's messages
    epoch: u16,                          // Matches outer
    flags: u8,
}

pub enum GroupContent {
    Text(TextContent),
    Receipt(ReceiptContent),

    // New group operations
    MemberAdd(MemberAddContent),
    MemberRemove(MemberRemoveContent),
    KeyDistribution(KeyDistributionContent),
    GroupInfo(GroupInfoContent),
}
```

### 3.3 Key Management

#### Sender Key Structure

```rust
pub struct SenderKey {
    chain_key: [u8; 32],          // Ratchets forward with each message
    signing_key: PublicID,         // Owner's identity
    epoch: u32,                    // Key generation epoch
    message_index: u32,            // Messages sent with this key
}
```

#### Key Distribution Flow

```
New Member Join:
1. Admin creates MemberAdd message signed by admin key
2. Admin sends to all existing members via group
3. Each existing member sends their SenderKey to new member (pairwise)
4. New member generates their SenderKey
5. New member distributes via pairwise to all members
6. Epoch increments
```

#### Key Rotation (Forward Secrecy)

```
Rotation Triggers:
- Member removed from group
- Admin-initiated rotation
- Message count threshold (e.g., every 100 messages)
- Time-based (e.g., every 24 hours)

Rotation Flow:
1. Each member generates new SenderKey
2. Distributes via pairwise encryption
3. Epoch increments
4. Old keys retained until DAG confirms all messages acknowledged
```

### 3.4 Group DAG Design

Extend the existing DAG for multi-sender scenarios:

```rust
pub struct GroupGapDetector {
    // Per-member tracking (extends current SenderGapDetector)
    members: HashMap<PublicID, MemberChain>,

    // Global observed state
    all_heads: HashSet<ContentId>,
}

pub struct MemberChain {
    sent: HashMap<ContentId, Option<ContentId>>,  // content_id -> prev_self
    heads: HashSet<ContentId>,
    last_seen_epoch: u32,
}
```

**Gap detection works per-member:**
- Each member's `prev_self` chain tracked independently
- Missing message from Alice doesn't block Bob's messages
- `observed_heads` can reference any member's message

### 3.5 Public vs Private Groups

#### Private Groups (Default)

- **Invite-only** - Admin must add members
- **Encrypted group_id** - Relays see routing_key only
- **No discovery** - Must know group_id to participate

#### Public Groups (Optional)

For "public group chats" as mentioned in the task:

```rust
pub struct PublicGroupInfo {
    group_id: [u8; 16],
    name: String,
    description: String,
    admin_ids: Vec<PublicID>,
    join_policy: JoinPolicy,
}

pub enum JoinPolicy {
    Open,                      // Anyone can join
    RequestApproval,           // Admin must approve
    InviteOnly,               // Admin must add
}
```

**Discovery mechanism:**
- Groups can optionally publish to a "group directory" (another mailbox)
- Directory entry signed by admin
- Users can browse and request to join

**Privacy tradeoff:**
- Public groups sacrifice some metadata privacy for discoverability
- Group membership still protected (encrypted sender keys)
- Message content always E2E encrypted

### 3.6 Transport Considerations

#### HTTP/MQTT (Unconstrained)

- Full GroupOuterEnvelope
- Rich GroupContent types
- Full DAG linkage

#### BLE/LoRa (Constrained)

```rust
// Detached group message for constrained transports
pub struct DetachedGroupMessage {
    group_id: [u8; 16],
    epoch: u32,
    sender_index: u16,
    timestamp_hours: u32,
    // No DAG fields (FLAG_DETACHED)
    inner_ciphertext: Vec<u8>,  // Must fit in LoRa MTU after chunking
}
```

**Size budget (LoRa ~200 bytes):**
- Header: ~26 bytes
- ChaCha20-Poly1305 tag: 16 bytes
- Signature: 64 bytes
- Content: ~90 bytes remaining

May need to split larger messages using TransportChunk (v0.7).

---

## 4. Implementation Phases

### Phase 1: Foundation (Post-v1.0)

1. **GroupState** crate with membership tracking
2. **SenderKey** generation and storage
3. **GroupOuterEnvelope/InnerEnvelope** wire format
4. **GroupGapDetector** for multi-sender DAG

### Phase 2: Core Operations

1. Group creation and member invitation
2. Key distribution via pairwise encryption
3. Group message send/receive
4. Basic admin operations (add/remove)

### Phase 3: Advanced Features

1. Key rotation policies
2. Public group directory
3. Admin privileges and transfer
4. Group settings (name, avatar, permissions)

### Phase 4: Transport Integration

1. Group message routing through all transports
2. Detached mode for BLE/LoRa
3. Chunking for large groups

---

## 5. Comparison Summary

| Aspect | Matrix | Sender Keys | MLS |
|--------|--------|-------------|-----|
| **Architecture fit** | ❌ Poor | ✅ Excellent | ⚠️ Good |
| **DTN tolerance** | ❌ No | ✅ Yes | ⚠️ Partial |
| **Implementation effort** | High (bridge) | Medium | High |
| **Metadata privacy** | ❌ Poor | ✅ Good | ✅ Good |
| **Forward secrecy** | ✅ Megolm | ⚠️ Per-rotation | ✅ Per-epoch |
| **Scalability (1000+)** | ✅ Good | ⚠️ O(n) key dist | ✅ O(log n) |
| **Bandwidth efficiency** | ❌ Poor | ✅ Good | ✅ Good |
| **Transport agnostic** | ❌ HTTP-only | ✅ Yes | ✅ Yes |

---

## 6. Conclusion

### Recommended Path

1. **Do NOT integrate Matrix** - Architectural mismatch is fundamental
2. **Implement Sender Keys** as planned in ROADMAP.md
3. **Borrow MLS patterns** for:
   - Epoch-based key lifecycle
   - Tree-structured key distribution (for very large groups)
   - Commit semantics for membership changes
4. **Design for constraints** - LoRa/BLE compatibility from start

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Protocol | Sender Keys + MLS patterns | DTN compatibility, fits architecture |
| State model | Local only, no server state | Self-sovereign, works offline |
| Key distribution | Pairwise via existing transport | Reuses proven 1:1 encryption |
| Forward secrecy | Epoch rotation + DAG lifecycle | Balance security and DTN tolerance |
| Public groups | Optional directory service | Opt-in discoverability |

### Future Considerations

- **Full MLS migration** when/if DTN-MLS variant is standardized
- **Interoperability bridge** to Matrix/Signal groups (low priority)
- **Post-quantum sender keys** with Kyber (v2.0+)

---

## References

- [RFC 9420 - The Messaging Layer Security (MLS) Protocol](https://datatracker.ietf.org/doc/rfc9420/)
- [Signal Sender Keys Analysis](https://arxiv.org/abs/2301.07045)
- [Signal Private Groups](https://signal.org/blog/private-groups/)
- [OpenMLS Implementation](https://openmls.tech/)
- [AWS mls-rs Implementation](https://github.com/awslabs/mls-rs)
- [Matrix MLS Proposal (MSC2883)](https://github.com/matrix-org/matrix-doc/issues/589)
- [Wire MLS Implementation](https://wire.com/en/blog/messaging-layer-security-mls-explained)
