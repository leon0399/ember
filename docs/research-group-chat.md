# Research: Public Group Chat Integration for reme

**Date:** February 2026
**Status:** Research
**Author:** Claude (AI-assisted analysis)

---

## Executive Summary

This document analyzes options for integrating public group chats into reme. After evaluating Matrix integration, Signal's Sender Keys protocol, MLS (RFC 9420), and custom solutions, the recommendation is to implement a **custom DTN-first group protocol based on Sender Keys** with multi-sender DAG extension.

Matrix integration is **not recommended** due to fundamental architectural conflicts with reme's DTN-first, stateless design philosophy.

---

## Current State

reme is a 1:1 messaging system. Per ROADMAP.md:462-467, group messaging is planned for **post-v1.0**:

```
### Group messaging
- Sender Keys protocol (O(1) encryption)
- Multi-sender DAG with per-member gap detection
- Admin operations (add/remove/promote)
```

---

## Option 1: Matrix Integration

### Overview
- Federated messaging protocol with multi-user rooms
- Encryption: Olm (1:1) + Megolm (groups), migrating to MLS (MSC2883)
- Large user base and federation network

### Evaluation

| Aspect | Matrix | reme | Conflict |
|--------|--------|------|----------|
| Architecture | Federated servers | Optional mailboxes | Matrix requires servers |
| Connectivity | Always-on | DTN-tolerant | Matrix fails offline |
| Metadata | Significant to servers | Minimal to relays | Privacy violation |
| Encryption | Session-based (Megolm) | Stateless | Architectural mismatch |

### Issues (per WHITEPAPER.md comparison)

1. **Federation complexity** - requires homeservers, DNS, database synchronization
2. **Metadata leakage** - servers see significant metadata (who talks to whom, when, room membership)
3. **Not DTN-compatible** - assumes always-on connectivity, fails during network partitions
4. **Protocol mismatch** - Matrix's session-based encryption conflicts with reme's stateless design

### Verdict

**REJECT** - Matrix integration would fundamentally conflict with reme's design goals. The metadata exposure to homeservers violates reme's minimal-metadata principle, and federation requires infrastructure that reme is designed to work without.

---

## Option 2: Sender Keys Protocol

### Overview
Signal's Sender Keys protocol provides O(1) encryption efficiency for group messaging.

### How It Works
1. Each group member generates a "Sender Key" (32-byte Chain Key + Ed25519 Signature Key)
2. Keys are distributed pairwise via existing 1:1 encryption
3. Messages encrypted once with sender's key (O(1) encryption)
4. Chain Key ratchets forward after each message (partial forward secrecy)
5. All members can decrypt using the distributed key

### Security Properties

| Property | Status |
|----------|--------|
| Confidentiality | ✅ |
| Authenticity | ✅ (signatures) |
| Forward Secrecy | ⚠️ Partial (per-message ratchet) |
| Post-Compromise Security | ❌ No |
| Membership Authentication | ✅ |

### DTN Compatibility

**Excellent fit:**
- Key distribution uses existing 1:1 MIK encryption (already DTN-safe)
- No session state synchronization needed
- Detached messages (no DAG) work for constrained transports
- Tolerates out-of-order message delivery

### Trade-offs

**Pros:**
- O(1) efficiency - send to N members with single encryption
- Well-analyzed by academic community
- Used by Signal, WhatsApp, Facebook Messenger
- Aligns with roadmap

**Cons:**
- No Post-Compromise Security - if sender key leaked, all future messages compromised until key rotation
- Key rotation required on membership change - removing a member requires all members to regenerate keys

### Verdict

**RECOMMENDED** - Sender Keys aligns with reme's DTN-first design and is already planned in the roadmap.

---

## Option 3: MLS (Messaging Layer Security, RFC 9420)

### Overview
IETF standard published July 2023. Uses TreeKEM for efficient key management with O(log n) complexity.

### Security Properties

| Property | Status |
|----------|--------|
| Confidentiality | ✅ |
| Authenticity | ✅ |
| Forward Secrecy | ✅ Full |
| Post-Compromise Security | ✅ |
| Scalability | ✅ Up to 50,000 members |

### DTN Compatibility Issues

MLS assumes members can receive key update messages in a timely manner:
- TreeKEM requires coordinated group state updates
- Members offline for days/weeks cause state divergence
- Update messages may arrive out of order
- Requires "Delivery Service" for message ordering

### Industry Adoption
- Apple RCS support announced March 2025
- Matrix migrating via MSC2883
- AWS Labs provides mls-rs Rust implementation

### Verdict

**FUTURE CONSIDERATION** - MLS provides superior security properties but requires adaptations for DTN scenarios. Consider for v2.0 if a DTN-adapted variant is developed.

---

## Option 4: Custom DTN-First Group Protocol (Recommended)

### Design Principles

1. **Sender Keys foundation** - O(1) encryption with per-message ratchet
2. **Multi-sender DAG** - Each member maintains their own chain with cross-member references
3. **Membership DAG** - Admin operations as content-addressed, causally ordered nodes
4. **Epoch-based key rotation** - New epoch on membership change, old keys retained until all members confirm

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Group Structure                                                        │
├─────────────────────────────────────────────────────────────────────────┤
│  group_id: [u8; 16]           // BLAKE3 hash of initial membership     │
│  admin: PublicID               // Group creator/admin                   │
│  members: Vec<PublicID>        // Current membership                    │
│  epoch: u32                    // Key epoch (increments on change)      │
│  member_keys: HashMap<PublicID, SenderKey>  // Per-member sender keys   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Multi-Sender DAG

```
┌────────────────────────────────────────────────────────────────────────┐
│  Multi-Sender DAG for Group "Family"                                   │
│  ──────────────────────────────────────────────────────────────────────│
│                                                                         │
│  Alice:  A1 ──────────── A2 ──────────── A3                            │
│            \              /                                             │
│             \            /                                              │
│  Bob:        B1 ──────── B2                                            │
│               \                                                         │
│                \                                                        │
│  Carol:         C1                                                      │
│                                                                         │
│  prev_self: Links own messages (A1→A2→A3)                              │
│  observed_heads: Tracks what each member has seen from ALL others      │
└────────────────────────────────────────────────────────────────────────┘
```

### Wire Format Extension

```rust
pub struct GroupEnvelope {
    version: Version,
    group_id: [u8; 16],           // Group identifier
    routing_key: RoutingKey,       // For mailbox storage
    epoch: u32,                    // Key epoch
    sender_key_id: [u8; 8],        // Which sender key encrypted this
    timestamp_hours: u32,          // Hour granularity
    ttl_hours: Option<u16>,
    message_id: MessageID,
    inner_ciphertext: Vec<u8>,     // Encrypted with Sender Key
}

pub struct GroupInnerEnvelope {
    from: PublicID,
    created_at_ms: u64,
    content: GroupContent,
    signature: [u8; 64],

    // Multi-sender DAG fields
    prev_self: Option<ContentId>,
    observed_heads: HashMap<PublicID, ContentId>,  // Per-member heads
    epoch: u32,
    flags: u8,
}

pub enum GroupContent {
    Text(TextContent),
    Receipt(ReceiptContent),
    MembershipOp(MembershipOperation),
}

pub enum MembershipOperation {
    Invite { pubkey: PublicID, sender_key: EncryptedSenderKey },
    Remove { pubkey: PublicID },
    Leave,
    PromoteAdmin { pubkey: PublicID },
    RotateKey { new_sender_key: EncryptedSenderKey },
}
```

### Key Management

**Initial Group Creation:**
1. Creator generates group_id = BLAKE3(creator_pubkey || timestamp || random)
2. Creator generates their Sender Key
3. Creator invites members via 1:1 channels, distributing:
   - group_id
   - Initial membership list
   - Creator's Sender Key (encrypted to each invitee's MIK)
4. Each invitee generates their Sender Key and distributes to all members

**Adding Members:**
1. Admin sends MembershipOp::Invite with new member's pubkey
2. All existing members send their Sender Keys to new member (via 1:1)
3. New member generates Sender Key and distributes to all
4. Epoch increments

**Removing Members:**
1. Admin sends MembershipOp::Remove
2. All remaining members generate new Sender Keys (new epoch)
3. New keys distributed via 1:1 channels
4. Old epoch keys retained until all members confirm new epoch

**Key Rotation (Optional):**
- Members can periodically rotate their Sender Key for forward secrecy
- MembershipOp::RotateKey distributes new key
- Old key deleted after all members acknowledge

### Gap Detection

Per-member gap detection extends the existing 1:1 gap detector:

```rust
pub struct GroupGapDetector {
    group_id: [u8; 16],
    // Per-member tracking
    member_chains: HashMap<PublicID, Vec<ContentId>>,
    member_heads: HashMap<PublicID, HashSet<ContentId>>,
    orphans: HashMap<PublicID, Vec<(ContentId, Option<ContentId>)>>,
}

impl GroupGapDetector {
    pub fn on_receive(
        &mut self,
        from: &PublicID,
        content_id: ContentId,
        prev_self: Option<ContentId>,
        observed_heads: &HashMap<PublicID, ContentId>,
    ) -> GroupGapResult {
        // Check sender's chain continuity
        // Check if we have all referenced heads
        // Return missing messages per-member
    }
}
```

### DTN Considerations

**Detached Messages:**
- Groups support FLAG_DETACHED for constrained transports (LoRa, BLE)
- Detached messages have empty observed_heads
- Linked later when followed by a full DAG message

**Epoch Synchronization:**
- Members may be on different epochs during transitions
- Messages include epoch number
- Recipients accept messages from current or previous epoch
- Old epoch keys retained until all members confirm transition

**Offline Members:**
- Key updates sent via 1:1 channels (stored in mailboxes)
- Returning members catch up on membership changes
- Messages encrypted to old epoch still decryptable with retained keys

---

## Implementation Roadmap

### Prerequisites (v1.0)
- ✅ Stateless encryption (MIK-based)
- ⏳ Forward Secrecy (Noise XX handshake)
- ⏳ Protobuf wire format (schema evolution for groups)

### Phase 1: Group Foundation (v1.1)
- [ ] GroupID generation and management
- [ ] Sender Key generation (32-byte Chain Key + Signature Key)
- [ ] Sender Key distribution via 1:1 MIK channels
- [ ] Basic group encryption/decryption
- [ ] Group storage schema (SQLite)

### Phase 2: Multi-Sender DAG (v1.2)
- [ ] Per-member gap detection
- [ ] Cross-member observed_heads
- [ ] Epoch synchronization across members
- [ ] Orphan tracking per-member

### Phase 3: Membership Operations (v1.3)
- [ ] MembershipOp wire format
- [ ] Admin operations (invite/remove/promote)
- [ ] Key rotation on membership change
- [ ] Conflict resolution for concurrent admin ops

### Phase 4: Transport Integration (v1.4)
- [ ] Group message routing through tiered delivery
- [ ] Detached group messages for LoRa/BLE
- [ ] Group tombstones for acknowledgment

---

## Comparison Summary

| Criterion | Matrix | Sender Keys | MLS | Custom DTN |
|-----------|--------|-------------|-----|------------|
| DTN Compatible | ❌ | ✅ | ⚠️ | ✅ |
| Stateless Encryption | ❌ | ✅ | ❌ | ✅ |
| Minimal Metadata | ❌ | ✅ | ✅ | ✅ |
| Forward Secrecy | ⚠️ Partial | ⚠️ Partial | ✅ Full | ⚠️ Partial |
| Post-Compromise Security | ❌ | ❌ | ✅ | ❌ (with rotation) |
| Implementation Complexity | High | Medium | High | Medium |
| Aligns with Roadmap | ❌ | ✅ | ❌ | ✅ |

---

## Conclusion

For public group chats in reme, the recommended approach is a **custom DTN-first group protocol** based on:

1. **Sender Keys** for O(1) encryption efficiency
2. **Multi-sender DAG** for decentralized causality tracking
3. **Membership DAG** for conflict-free admin operations
4. **Epoch-based key rotation** for forward secrecy during membership changes

This approach:
- Maintains reme's stateless encryption philosophy
- Works across all transports (HTTP, LoRa, BLE, sneakernet)
- Minimizes metadata exposure to relay nodes
- Supports offline-first, DTN-tolerant operation

Matrix integration is explicitly rejected due to fundamental architectural conflicts with reme's design goals around federation independence, metadata privacy, and DTN tolerance.

---

## References

### Protocol Specifications
- [RFC 9420: The Messaging Layer Security (MLS) Protocol](https://datatracker.ietf.org/doc/rfc9420/)
- [Matrix Megolm Specification](https://spec.matrix.org/v1.17/olm-megolm/megolm/)
- [Signal Sender Keys Implementation](https://signal.org/docs/)

### Academic Analysis
- [Analysis and Improvements of the Sender Keys Protocol](https://arxiv.org/pdf/2301.07045)
- [Practically-exploitable Cryptographic Vulnerabilities in Matrix](https://nebuchadnezzar-megolm.github.io/)
- [A Security Analysis of Signal Protocol's Group Messaging](https://ir.library.oregonstate.edu/downloads/xd07h076n)

### Implementations
- [mls-rs by AWS Labs](https://github.com/awslabs/mls-rs) - Rust MLS implementation
- [OpenMLS](https://github.com/openmls/openmls) - Open source MLS implementation
