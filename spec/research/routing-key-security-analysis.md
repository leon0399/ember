# Routing Key Security and Anonymity Analysis

This document analyzes the current routing key design in REME, its security properties, anonymity implications, and potential alternatives.

## Executive Summary

The current routing key design (`BLAKE3(PublicID)[0..16]`) provides **confidentiality** (messages are encrypted end-to-end) but offers **limited anonymity**. The static, deterministic routing key enables traffic analysis, communication pattern correlation, and social graph construction by malicious mailbox nodes or network observers.

**Key Finding**: The routing key is functionally equivalent to a permanent pseudonymous address. While it hides the cryptographic identity from mailbox nodes, it enables full linkability of all messages to/from a user.

**Recommendation**: For a privacy-focused messenger, consider implementing per-contact or per-mailbox routing keys as a medium-term improvement, with optional stealth addresses or PIR for high-threat-model users.

---

## Current Design

### Implementation

```rust
// crates/reme-identity/src/lib.rs:212-217
pub fn routing_key(&self) -> RoutingKey {
    let hash = blake3::hash(&self.to_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.as_bytes()[0..16]);
    RoutingKey(bytes)
}
```

### Properties

| Property | Value |
|----------|-------|
| Size | 16 bytes (128 bits) |
| Derivation | `BLAKE3(PublicID)[0..16]` |
| Determinism | Static - same PublicID always produces same RoutingKey |
| Scope | Global - used for all mailbox nodes |

### Wire Format Usage

```
OuterEnvelope (unencrypted metadata):
├── version: u8
├── routing_key: [u8; 16]  ← Used for mailbox addressing
├── timestamp_hours: u32   ← Coarse granularity (privacy measure)
├── ttl_hours: Option<u16>
├── message_id: [u8; 16]
├── ephemeral_key: [u8; 32]
├── ack_hash: [u8; 16]
└── inner_ciphertext: Vec<u8>  ← Encrypted (sender identity inside)
```

---

## Security Properties Analysis

### What the Current Design Provides

| Property | Status | Notes |
|----------|--------|-------|
| End-to-end encryption | ✅ Strong | ChaCha20-Poly1305 + XEdDSA signatures |
| Forward secrecy | ✅ Strong | Ephemeral X25519 keys per message |
| Sender authentication | ✅ Strong | XEdDSA signatures inside encrypted envelope |
| Recipient binding | ✅ Strong | AEAD + nonce binding to recipient |
| Message integrity | ✅ Strong | Poly1305 MAC + signature |
| Identity hiding from nodes | ⚠️ Partial | Nodes see routing_key, not PublicID |
| Metadata privacy | ⚠️ Partial | Hour-granularity timestamps |
| Unlinkability | ❌ None | Static routing key enables full correlation |
| Sender anonymity | ❌ Limited | Traffic analysis reveals sender patterns |

### Threat Model Analysis

#### Threat: Passive Network Observer

| Attack | Feasibility | Notes |
|--------|-------------|-------|
| Correlate messages to same recipient | Trivial | Same routing_key on all messages |
| Build social graph | Easy | Observe sender IP + routing_key pairs |
| Determine conversation frequency | Easy | Count messages per routing_key over time |
| Identify routing_key↔PublicID mapping | Medium | Requires one known association |

#### Threat: Malicious Mailbox Node

| Attack | Feasibility | Notes |
|--------|-------------|-------|
| Log all messages to a routing_key | Trivial | Node sees all stored messages |
| Correlate senders (by IP/timing) | Easy | Node sees submission metadata |
| Sell communication metadata | Easy | routing_key is stable identifier |
| Identify users from directory | Easy | Compute BLAKE3(PublicID) for known IDs |

#### Threat: Active Adversary (State-level)

| Attack | Feasibility | Notes |
|--------|-------------|-------|
| Subpoena mailbox node logs | Easy | routing_key is permanent identifier |
| Traffic analysis across nodes | Medium | Same routing_key on all nodes |
| Deanonymize users via directory | Easy | Public directories map ID↔routing_key |

---

## The Core Problem: Static Routing Keys

### Linkability Attack

```
Time T1: Alice sends to Bob's routing_key R_bob via Node1
Time T2: Carol sends to Bob's routing_key R_bob via Node2
Time T3: Alice sends to Bob's routing_key R_bob via Node1

Adversary observes: R_bob receives messages at T1, T2, T3
Result: Full communication pattern of Bob is revealed
```

### Rainbow Table Attack

If an adversary has access to a public directory of `PublicID`s (e.g., key server, social network profile):

```python
# Trivial attack to deanonymize routing keys
def build_rainbow_table(public_directory):
    return {blake3(pubid)[:16]: pubid for pubid in public_directory}

def deanonymize(routing_key, rainbow_table):
    return rainbow_table.get(routing_key)  # O(1) lookup
```

**Mitigation difficulty**: This attack cannot be prevented with the current design because:
1. The derivation is deterministic
2. BLAKE3 is fast (~1GB/s), making brute-force feasible
3. The search space is bounded by the number of users

---

## Alternative Routing Key Designs

### Option 1: Per-Mailbox Routing Keys

**Concept**: Derive different routing keys for each mailbox node.

```rust
pub fn routing_key_for_node(&self, node_id: &[u8; 32]) -> RoutingKey {
    let mut hasher = blake3::Hasher::new_derive_key("reme-routing-v2");
    hasher.update(&self.to_bytes());
    hasher.update(node_id);
    let hash = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.as_bytes()[0..16]);
    RoutingKey(bytes)
}
```

| Pros | Cons |
|------|------|
| Different routing_key per node | Same routing_key within a node |
| Prevents cross-node correlation | Doesn't help single-node adversary |
| Simple implementation | Requires node_id in sender's contact info |
| Backward compatible wire format | Increases contact metadata size |

**Anonymity improvement**: Medium. Prevents passive cross-node correlation but doesn't protect against individual malicious nodes.

### Option 2: Per-Contact Routing Keys

**Concept**: Each contact pair shares a unique routing key derived from both identities.

```rust
pub fn routing_key_for_contact(&self, contact: &PublicID) -> RoutingKey {
    let mut hasher = blake3::Hasher::new_derive_key("reme-contact-routing-v1");
    // Sort to ensure Alice→Bob and Bob→Alice use same key
    let (a, b) = if self.to_bytes() < contact.to_bytes() {
        (self.to_bytes(), contact.to_bytes())
    } else {
        (contact.to_bytes(), self.to_bytes())
    };
    hasher.update(&a);
    hasher.update(&b);
    let hash = hasher.finalize();
    RoutingKey(hash.as_bytes()[0..16].try_into().unwrap())
}
```

| Pros | Cons |
|------|------|
| Each conversation has unique routing_key | Requires per-contact routing_key distribution |
| Limits blast radius of compromise | Doesn't hide conversation existence from nodes |
| Simple cryptographic implementation | Increases complexity of contact management |

**Anonymity improvement**: Medium-High. Adversary can't correlate across contacts but can still observe conversation patterns.

### Option 3: Stealth Addresses (Ephemeral Receive Keys)

**Concept**: Inspired by cryptocurrency stealth addresses. Sender generates one-time routing key that only recipient can link to their identity.

```rust
// Sender generates ephemeral routing key
pub fn generate_stealth_routing(recipient: &PublicID) -> (RoutingKey, [u8; 32]) {
    let ephemeral = EphemeralSecret::random();
    let ephemeral_public = X25519PublicKey::from(&ephemeral);

    // Shared secret only sender and recipient can compute
    let shared = ephemeral.diffie_hellman(&recipient.x25519_public());

    // Derive one-time routing key
    let mut hasher = blake3::Hasher::new_derive_key("reme-stealth-v1");
    hasher.update(shared.as_bytes());
    let routing_key = RoutingKey(hasher.finalize().as_bytes()[0..16].try_into().unwrap());

    (routing_key, ephemeral_public.to_bytes())
}

// Recipient scans all messages to find theirs
pub fn check_stealth_message(&self, ephemeral_pub: &[u8; 32], routing_key: &RoutingKey) -> bool {
    let ephemeral = X25519PublicKey::from(*ephemeral_pub);
    let shared = self.x25519_secret.diffie_hellman(&ephemeral);

    let mut hasher = blake3::Hasher::new_derive_key("reme-stealth-v1");
    hasher.update(shared.as_bytes());
    let expected = RoutingKey(hasher.finalize().as_bytes()[0..16].try_into().unwrap());

    &expected == routing_key
}
```

| Pros | Cons |
|------|------|
| Perfect unlinkability | Recipient must scan ALL messages |
| No rainbow table attack possible | O(n) computation per message fetch |
| One-time addresses | Ephemeral key adds 32 bytes to envelope |
| Strong anonymity | Significant scalability challenges |

**Anonymity improvement**: High. Each message has unique routing key. Adversary cannot correlate without recipient's private key.

**Scalability concern**: Recipient must compute ECDH for every message on the mailbox to identify their messages. This could be mitigated with:
- View keys (separate scanning key)
- Probabilistic filters (Bloom filters of potential routing keys)
- Private Information Retrieval (PIR)

### Option 4: Private Information Retrieval (PIR)

**Concept**: Recipient queries mailbox without revealing which routing key they want.

```
Recipient wants routing_key R_i from mailbox with messages [M_0, M_1, ..., M_n]
PIR protocol allows fetching M_i without server learning i
```

| Pros | Cons |
|------|------|
| Information-theoretic privacy | High computational cost |
| Server learns nothing | Specialized server implementation |
| Compatible with static routing keys | Significant latency increase |

**Anonymity improvement**: Very High. Mailbox learns nothing about which messages are accessed.

**Practical concern**: PIR is computationally expensive. Single-server PIR has O(n) server computation per query. Multi-server PIR requires non-colluding servers.

### Option 5: Mix Networks / Onion Routing

**Concept**: Route messages through multiple independent relays with layered encryption.

```
Alice → Node1 → Node2 → Node3 → Bob's Mailbox

Each node only knows previous and next hop.
No single node knows both sender and recipient.
```

| Pros | Cons |
|------|------|
| Strong sender anonymity | High latency (multiple hops) |
| Widely studied (Tor, Nym, Loopix) | Network effect (needs many users) |
| Defeats traffic analysis | Complex implementation |
| Established security models | Requires coordination infrastructure |

**Anonymity improvement**: Very High. Provides sender/receiver unlinkability against passive global adversary.

---

## Comparison Matrix

| Design | Unlinkability | Rainbow Table Resistance | Scalability | Implementation Complexity | Wire Format Change |
|--------|---------------|--------------------------|-------------|---------------------------|-------------------|
| Current (static) | None | None | High | N/A | N/A |
| Per-mailbox | Per-node | Low | High | Low | None |
| Per-contact | Per-contact | Medium | High | Medium | None |
| Stealth addresses | Per-message | High | Medium | Medium | +32 bytes |
| PIR | Full | High | Low | High | None |
| Mix network | Full | High | Medium | Very High | Significant |

---

## Recommendations

### Short-term (Current Release)

**Keep current design** but document the privacy limitations clearly. The current design is appropriate for:
- Users with low threat models
- Internal/corporate deployments with trusted infrastructure
- Proof-of-concept phase

### Medium-term Improvements

1. **Per-mailbox routing keys** (Option 1)
   - Low implementation effort
   - Breaks cross-node correlation
   - Backward compatible with current wire format
   - Can be opt-in feature

2. **Per-contact routing keys** (Option 2)
   - Medium implementation effort
   - Significantly improves privacy within a mailbox
   - Requires contact exchange protocol update

### Long-term / High-Security Mode

For users with high threat models (journalists, activists, etc.):

1. **Optional stealth addresses** (Option 3)
   - Implement as opt-in "high privacy mode"
   - Accept scalability trade-off for unlinkability
   - Consider view keys to reduce scanning cost

2. **Mix network integration** (Option 5)
   - Integrate with existing mix networks (Nym, I2P)
   - Use as transport layer for Tier 1/2 delivery
   - Provides strong anonymity without reinventing the wheel

---

## Implementation Considerations

### Backward Compatibility

The `OuterEnvelope` already contains `routing_key` as a 16-byte field. Options 1-3 can reuse this field without wire format changes.

For stealth addresses, the `ephemeral_key` field could potentially be repurposed, but this would conflict with the encryption ephemeral key. A separate stealth ephemeral key would require wire format versioning.

### Key Considerations for Any Change

1. **Contact exchange protocol**: How do contacts learn each other's routing keys for new schemes?
2. **Multi-device**: How do multiple devices share routing key state?
3. **Key rotation**: How are routing keys rotated without losing messages?
4. **Mailbox notification**: How do mailboxes learn about new routing keys for a user?

---

## Conclusion

The current routing key design prioritizes simplicity and efficiency over anonymity. This is a reasonable trade-off for a proof-of-concept messenger, but should be addressed before production use if privacy is a goal.

**Immediate action items:**
1. Document current privacy limitations in user-facing materials
2. Design per-mailbox routing key derivation for next version
3. Research integration points for mix network transports

**Future research:**
- Evaluate PIR protocols for practical deployment
- Prototype stealth addresses with view key optimization
- Survey existing mix network integration options (Nym, Katzenpost)
