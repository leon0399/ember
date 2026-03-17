# Threat Model

Attack scenarios, mitigations, and residual risks for the reme messaging system.

## LAN Discovery

## 1. Impersonation via mDNS routing key spoofing

**Attack**: Mallory advertises herself on mDNS with Bob's routing key (`rk=<Bob's RK>`). Alice's discovery controller matches the routing key against her contact list and attempts to register Mallory as Bob's direct transport target.

**Mitigation**: The discovery controller performs identity verification before registering any target. It sends a random challenge to the discovered peer's `/api/v1/identity` endpoint and verifies the XEdDSA signature against known contact public keys. Mallory cannot produce a valid signature without Bob's private key. The peer is silently ignored if verification fails.

**Residual risk**: None — Mallory is never registered as a target.

## 2. Identity challenge relay (MITM on verification)

**Attack**: Mallory advertises Bob's routing key, intercepts Alice's identity challenge, forwards it to the real Bob, and replays Bob's signed response back to Alice. Alice now believes Mallory is Bob and registers her as a direct target.

**Mitigation**: Even if Mallory passes verification, the transport layer limits the impact:

1. **Confidentiality**: Messages are E2E encrypted to Bob's MIK (X25519). Mallory cannot decrypt them.
2. **If Mallory proxies to Bob**: She is acting as a relay — the message reaches Bob and the system works as designed. This is functionally equivalent to the relay architecture the system already supports.

**Known gap — receipt-gated direct tier**: Currently, `try_direct_tier()` considers any HTTP 2xx response as success, regardless of receipt validity. The receipt signature (XEdDSA over domain-separated `signer_pubkey || message_id`) is verified and recorded but does **not** gate tier success. This means:

- **If Mallory returns 200 with no/invalid receipt**: The direct tier succeeds, the message is blackholed, and quorum fallback is **not** triggered.
- **If Mallory drops the connection**: HTTP error → direct tier fails → quorum fallback works correctly.

<!-- TODO: Implement receipt-gated direct tier success — require a verified receipt -->
<!-- signature (or at minimum ack_secret presence) for Direct tier to be considered -->
<!-- successful. Without this, a relay attacker returning 200 OK can silently -->
<!-- blackhole messages. See threat model §2. -->

**Residual risk**: A relay attacker who passes identity verification can silently drop messages by returning HTTP 200 with an empty/invalid receipt. Mallory also learns that Alice (by her IP address) is attempting to send to Bob's routing key — this is an information leak beyond what mDNS broadcasts reveal, since the advertisement shows Bob's presence but not which clients are interested in it.

**Why channel binding was rejected**: An earlier design included channel binding (mixing the responder's IP:port into the challenge hash). Even with channel binding, the receipt-gating gap above would still allow message blackholing. The correct fix is receipt-gated direct tier success, not channel binding. See PR #87 close rationale.

## 3. Discovery spam / resource exhaustion

**Attack**: Mallory floods the network with thousands of mDNS advertisements, each with a different routing key, attempting to exhaust the discovery controller's resources.

**Mitigation**:
- The controller enforces a hard cap of 256 tracked peers
- Only peers whose routing key matches a known contact are processed (strangers are ignored)
- Identity verification adds latency per peer, but the 256 cap bounds total work
- The mDNS-SD backend uses `broadcast` channels that drop events on lag rather than growing unboundedly

**Residual risk**: An attacker who knows a contact's routing key (16 bytes, derived from their public key via BLAKE3) could trigger verification attempts. The 256 peer cap (`MAX_PEERS` in `apps/client/src/discovery/controller.rs`) and the discovery controller's reqwest client timeouts (2s connect, 5s total) bound the amplification.

## 4. Stale peer targets after network change

**Attack**: Not an adversarial attack, but a reliability concern. A peer goes offline without sending an mDNS goodbye packet (e.g., abrupt network disconnect). The controller retains the stale target, and direct-tier delivery attempts fail until the mDNS TTL expires.

**Mitigation**:
- The HTTP target's circuit breaker marks the target as unhealthy after 2 consecutive failures (ephemeral threshold), with 10s recovery window
- Unhealthy targets are skipped by the coordinator's target selection
- Direct tier has a configurable timeout; failure falls back to quorum
- When the mDNS daemon detects the service is gone (TTL expiry), it emits `PeerLost` and the controller removes the target
- On controller shutdown, all tracked peers are deregistered from the coordinator

**Residual risk**: Brief window (seconds) of failed direct delivery before circuit breaker trips. Quorum fallback ensures delivery.

## 5. Routing key privacy leakage

**Attack**: An observer on the LAN can see routing keys in mDNS TXT records. Since `routing_key = BLAKE3(PublicID)[..16]`, this is a 16-byte truncated hash of the peer's public identity. An attacker who knows a target's PublicID can confirm their presence on the network.

**Mitigation**:
- Routing keys are one-way (BLAKE3 hash) — knowing the routing key does not reveal the PublicID
- However, an attacker with a candidate PublicID can compute `BLAKE3(candidate)[..16]` and check for a match
- This is inherent to the mDNS discovery model — advertising presence on the LAN necessarily reveals some identity information

**Residual risk**: Presence confirmation for targeted surveillance. Acceptable for the LAN-first threat model. Future mitigation options include rotating routing keys or using ephemeral advertisement identifiers.

## 6. Fetch polling privacy (why ephemeral targets are SEND-only)

**Attack**: If Alice polls an mDNS-discovered peer for messages (`GET /api/v1/fetch/{routing_key}`), she reveals her own routing key to that peer. A malicious peer could collect routing keys of all clients polling it.

**Mitigation**: Ephemeral targets (discovered via mDNS) default to `TargetCapabilities { send: true, fetch: false, .. }`. The capability-filtered fetch path skips targets without the `fetch` capability. Alice never polls discovered peers — she only sends to them. Message fetching happens exclusively from trusted stable mailbox nodes.

**Residual risk**: None — the capability system prevents this by design.
