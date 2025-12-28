# Tiered Delivery with Quorum Semantics

This document describes the tiered delivery system implemented in the Resilient Messenger client. Messages flow through multiple delivery tiers with configurable quorum requirements, ensuring reliable message delivery even when some transports fail.

## Overview

The delivery system is designed around a key principle: **the client never gives up**. Messages remain in the outbox until the recipient acknowledges receipt via the DAG (Directed Acyclic Graph) or tombstone mechanism.

```text
┌───────────────────────────────────────────────────────────────────────┐
│                           CLIENT                                      │
│  ┌───────────────────────────────────────────────────────────────────┐│
│  │ OUTBOX: Messages stay until ACKed                                 ││
│  │                                                                   ││
│  │ Phase 1 (Urgent): Aggressive retry until quorum reached           ││
│  │ Phase 2 (Distributed): Periodic refresh awaiting ACK              ││
│  │ Phase 3 (Confirmed): Remove after cleanup delay                   ││
│  └───────────────────────────────────────────────────────────────────┘│
│                                   │                                   │
│                          TransportCoordinator                         │
│                                   │                                   │
│          ┌────────────────────────┼────────────────────────┐          │
│          ▼                        ▼                        ▼          │
│   ┌─────────────┐          ┌─────────────┐          ┌─────────────┐   │
│   │ TIER 1      │          │ TIER 2      │          │ TIER 3      │   │
│   │ Direct      │          │ Quorum      │          │ BestEffort  │   │
│   │             │          │             │          │             │   │
│   │ Race        │          │ Broadcast   │          │ Fire &      │   │
│   │ Exit on     │ ───────> │ Require     │ ───────> │ Forget      │   │
│   │ ANY         │   fail   │ Quorum      │   fail   │             │   │
│   └─────────────┘          └─────────────┘          └─────────────┘   │
└───────────────────────────────────────────────────────────────────────┘
```

## Delivery Tiers

Messages flow through three delivery tiers in sequence. Each tier has different characteristics and success criteria.

| Tier               | Targets                       | Strategy      | Success Criteria      | On Failure     |
|--------------------|-------------------------------|---------------|-----------------------|----------------|
| **1. Direct**      | Ephemeral (mDNS, DHT, Iroh)   | Race all      | ANY success → DONE    | Try Tier 2     |
| **2. Quorum**      | HTTP mailboxes + MQTT brokers | Broadcast all | QUORUM reached → DONE | Try Tier 3     |
| **3. Best-Effort** | BLE mesh, LoRa/Meshtastic     | Best effort   | Fire and forget       | Outbox retries |

### Tier 1: Direct

The Direct tier attempts to deliver messages directly to the recipient or their nearby peers. This provides the highest confidence delivery since the recipient (or their proxy) has the message immediately.

- **Targets**: Ephemeral transports discovered via mDNS, DHT, or Iroh
- **Strategy**: Race all available targets simultaneously
- **Success**: Exit immediately when ANY target succeeds
- **Timeout**: 500ms by default (configurable)

### Tier 2: Quorum

The Quorum tier delivers messages to stable infrastructure nodes that store and forward messages to recipients when they come online.

- **Targets**: HTTP mailbox nodes and MQTT brokers
- **Strategy**: Broadcast to ALL configured stable targets
- **Success**: Requires configurable quorum to be satisfied
- **Timeout**: 5 seconds by default (configurable)

### Tier 3: Best-Effort

The Best-Effort tier provides fire-and-forget delivery over constrained networks for disaster/offline scenarios.

- **Targets**: BLE mesh, LoRa/Meshtastic (not yet implemented)
- **Strategy**: Best effort transmission
- **Success**: Fire and forget (outbox handles retries)

## Quorum Strategies

The Quorum tier requires a configurable number of transports to succeed before considering delivery complete. This ensures redundancy in case some nodes fail.

### Available Strategies

| Strategy | Description |
|----------|-------------|
| **Any** | Any single transport success (legacy behavior) |
| **Count(N)** | At least N transports must succeed |
| **Fraction(F)** | Fraction of configured stable transports must succeed (e.g., 0.5 = majority) |
| **All** | All configured stable transports must succeed |

### Default Behavior

- For 1-2 transports: `Any` strategy
- For 3+ transports: `Count(2)` recommended

### Examples

| Config          | 5 Transports       | Meaning                           |
|-----------------|--------------------|-----------------------------------|
| `Any`           | 1 success needed   | Legacy behavior                   |
| `Count(2)`      | 2 successes needed | At least 2 nodes have the message |
| `Fraction(0.5)` | 3 successes needed | Majority of nodes                 |
| `All`           | 5 successes needed | Every configured node             |

## Three-Phase Delivery State Machine

Each message in the outbox goes through three phases:

```text
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: URGENT (Quorum not reached)                           │
│  ├─ FULL PIPELINE RETRY: Direct → Quorum → Best-Effort          │
│  │   └─ Recipient may have come online since last attempt!      │
│  ├─ Direct success → transition to Distributed                  │
│  ├─ Quorum: retry FAILED targets only (skip successes)          │
│  ├─ Exponential backoff: 5s → 10s → 20s → 40s → 60s (cap)       │
│  └─ Transition to Phase 2 when quorum OR direct delivery        │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 2: DISTRIBUTED (Quorum reached, awaiting ACK)            │
│  ├─ FULL PIPELINE REFRESH: Direct → Quorum                      │
│  │   └─ Recipient may be online now - try direct first!         │
│  ├─ Direct success → upgrade confidence level                   │
│  ├─ Quorum: refresh ALL targets (nodes may have crashed)        │
│  ├─ Periodic: every 4 hours (configurable)                      │
│  └─ Transition to Phase 3 when recipient ACKs                   │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 3: CONFIRMED (Recipient ACKed via DAG/tombstone)         │
│  └─ Remove from outbox after cleanup delay                      │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 1: Urgent

Messages start in the Urgent phase with aggressive retry behavior.

- **Goal**: Reach quorum or achieve direct delivery
- **Retry Strategy**: Full pipeline (Direct → Quorum → Best-Effort)
- **Backoff**: Exponential with configurable initial delay, max delay, and multiplier
- **Quorum Retry**: Only retry FAILED targets (skip already successful ones)
- **Transition**: Move to Distributed when quorum reached OR Direct succeeds

### Phase 2: Distributed

Messages in the Distributed phase have reached infrastructure and await recipient acknowledgment.

- **Goal**: Ensure message availability until recipient ACKs
- **Maintenance**: Periodic refresh at configurable interval
- **Refresh Strategy**: Full pipeline (Direct first, then ALL Quorum targets)
- **Direct Check**: Always try Direct first - recipient may have come online!
- **Transition**: Move to Confirmed when recipient ACKs via DAG/tombstone

### Phase 3: Confirmed

Messages are confirmed when the recipient acknowledges receipt.

- **Confirmation Sources**: DAG reference or tombstone receipt
- **Action**: Remove from outbox after cleanup delay

## Delivery Confidence

The system tracks confidence levels to understand delivery quality:

| Confidence Level   | Description                                                                                                                            |
|--------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| **QuorumReached**  | Message reached N stable transports (store-and-forward). Recipient will get it when they poll. Tracks success count vs required count. |
| **DirectDelivery** | Message delivered directly to recipient or their peer. Highest confidence - recipient (or their proxy) has it.                         |

**Direct success > Quorum**: Direct delivery is always better than store-and-forward, so Direct tier success immediately transitions to Distributed phase regardless of Quorum tier results.

## Client Operations

### Tiered Delivery Operations

| Operation                  | Description                                                                                                                                  |
|----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| **send_text_tiered**       | Send message with tiered delivery and quorum semantics. Returns message ID and initial delivery phase.                                       |
| **process_urgent_retries** | Background task to process urgent retries for messages that haven't reached quorum. Returns list of processed entries with their new phases. |
| **process_maintenance**    | Background task to process maintenance refreshes for distributed messages. Returns count of refreshed messages.                              |
| **tiered_outbox_tick**     | Combined tick operation: expire messages, process urgent retries, run maintenance. Returns counts of (urgent, maintenance, expired).         |

### Background Task Loop (Pseudocode)

```text
LOOP forever:
    # Process all outbox operations in one tick
    (urgent_count, maintenance_count, expired_count) = tiered_outbox_tick()

    # Log progress if any work was done
    IF urgent_count > 0:
        log("Processed {urgent_count} urgent retries")
    IF maintenance_count > 0:
        log("Refreshed {maintenance_count} distributed messages")
    IF expired_count > 0:
        log("Expired {expired_count} messages")

    # Sleep for tick interval (default 5 seconds)
    sleep(tick_interval)
END LOOP
```

## Configuration

### Config File Structure

```toml
[delivery]
# Quorum strategy for Quorum tier
quorum = "any"  # or { count = 2 }, { fraction = 0.5 }, "all"

# Phase 1 (Urgent) retry settings
urgent_initial_delay_secs = 5
urgent_max_delay_secs = 60
urgent_backoff_multiplier = 2.0

# Phase 2 (Maintenance) settings
maintenance_interval_hours = 4
maintenance_enabled = true

# Tier timeouts
direct_tier_timeout_ms = 500
quorum_tier_timeout_secs = 5
```

### Configuration Options

| Option                       | Type          | Default | Description                                                               |
|------------------------------|---------------|---------|---------------------------------------------------------------------------|
| `quorum`                     | string/object | `"any"` | Quorum strategy: `"any"`, `"all"`, `{ count = N }`, or `{ fraction = F }` |
| `urgent_initial_delay_secs`  | integer       | `5`     | Initial retry delay in urgent phase                                       |
| `urgent_max_delay_secs`      | integer       | `60`    | Maximum retry delay in urgent phase                                       |
| `urgent_backoff_multiplier`  | float         | `2.0`   | Backoff multiplier for urgent retries                                     |
| `maintenance_interval_hours` | integer       | `4`     | Hours between maintenance refreshes                                       |
| `maintenance_enabled`        | bool          | `true`  | Enable maintenance refreshes                                              |
| `direct_tier_timeout_ms`     | integer       | `500`   | Direct tier timeout in milliseconds                                       |
| `quorum_tier_timeout_secs`   | integer       | `5`     | Quorum tier timeout in seconds                                            |

## Outbox Persistence

The outbox persists message delivery state to ensure reliability across restarts.

### Stored Data Per Message

| Field                      | Description                                      |
|----------------------------|--------------------------------------------------|
| Recipient ID               | 32-byte public identity of the recipient         |
| Content ID                 | 8-byte content identifier for DAG tracking       |
| Message ID                 | 16-byte unique message identifier                |
| Envelope bytes             | Serialized outer envelope for re-transmission    |
| Inner bytes                | Serialized inner envelope (encrypted payload)    |
| Created timestamp          | When the message was queued                      |
| Expiration timestamp       | Optional TTL for message cleanup                 |
| Delivery phase             | Current phase: urgent, distributed, or confirmed |
| Next retry timestamp       | When the next retry should occur                 |
| Last maintenance timestamp | When last maintenance refresh occurred           |

### Per-Target Tracking

| Data            | Description                                                            |
|-----------------|------------------------------------------------------------------------|
| Success records | Which targets have successfully received the message, with timestamps  |
| Attempt history | Per-target attempt records with timestamps, results, and error details |

## Node Integration Path

The architecture is designed for mailbox nodes to reuse the same transport coordinator:

```text
ON message_received(envelope, source_target):
    # Store locally for recipient to fetch
    store.enqueue(envelope)

    # Replicate via coordinator (same as Client)
    # Exclude source to avoid echo
    config = delivery_config.with_excluded_target(source_target)
    result = coordinator.submit_tiered(envelope, config)

    # Node doesn't track outbox state (message came from outside)
    # But could log replication success for monitoring
END
```

**Node differences from Client**:
- No outbox persistence (messages come from clients)
- Exclude source transport when replicating to avoid echo
- Respect message TTL (don't store forever)

## Future Enhancements

1. **Best-Effort Tier**: Implement BLE mesh and LoRa/Meshtastic transports
2. **Smart Quorum**: Auto-adjust quorum based on transport health
3. **Priority Queues**: Urgent messages get preferential retry scheduling
4. **Compression**: Reduce message size for constrained transports
5. **Adaptive Timeouts**: Adjust tier timeouts based on historical latency
6. **Transition to Confirmed** after Urgent phase succeeds: Add receipts to verify that receipt is actually received by intended party and skip broadcasting
