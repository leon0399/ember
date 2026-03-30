# Ember

End-to-end encrypted messenger that works during network outages, over intermittent connections, and across constrained transports like LoRa or BLE. No session state, no prekeys, no central server required.

> *An ember glows quietly, surviving long after the flame has gone out. When instant messaging systems go dark, Ember keeps messages alive - waiting patiently to deliver them when connectivity returns.*

> 🚧 **Experimental.** Most of the code, tests, and documentation were written by AI (Claude Code, Codex, GitHub Copilot, OpenCode). Humans direct architecture and design decisions but have not reviewed most code line-by-line. There will be bugs. Use at your own risk.

## Features

- Stateless encryption - no session keys or prekeys. Messages work independently, even if delivered out of order or months late.
- Multiple transports - HTTP mailboxes, MQTT broadcast, mDNS/LAN direct P2P. LoRa, Meshtastic, and BLE planned.
- LAN discovery - finds and verifies peers on local networks automatically via mDNS.
- Sneakernet - export/import `.ember` bundles for air-gapped message transfer.
- Delay-tolerant by default - every design decision favors eventual delivery over low latency.

## Status (v0.5)

Proof-of-concept. Working:

- Stateless encryption (MIK-based, similar to Session V1)
- HTTP mailbox transport with pagination
- MQTT broadcast transport
- mDNS/LAN peer discovery with identity verification
- Multi-transport delivery with outbox retry
- Merkle DAG message ordering
- Delivery receipts and cache clearing (tombstones)
- Sneakernet bundle export/import
- TUI client with embedded relay

See [ROADMAP.md](ROADMAP.md) for what's next and [WHITEPAPER.md](WHITEPAPER.md) for the protocol spec.

## Quick start

Requires Rust 1.75+.

```bash
git clone https://github.com/leon0399/ember.git
cd ember
cargo build --release
```

Start a mailbox node and two clients in separate terminals:

```bash
cargo run --bin node -- --port 3000
```

```bash
cargo run --bin client   # Alice
```

```bash
cargo run --bin client   # Bob
```

In the TUI: create an identity, add the other user's Public ID as a contact, and send a message. Messages route through the local mailbox at `http://127.0.0.1:3000`.

### LAN discovery

If both clients have the embedded relay enabled and are on the same network:

1. Set `lan_discovery.enabled = true` in config
2. Set `embedded_node.http_bind = "0.0.0.0:0"` (random port)
3. Restart - clients discover each other via mDNS and send messages directly, bypassing the mailbox

## Architecture

Rust workspace with focused crates (`ember-identity`, `ember-encryption`, `ember-transport`, etc.) and two binaries:

- `client` - TUI (ratatui) with embedded relay
- `node` - standalone mailbox server (Axum)

## Configuration

Both binaries use layered config: CLI args > env vars > config file > defaults.

- Client: `~/.config/ember/config.toml`, env prefix `EMBER_*`
- Node: `~/.config/ember/node.toml`, env prefix `EMBER_NODE_*`

See `apps/client/config.example.toml` and `apps/node/config.example.toml` for all options.

## Documentation

- [WHITEPAPER.md](WHITEPAPER.md) - protocol spec, cryptography, wire format
- [ROADMAP.md](ROADMAP.md) - release timeline and feature planning
- [docs/threat-model.md](docs/threat-model.md) - attack scenarios and mitigations
- [docs/tiered-delivery.md](docs/tiered-delivery.md) - delivery system design
- [docs/lan-discovery.md](docs/lan-discovery.md) - mDNS peer discovery

## Security

No forward secrecy in v0.5. Ember uses stateless encryption to tolerate arbitrary message delay and reordering. If a user's key is compromised, all their past messages are exposed. This is a deliberate tradeoff; forward secrecy is planned for v0.7.

Messages are end-to-end encrypted and authenticated. Relays never see plaintext. See [docs/threat-model.md](docs/threat-model.md) for details.

## Development

```bash
cargo test --workspace --all-features --all-targets
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check
```

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

## Acknowledgments

Ember draws on ideas from [Session](https://getsession.org/) (stateless encryption), [Briar](https://briarproject.org/) (DTN messaging), [Meshtastic](https://meshtastic.org/) (LoRa mesh), [Nostr](https://nostr.com/) (relay architecture), and the [Signal Protocol](https://signal.org/) (studied but not adopted due to DTN incompatibility).

---

[getember.chat](https://getember.chat) · [GitHub](https://github.com/leon0399/ember) · [Issues](https://github.com/leon0399/ember/issues)
