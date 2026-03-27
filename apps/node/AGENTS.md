# Node (Mailbox Server)

Axum-based store-and-forward mailbox server. Stores encrypted envelopes keyed by `routing_key` and serves them to recipients.

## Running

```bash
cargo run --bin node                          # Default: http://127.0.0.1:23003
cargo run --bin node -- --port 3001           # Custom port
cargo run --bin node -- --tls-enabled --tls-cert cert.pem --tls-key key.pem
```

## Module Map

| File                | Purpose                                                               |
|---------------------|-----------------------------------------------------------------------|
| `main.rs`           | Entry point, config loading, server startup, graceful shutdown        |
| `api.rs`            | Axum router + all HTTP handlers                                       |
| `config.rs`         | CLI args (clap), env vars (`REME_NODE_*`), TOML config, layered merge |
| `cleanup.rs`        | Background task: TTL expiration of old messages                       |
| `mqtt_bridge.rs`    | Optional MQTT subscriber/publisher bridge                             |
| `replication.rs`    | Fire-and-forget replication to peer nodes                             |
| `node_identity.rs`  | Node's X25519 identity (signing, challenge-response)                  |
| `rate_limit.rs`     | Per-IP and per-routing-key rate limiting (tower_governor)             |
| `signed_headers.rs` | XEdDSA signature verification for node-to-node requests               |

## API Endpoints

| Method | Path                               | Auth  | Purpose                                  |
|--------|------------------------------------|-------|------------------------------------------|
| `POST` | `/api/v1/submit`                   | Basic | Submit message or ack-tombstone          |
| `GET`  | `/api/v1/fetch/{routing_key}`      | Basic | Fetch messages (paginated, cursor-based) |
| `GET`  | `/api/v1/stats`                    | Basic | Mailbox statistics                       |
| `GET`  | `/api/v1/identity?challenge=<b64>` | None  | Challenge-response identity verification |
| `GET`  | `/api/v1/health`                   | None  | Health check / readiness probe           |

## Config File

`~/.config/reme/node.toml` — see `config.rs` module docs for full reference including TLS, MQTT, peers, rate limits.

Env prefix: `REME_NODE_*` (e.g., `REME_NODE_BIND_ADDR`, `REME_NODE_STORAGE_PATH`).

## Non-obvious Patterns

- **Signed headers**: Node-to-node requests carry `x-node-signature` for loop prevention and source verification. Signature includes destination host — `public_host` config is required when identity is active.
- **Receipt generation**: On submit, the node returns an XEdDSA-signed receipt. If the node is the intended recipient (routing_key matches), it also returns an `ack_secret` derived from ECDH.
- **Crypto offloading**: XEdDSA signing and ECDH operations use `spawn_blocking` to avoid blocking Tokio workers.
- **Fetch response size cap**: `MAX_FETCH_RESPONSE_BYTES` (64 KiB) limits response size; large result sets are paginated even if within the row limit.
- **Body limit**: 256 KiB max request body (`MAX_BODY_SIZE`).
- **Storage**: SQLite via `PersistentMailboxStore`. Defaults to `:memory:` (no persistence across restarts).
- **Graceful shutdown**: `CancellationToken` propagated to cleanup task, MQTT bridge, and HTTP server. 10s shutdown timeout.
