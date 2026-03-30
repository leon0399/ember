# GitHub Copilot Code Review Instructions

## Review Philosophy

- Only comment when you have HIGH CONFIDENCE (>80%) that an issue exists
- Be concise: one sentence per comment when possible
- Focus on actionable feedback, not observations
- When in doubt, stay silent — false positives create noise and erode trust

## Priority Areas (Review These)

### Security & Cryptography

This codebase is a security-critical encrypted messaging system. Extra scrutiny applies to anything touching keys, encryption, or identity:

- `unsafe` blocks without a `// SAFETY:` justification comment
- Credential or key material exposure in logs, errors, or debug output (URLs must be sanitized before logging — use `TargetId::as_str()`, not raw URL strings)
- Hardcoded secrets or test keys leaking into production paths
- Missing input validation on externally received envelopes or wire formats
- Improper error handling that could leak cryptographic material (e.g., returning the raw key in an error message)
- Changes to `ember-encryption` or `ember-identity` that alter the wire format without bumping the protocol version
- Identity verification bypass in discovery: peers must be verified via challenge-response before being registered as ephemeral targets

### Correctness Issues

- `unwrap()` or `expect()` in library crates (`crates/` directory) — use `?` and proper error propagation instead
- Mutex lock poisoning not handled: poisoned locks must map to a `*Error::LockPoisoned` variant and propagate via `?`, not panic
- Race conditions in async code (tokio tasks sharing mutable state without proper synchronization)
- SQLite `IN (...)` queries not chunked when binding many parameters — SQLite has a limit of 999 bound parameters; large sets must be chunked
- Resource leaks: unclosed database connections, HTTP connections not returned to pool, tasks not joined/aborted
- Off-by-one errors in byte slicing on fixed-size wire types (`RoutingKey` = 16 bytes, `PublicID` = 32 bytes, `MessageID` = 16 bytes, `ContentId` = 8 bytes, `ack_hash` = 16 bytes)
- Error context that adds no useful information beyond what the underlying error already says
- Overly defensive checks with unreachable branches that should instead be type-enforced
- Unnecessary comments that only restate what the code already shows

### Architecture & Patterns

- Code that violates the layered crate dependency order: `ember-core` depends on everything; lower-level crates must not depend on higher-level crates
- Error types must use `thiserror` — all library crates use `thiserror` for structured error enums, not `anyhow`
- Async blocking: no `std::thread::sleep`, blocking I/O, or CPU-bound work on the tokio async executor without `spawn_blocking`
- Transport registration: ephemeral targets (mDNS-discovered peers) are SEND-only; registering them with FETCH or QUORUM_CREDIT capability is wrong
- Wire format changes: `bincode v2` is used for all wire formats — adding/removing/reordering fields in serialized structs without a version gate breaks wire compatibility
- Improper trait implementations on public types in `ember-transport` or `ember-message` that could allow misuse

## Project-Specific Context

- Pure Rust cargo workspace; no JavaScript or frontend code
- Core crates: `ember-identity`, `ember-encryption`, `ember-message`, `ember-transport`, `ember-storage`, `ember-outbox`, `ember-node-core`, `ember-config`, `ember-discovery`, `ember-core`
- Apps: `apps/node` (Axum mailbox server), `apps/client` (ratatui TUI)
- Error handling: `thiserror` with structured error enums in all `crates/`; no `anyhow` in library code
- Async runtime: tokio
- Serialization: bincode v2 for wire formats, serde for config
- Crypto: X25519 MIK, BLAKE3 KDF, ChaCha20Poly1305 — any changes here require careful review
- Project phase: research/prototype — breaking API changes are acceptable and encouraged if they improve architecture

## CI Pipeline Context

**Important**: Copilot reviews PRs before CI completes. Do not flag issues CI will catch automatically.

### What CI checks (`.github/workflows/lint.yml`)

- `cargo fmt --all -- --check` — formatting (rustfmt)
- `cargo clippy --all-targets --all-features -- -D warnings` — linting (clippy, treated as errors)

### What CI does NOT check

- `cargo test` is not in CI yet — test failures are worth flagging if you can identify a clear logic error
- No OpenAPI or schema validation

## Skip These (Low Value)

Do not comment on:

- **Formatting** — CI enforces rustfmt
- **Clippy warnings** — CI treats them as errors
- **Minor naming suggestions** — unless the name is genuinely misleading
- **Suggestions to add comments** — for self-documenting code
- **Refactoring suggestions** — unless there is a clear bug or correctness issue
- **Missing tests** — unless a specific existing test would clearly catch a regression introduced in this PR
- **Logging suggestions** — the codebase needs less noise, not more; only flag if error events or security-relevant operations are silently swallowed
- **Style preferences** — single vs double indirection, etc.
- **Multiple issues in one comment** — choose the single most critical issue per location

## Response Format

When you identify an issue:

1. **State the problem** (1 sentence)
2. **Why it matters** (1 sentence, only if not obvious)
3. **Suggested fix** (code snippet or specific action)

Example:
```
This `unwrap()` in a library crate will panic if the lock is poisoned. Map it to `Error::LockPoisoned` and propagate with `?`.
```

## When to Stay Silent

If you are not confident an issue exists, do not comment.
