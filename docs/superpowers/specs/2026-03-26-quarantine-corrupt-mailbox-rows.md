# Quarantine corrupt mailbox rows

**Issue:** #127 (SEC-L11)
**Milestone:** Postcard Migration (final item)

## Problem

When `fetch_page` encounters a row that fails `postcard::from_bytes`, it deletes the row and logs a warning. This means a node serving corrupted data (e.g., from a compromised replication peer or a serialization bug) silently loses messages with no recovery path.

The `get_message` path propagates the deserialization error but doesn't quarantine the corrupt row either.

## Solution

Move corrupt rows to a `quarantined_messages` table instead of deleting them. Preserve the raw bytes for forensic analysis and potential future recovery.

## Schema

Add `quarantined_messages` to `init_schema` (no migration — PoC stage, no deployed nodes):

```sql
CREATE TABLE IF NOT EXISTS quarantined_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_id INTEGER,
    routing_key BLOB NOT NULL,
    message_id BLOB,
    envelope_data BLOB NOT NULL,
    error TEXT NOT NULL,
    quarantined_at INTEGER NOT NULL,
    original_expires_at INTEGER,
    original_created_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_quarantine_expires
    ON quarantined_messages(original_expires_at);
```

`message_id` is nullable — if the raw bytes are too corrupt to even extract the message ID, we still quarantine them.

## Affected code paths

### `fetch_page` (bulk fetch)

Currently collects corrupt row IDs into `invalid_ids_to_delete` and calls `delete_rows`. Change to:

1. Collect corrupt entries as `(id, routing_key, raw_blob, error_string)`.
2. New method `quarantine_rows` runs in a single transaction:
   - INSERT each entry into `quarantined_messages`
   - DELETE corresponding rows from `mailbox_messages`
3. Log at `warn!` with structured fields: row_id, routing_key prefix, error.

### `get_message` (single fetch by message_id)

Currently returns `Err(NodeError::Deserialization(...))` on corrupt data. Change to:

1. If `deserialize_envelope` fails, quarantine the row.
2. Return `Ok(None)` — the message is effectively gone from the caller's perspective, same as if it didn't exist. The quarantine + warn log provides the audit trail.

Returning `Ok(None)` rather than `Err` is deliberate: the caller (sync protocol) shouldn't fail its entire operation because one message is corrupt. The row is quarantined and logged.

## Cleanup

Extend `cleanup_expired` to also delete quarantined rows past their `original_expires_at`:

```sql
DELETE FROM quarantined_messages WHERE original_expires_at <= ?
```

Quarantined rows without an `original_expires_at` (NULL) are cleaned up after the default TTL from `quarantined_at`.

## Stats

Add `quarantined_messages: usize` to `PersistentStoreStats`. Queried as:

```sql
SELECT COUNT(*) FROM quarantined_messages
```

## Error handling

If the quarantine INSERT fails (e.g., disk full), fall back to deleting the corrupt row — the current behavior. Log at `error!` level to distinguish from normal quarantine `warn!`. Losing the corrupt data is acceptable as a fallback; blocking the fetch path is not.

## Trait boundary

`MailboxStore` trait is unchanged. Quarantine is an implementation detail of `PersistentMailboxStore`. No API changes for consumers.

## Testing

- Unit test: enqueue a valid message, manually corrupt the `envelope_data` in SQLite, fetch — verify the row moves to `quarantined_messages` with correct metadata.
- Unit test: same corruption scenario via `get_message` — verify quarantine + `Ok(None)` return.
- Unit test: verify `cleanup_expired` removes expired quarantined rows.
- Unit test: verify `stats()` reports quarantine count.
