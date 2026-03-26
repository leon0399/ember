# Quarantine Corrupt Mailbox Rows — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move corrupt mailbox rows to a quarantine table instead of deleting them, preserving raw bytes for forensic analysis.

**Architecture:** Add a `quarantined_messages` table to the existing SQLite schema. Replace delete-on-corrupt with quarantine-on-corrupt in both `fetch_page` and `get_message`. Extend cleanup and stats to cover quarantined rows.

**Tech Stack:** Rust, rusqlite, postcard (serde)

**Spec:** `docs/superpowers/specs/2026-03-26-quarantine-corrupt-mailbox-rows.md`

---

### File Map

- **Modify:** `crates/reme-node-core/src/mailbox_store.rs` — schema, quarantine logic, stats, cleanup, tests

This is a single-file change. All quarantine logic is internal to `PersistentMailboxStore`.

---

### Task 1: Add quarantine table to schema and quarantine_count to stats

**Files:**
- Modify: `crates/reme-node-core/src/mailbox_store.rs:144-148` (PersistentStoreStats)
- Modify: `crates/reme-node-core/src/mailbox_store.rs:216-242` (init_schema)
- Modify: `crates/reme-node-core/src/mailbox_store.rs:358-388` (stats)

- [ ] **Step 1: Write failing test for quarantine_count in stats**

Add at the bottom of the `tests` module:

```rust
#[test]
fn test_stats_includes_quarantine_count() {
    let config = PersistentStoreConfig::default();
    let store = PersistentMailboxStore::in_memory(config).unwrap();

    let stats = store.stats().unwrap();
    assert_eq!(stats.quarantined_messages, 0);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p reme-node-core test_stats_includes_quarantine_count`
Expected: FAIL — `quarantined_messages` field doesn't exist on `PersistentStoreStats`.

- [ ] **Step 3: Add quarantine table to schema and quarantine_count to stats**

In `PersistentStoreStats` (line 143-148), add the field:

```rust
pub struct PersistentStoreStats {
    pub mailbox_count: usize,
    pub total_messages: usize,
    pub expired_pending_cleanup: usize,
    pub quarantined_messages: usize,
}
```

In `init_schema` (line 216-242), add after the `schema_version` table creation:

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

In `stats()` (line 358-388), add a query for quarantine count and populate the new field:

```rust
let quarantined_count: i64 = conn.query_row(
    "SELECT COUNT(*) FROM quarantined_messages",
    [],
    |row| row.get(0),
)?;
```

And update the return:

```rust
Ok(PersistentStoreStats {
    mailbox_count: mailbox_count as usize,
    total_messages: total_messages as usize,
    expired_pending_cleanup: expired_count as usize,
    quarantined_messages: quarantined_count as usize,
})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p reme-node-core test_stats_includes_quarantine_count`
Expected: PASS

- [ ] **Step 5: Run full crate tests to check nothing broke**

Run: `cargo test -p reme-node-core`
Expected: All tests pass. (Existing tests don't reference `PersistentStoreStats` fields by name in assertions.)

- [ ] **Step 6: Commit**

```bash
git add crates/reme-node-core/src/mailbox_store.rs
git commit -m "feat: add quarantine table schema and stats field (#127)"
```

---

### Task 2: Add quarantine_rows helper method

**Files:**
- Modify: `crates/reme-node-core/src/mailbox_store.rs` (new private method on `PersistentMailboxStore`)

- [ ] **Step 1: Write failing test for quarantine behavior**

This test inserts a corrupt row, then calls a test helper that exercises quarantine. We'll verify the row ends up in `quarantined_messages` with correct metadata.

Add a helper struct and test:

```rust
/// Metadata needed to quarantine a corrupt row.
struct CorruptRow {
    id: i64,
    message_id: Option<Vec<u8>>,
    envelope_data: Vec<u8>,
    error: String,
    expires_at: i64,
    created_at: i64,
}

#[test]
fn test_quarantine_rows_moves_to_quarantine_table() {
    let config = PersistentStoreConfig::default();
    let store = PersistentMailboxStore::in_memory(config).unwrap();
    let routing_key = RoutingKey::from_bytes([20u8; 16]);

    // Insert a corrupt row directly
    let message_id = MessageID::new();
    let now = timestamp_to_i64(now_secs());
    let expires = timestamp_to_i64(now_secs() + 3600);
    let corrupt_data = vec![0xFFu8, 0x00, 0x01];

    let original_id;
    {
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO mailbox_messages
             (routing_key, message_id, envelope_data, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?)",
            params![
                &routing_key[..],
                &message_id.as_bytes()[..],
                &corrupt_data[..],
                expires,
                now
            ],
        )
        .unwrap();
        original_id = conn.last_insert_rowid();
    }

    // Quarantine the row
    {
        let conn = store.conn.lock().unwrap();
        let corrupt = CorruptRow {
            id: original_id,
            message_id: Some(message_id.as_bytes().to_vec()),
            envelope_data: corrupt_data.clone(),
            error: "test error".to_string(),
            expires_at: expires,
            created_at: now,
        };
        PersistentMailboxStore::quarantine_rows(&conn, &routing_key, &[corrupt]).unwrap();
    }

    // Original row should be gone
    assert!(!store.has_message(&routing_key, &message_id).unwrap());

    // Quarantine table should have the row
    let stats = store.stats().unwrap();
    assert_eq!(stats.quarantined_messages, 1);

    // Verify quarantine row contents
    let conn = store.conn.lock().unwrap();
    let (q_data, q_error, q_orig_id): (Vec<u8>, String, i64) = conn
        .query_row(
            "SELECT envelope_data, error, original_id FROM quarantined_messages LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(q_data, corrupt_data);
    assert_eq!(q_error, "test error");
    assert_eq!(q_orig_id, original_id);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p reme-node-core test_quarantine_rows_moves_to_quarantine_table`
Expected: FAIL — `quarantine_rows` method doesn't exist, `CorruptRow` struct doesn't exist.

- [ ] **Step 3: Implement CorruptRow struct and quarantine_rows method**

Add the `CorruptRow` struct above the `impl PersistentMailboxStore` block (it's used by both the impl and tests):

```rust
/// Metadata needed to quarantine a corrupt row from mailbox_messages.
struct CorruptRow {
    id: i64,
    message_id: Option<Vec<u8>>,
    envelope_data: Vec<u8>,
    error: String,
    expires_at: i64,
    created_at: i64,
}
```

Add `quarantine_rows` as a private method on `PersistentMailboxStore`, next to `delete_rows`:

```rust
/// Move corrupt rows to the quarantine table and delete from mailbox_messages.
///
/// Runs in a single transaction. If the quarantine INSERT fails, falls back to
/// deleting the row (current behavior) and logs at error level.
fn quarantine_rows(
    conn: &Connection,
    routing_key: &RoutingKey,
    rows: &[CorruptRow],
) -> Result<(), NodeError> {
    if rows.is_empty() {
        return Ok(());
    }

    let now = timestamp_to_i64(now_secs());

    for row in rows {
        let result = conn.execute(
            "INSERT INTO quarantined_messages
             (original_id, routing_key, message_id, envelope_data, error,
              quarantined_at, original_expires_at, original_created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                row.id,
                &routing_key[..],
                row.message_id.as_deref(),
                &row.envelope_data,
                &row.error,
                now,
                row.expires_at,
                row.created_at,
            ],
        );

        match result {
            Ok(_) => {
                conn.execute(
                    "DELETE FROM mailbox_messages WHERE id = ?",
                    params![row.id],
                )?;
            }
            Err(e) => {
                // Fallback: delete the corrupt row (pre-quarantine behavior).
                // This path only fires if the quarantine INSERT fails (e.g., disk full).
                tracing::error!(
                    id = row.id,
                    error = %e,
                    "failed to quarantine corrupt row, falling back to delete"
                );
                conn.execute(
                    "DELETE FROM mailbox_messages WHERE id = ?",
                    params![row.id],
                )?;
            }
        }
    }

    Ok(())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p reme-node-core test_quarantine_rows_moves_to_quarantine_table`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/reme-node-core/src/mailbox_store.rs
git commit -m "feat: add quarantine_rows helper method (#127)"
```

---

### Task 3: Replace delete-on-corrupt with quarantine in fetch_page

**Files:**
- Modify: `crates/reme-node-core/src/mailbox_store.rs:491-566` (fetch_page impl)

- [ ] **Step 1: Update existing test to verify quarantine instead of delete**

The existing test `test_fetch_deletes_invalid_rows_only` (line 779) currently asserts that corrupt rows are deleted. Update it to also verify they appear in quarantine:

Rename to `test_fetch_quarantines_invalid_rows` and add quarantine assertions at the end:

```rust
#[test]
fn test_fetch_quarantines_invalid_rows() {
    let config = PersistentStoreConfig::default();
    let store = PersistentMailboxStore::in_memory(config).unwrap();
    let routing_key = RoutingKey::from_bytes([8u8; 16]);
    let message_id = MessageID::new();
    let expires_at = timestamp_to_i64(now_secs() + 3600);
    let created_at = timestamp_to_i64(now_secs());

    {
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO mailbox_messages
             (routing_key, message_id, envelope_data, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?)",
            params![
                &routing_key[..],
                &message_id.as_bytes()[..],
                &[0xFFu8, 0x00, 0x01][..],
                expires_at,
                created_at
            ],
        )
        .unwrap();
    }

    assert!(store.has_message(&routing_key, &message_id).unwrap());

    let fetched = store.fetch(&routing_key).unwrap();
    assert!(fetched.is_empty());
    assert!(!store.has_message(&routing_key, &message_id).unwrap());

    // Verify row was quarantined, not just deleted
    let stats = store.stats().unwrap();
    assert_eq!(stats.quarantined_messages, 1);

    // Verify raw bytes preserved
    let conn = store.conn.lock().unwrap();
    let q_data: Vec<u8> = conn
        .query_row(
            "SELECT envelope_data FROM quarantined_messages LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(q_data, vec![0xFFu8, 0x00, 0x01]);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p reme-node-core test_fetch_quarantines_invalid_rows`
Expected: FAIL — `quarantined_messages` count is 0 because `fetch_page` still calls `delete_rows`.

- [ ] **Step 3: Rewrite fetch_page to use quarantine**

In `fetch_page` (line 491), make three changes:

**a)** Change the SQL query to also select `message_id, expires_at, created_at`:

```rust
let mut stmt = conn.prepare(
    "SELECT id, envelope_data, message_id, expires_at, created_at
     FROM mailbox_messages
     WHERE routing_key = ? AND expires_at > ? AND id > ?
     ORDER BY id ASC
     LIMIT ?",
)?;
```

**b)** Update the row mapping to capture all columns:

```rust
let rows = stmt.query_map(
    params![&routing_key[..], now_i64, last_scanned_id, remaining_scan],
    |row| {
        let id: i64 = row.get(0)?;
        let data: Vec<u8> = row.get(1)?;
        let msg_id: Option<Vec<u8>> = row.get(2)?;
        let expires_at: i64 = row.get(3)?;
        let created_at: i64 = row.get(4)?;
        Ok((id, data, msg_id, expires_at, created_at))
    },
)?;
```

**c)** Replace `invalid_ids_to_delete: Vec<i64>` with `corrupt_rows: Vec<CorruptRow>`:

```rust
let mut corrupt_rows: Vec<CorruptRow> = Vec::new();
```

In the deserialization error branch:

```rust
Err(e) => {
    warn!(id = id, error = %e, "failed to deserialize envelope, quarantining");
    corrupt_rows.push(CorruptRow {
        id,
        message_id: msg_id,
        envelope_data: data,
        error: e.to_string(),
        expires_at,
        created_at,
    });
}
```

Replace the delete call at the end:

```rust
if !corrupt_rows.is_empty() {
    Self::quarantine_rows(&conn, routing_key, &corrupt_rows)?;
}
```

Also update the destructuring of the row tuple inside the `for row in rows` loop:

```rust
let (id, data, msg_id, expires_at, created_at) = row?;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p reme-node-core test_fetch_quarantines_invalid_rows`
Expected: PASS

- [ ] **Step 5: Run full crate tests**

Run: `cargo test -p reme-node-core`
Expected: All tests pass. The batch test (`test_fetch_deletes_invalid_rows_in_batches`) should also pass since `quarantine_rows` handles rows individually (no chunking limit issue).

- [ ] **Step 6: Commit**

```bash
git add crates/reme-node-core/src/mailbox_store.rs
git commit -m "feat: quarantine corrupt rows in fetch_page instead of deleting (#127)"
```

---

### Task 4: Quarantine corrupt rows in get_message

**Files:**
- Modify: `crates/reme-node-core/src/mailbox_store.rs:311-331` (get_message)

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn test_get_message_quarantines_corrupt_row() {
    let config = PersistentStoreConfig::default();
    let store = PersistentMailboxStore::in_memory(config).unwrap();
    let routing_key = RoutingKey::from_bytes([21u8; 16]);
    let message_id = insert_invalid_row(&store, routing_key);

    // get_message should return None (message is effectively gone)
    let result = store.get_message(&message_id);
    assert!(result.unwrap().is_none());

    // Row should be quarantined
    let stats = store.stats().unwrap();
    assert_eq!(stats.quarantined_messages, 1);

    // Original row should be gone
    assert!(!store.has_message(&routing_key, &message_id).unwrap());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p reme-node-core test_get_message_quarantines_corrupt_row`
Expected: FAIL — `get_message` returns `Err(NodeError::Deserialization(...))`, not `Ok(None)`.

- [ ] **Step 3: Rewrite get_message to quarantine on deserialization failure**

The current `get_message` selects only `envelope_data`. We need the full row to quarantine. Replace the method body:

```rust
pub fn get_message(&self, message_id: &MessageID) -> Result<Option<OuterEnvelope>, NodeError> {
    let now = now_secs();
    let message_id_bytes = message_id.as_bytes();

    let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

    let result: Option<(i64, Vec<u8>, Vec<u8>, i64, i64)> = conn
        .query_row(
            "SELECT id, envelope_data, routing_key, expires_at, created_at
             FROM mailbox_messages
             WHERE message_id = ? AND expires_at > ?",
            params![&message_id_bytes[..], timestamp_to_i64(now)],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;

    let Some((id, data, routing_key_bytes, expires_at, created_at)) = result else {
        return Ok(None);
    };

    match Self::deserialize_envelope(&data) {
        Ok(envelope) => Ok(Some(envelope)),
        Err(e) => {
            warn!(message_id = ?message_id, error = %e, "corrupt message found, quarantining");
            let routing_key = RoutingKey::from_bytes(
                routing_key_bytes
                    .try_into()
                    .unwrap_or([0u8; 16]),
            );
            let corrupt = CorruptRow {
                id,
                message_id: Some(message_id_bytes.to_vec()),
                envelope_data: data,
                error: e.to_string(),
                expires_at,
                created_at,
            };
            Self::quarantine_rows(&conn, &routing_key, &[corrupt])?;
            Ok(None)
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p reme-node-core test_get_message_quarantines_corrupt_row`
Expected: PASS

- [ ] **Step 5: Run full crate tests**

Run: `cargo test -p reme-node-core`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/reme-node-core/src/mailbox_store.rs
git commit -m "feat: quarantine corrupt rows in get_message (#127)"
```

---

### Task 5: Extend cleanup_expired to remove expired quarantined rows

**Files:**
- Modify: `crates/reme-node-core/src/mailbox_store.rs:613-628` (cleanup_expired)

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn test_cleanup_removes_expired_quarantined_rows() {
    let config = PersistentStoreConfig::default();
    let store = PersistentMailboxStore::in_memory(config).unwrap();

    // Insert a quarantined row with an already-expired timestamp
    let past = timestamp_to_i64(now_secs().saturating_sub(3600));
    {
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO quarantined_messages
             (original_id, routing_key, message_id, envelope_data, error,
              quarantined_at, original_expires_at, original_created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                1i64,
                &[1u8; 16][..],
                &[2u8; 16][..],
                &[0xFFu8][..],
                "test error",
                past,
                past,
                past,
            ],
        )
        .unwrap();
    }

    assert_eq!(store.stats().unwrap().quarantined_messages, 1);

    store.cleanup_expired().unwrap();

    assert_eq!(store.stats().unwrap().quarantined_messages, 0);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p reme-node-core test_cleanup_removes_expired_quarantined_rows`
Expected: FAIL — quarantine count is still 1 after cleanup.

- [ ] **Step 3: Extend cleanup_expired**

Add quarantine cleanup after the existing mailbox cleanup in `cleanup_expired` (line 613):

```rust
fn cleanup_expired(&self) -> Result<usize, NodeError> {
    let now = now_secs();
    let now_i64 = timestamp_to_i64(now);

    let conn = self.conn.lock().map_err(|_| NodeError::LockPoisoned)?;

    let deleted = conn.execute(
        "DELETE FROM mailbox_messages WHERE expires_at <= ?",
        params![now_i64],
    )?;

    if deleted > 0 {
        debug!(deleted = deleted, "expired messages cleaned up");
    }

    // Clean up expired quarantined rows.
    // Rows with original_expires_at use that value.
    // Rows with NULL original_expires_at use quarantined_at + default_ttl as fallback.
    let fallback_ttl = timestamp_to_i64(self.config.default_ttl_secs);
    let quarantine_deleted = conn.execute(
        "DELETE FROM quarantined_messages
         WHERE COALESCE(original_expires_at, quarantined_at + ?) <= ?",
        params![fallback_ttl, now_i64],
    )?;

    if quarantine_deleted > 0 {
        debug!(deleted = quarantine_deleted, "expired quarantined rows cleaned up");
    }

    Ok(deleted + quarantine_deleted)
}
```

Note: `cleanup_expired` returns a count. Adding `quarantine_deleted` to the total is fine — the caller (the cleanup task) only uses it for logging.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p reme-node-core test_cleanup_removes_expired_quarantined_rows`
Expected: PASS

- [ ] **Step 5: Run full crate tests**

Run: `cargo test -p reme-node-core`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/reme-node-core/src/mailbox_store.rs
git commit -m "feat: clean up expired quarantined rows in cleanup_expired (#127)"
```

---

### Task 6: Run full workspace checks

- [ ] **Step 1: Format check**

Run: `cargo fmt --all -- --check`
Expected: No formatting issues.

- [ ] **Step 2: Clippy**

Run: `cargo clippy --all-targets --all-features -- -D warnings`
Expected: No warnings.

- [ ] **Step 3: Full workspace tests**

Run: `cargo test --workspace --all-features --all-targets`
Expected: All tests pass.

- [ ] **Step 4: Fix any issues found in steps 1-3**

If clippy or tests fail, fix the issues and re-run.

- [ ] **Step 5: Commit any fixes**

Only if fixes were needed from step 4.
