# Finding 017 — Unauthenticated stack-overflow crash via unbounded postcard recursion in `_retention` value decode

- **Severity:** High (unauthenticated, single-packet, whole-process crash). More acute
  than the README's general DoS caveat: pre-auth, tiny payload, aborts every Space on the
  instance.
- **Component:** `backend/storage-encoding/src/stored_value.rs`, `backend/server/src/db.rs`
- **Status:** Confirmed by code inspection

## Description

`StoredValue`, the on-merk column value type, is recursively nested and is decoded with
**postcard, which imposes no recursion/depth limit** (unlike serde_json's default 128):

```rust
// backend/storage-encoding/src/stored_value.rs:34-44, 106-109
pub enum StoredValue {
    ... Array(Vec<StoredValue>), Object(Vec<(String, StoredValue)>),   // self-referential
}
pub fn bytes_to_value(bytes: &[u8]) -> Result<Value> {
    let stored: StoredValue = postcard::from_bytes(bytes) ... ?;       // recurses per level
    Ok(stored.into())                                                  // From impl ALSO recurses
}
```

Both the `postcard::from_bytes` deserialize **and** the `From<StoredValue> for Value`
conversion (`stored_value.rs:72`) recurse one stack frame per nesting level. In postcard,
each nesting level costs ~2 bytes on the wire (enum discriminant + seq-length varint), so
a payload of a few tens of KB drives the recursion deep enough to overflow the thread
stack. A Rust stack overflow aborts the process (SIGABRT).

This decoder is reached on **client-controlled bytes, before any signature or identity
check**:

```rust
// backend/server/src/db.rs:2870-2885
pub async fn handle_change_with_proofs(&mut self, change, auth, retention_proofs) -> ... {
    self.verify_retention_proofs_from_change(...).await?;   // (A) runs FIRST
    self.handle_change(change, auth).await                  // (B) signature check is in here
}
```

`verify_retention_proofs_from_change` (`db.rs:2890`) calls
`extract_retention_writes_from_change` (`db.rs:231`), which calls
`stored_value::bytes_to_value` **directly on `kv.value`** for any entry whose key parses
as a `_retention` column:

```rust
// backend/server/src/db.rs:253-297 (abridged)
let bytes = kv.value.clone();                              // attacker-controlled
...
entry.0 = stored_value::bytes_to_value(&bytes)...          // db.rs:261
entry.1 = stored_value::bytes_to_value(&bytes)...          // db.rs:265
let key_str  = stored_value::bytes_to_value(key_bytes);    // db.rs:293
let value_blob = stored_value::bytes_to_value(value_bytes);// db.rs:297
```

`handle_change`'s `verify_change_signature` and `auth.uid == entry.uid` checks
(`db.rs:2087`) run only in step (B) — *after* the crashing decode in step (A). The
`MAX_LOGMSG_ENTRIES` / string-size / hashed-values caps also live in `handle_change`, so
none apply before the decode. Server authentication is a spoofable base64 query param
(`http.rs:94`), so no valid credential is needed.

## Exploit / failure scenario

1. An unauthenticated attacker opens a WebSocket, sends one `DbRequest::Change` frame with
   a single entry: key = `_retention` placeholder column `"key"` (or `"value"`), value =
   a deeply-nested postcard encoding of `Array(Array(Array(…)))` (a few tens of KB).
2. `handle_change_with_proofs` → `verify_retention_proofs_from_change` →
   `extract_retention_writes_from_change` → `bytes_to_value` recurses per nesting level.
3. The thread stack overflows; the process aborts. Because all requests are serialized
   through the single global `REQUEST_QUEUE`/`SPACES` machinery, the crash takes down
   **every Space** served by the instance.
4. No signature, membership, or valid `space_id` is required — the crash happens before
   any of that is checked.

## Recommended fix

- Bound recursion when decoding untrusted `StoredValue`: either set an explicit
  depth/`Limit` on the postcard deserializer, cap nesting during decode, or make
  `StoredValue` decoding iterative. Also bound the recursive `From<StoredValue> for Value`
  conversion.
- Apply size/shape limits to change entries **before** the retention decode, and only
  decode `_retention` values *after* the entry's signature and `auth.uid == entry.uid`
  have been verified — do retention-proof extraction post-authentication.
- Run request handling on a bounded-stack worker with catch/return on overflow, or
  validate max nesting depth of any `StoredValue` payload at ingress.
