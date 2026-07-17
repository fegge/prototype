# Finding 015 — Concurrent reads observe provisional, signature-unverified state during deferred verification

- **Severity:** Medium (authenticity of read results during a race window)
- **Component:** `sdk/src/changelog.rs` (`apply_broadcast_change`,
  `apply_fast_forward_from_anchor`), `sdk/src/table.rs` (read path)
- **Status:** Confirmed by code inspection

## Description

Both the broadcast apply path and the fast-forward path advance the client's committed
data commitment (DC) **before** the entry's signature is verified, using a
deferred-then-rollback pattern:

- `apply_broadcast_change` (`changelog.rs:1171-1260`) takes **no**
  `serialize_mutations` / `ff_in_progress` guard. When key resolution fails (stale DC) it
  applies the change via `validate_and_apply_change` (`:1235`, which advances
  `current_data_commitment`) and only *then* retries signature verification (`:1241-1257`),
  rolling back if it fails.
- The FF path holds `serialize_mutations` (`:1958`) and installs provisional state, then
  performs deferred signature verification at `:2409-2422`, rolling back on failure.

The read path takes **no** guard at all:

```rust
// sdk/src/table.rs:714 / 743 / 847
let commitment = self.space.current_data_commitment();   // plain state read, unguarded
... verify_query_proof_with_hashed_values(&query, &proof, &commitment, ...) ...
```

So a `SELECT` issued concurrently with a broadcast/FF apply can read
`current_data_commitment` while it points at a change whose **authorship signature has not
yet been verified** (and may still be rolled back). The row *data* is Merkle-proven and
ACL-checked (via `verify_proof_and_validate`), but *who authored* the latest change is not
yet confirmed at that instant.

## Exploit / failure scenario

1. A malicious server delivers a broadcast whose entry claims `uid = V` (a legitimate
   member) but carries an **invalid signature**, and arranges for key resolution to
   initially fail so the deferred path is taken (e.g. the entry references key state the
   client hasn't resolved yet).
2. `apply_broadcast_change` applies the change — `current_data_commitment` now includes the
   entry's writes — before the deferred signature retry runs.
3. A concurrent `SELECT` on the touched table reads the advanced DC and returns the new
   rows, which the application consumes as authentic (authored by V).
4. The deferred signature retry then fails and the state is rolled back — but the
   application has already acted on data attributed to an entry that never had a valid
   author signature.

The exposure window is short and the data is ACL/Merkle-valid (only authorship is
pending), so this is not a full forgery, but it lets a server transiently surface
unauthorized-author writes to a concurrent reader — a break of the "authenticated
authorship" property under concurrency.

## Recommended fix

- Hold a read lock coordinated with `serialize_mutations` / `ff_in_progress` (or a
  dedicated RW-lock over committed state) on the query read path, so reads never observe a
  DC that is mid-apply or pending deferred verification.
- Alternatively, do not advance `current_data_commitment` until signature verification has
  succeeded: verify authorship *before* publishing the new DC to readers, even on the
  deferred path (e.g. apply to a shadow state, promote only after the deferred check
  passes).
- Ensure `apply_broadcast_change` acquires the same guard the FF and signer paths use, so
  a concurrent signer/reader cannot interleave with a broadcast mid-apply.
