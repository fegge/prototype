# Finding 012 — "Already-applied" re-verification returns writes from an unanchored proof (cache / row-id poisoning)

- **Severity:** Medium (local integrity: wrong returned row-id and poisoned cache; does
  not corrupt the committed data commitment)
- **Component:** `sdk/src/changelog.rs` (`validate_and_apply_change` already-applied
  branch), `sdk/src/table.rs`
- **Status:** Confirmed by code inspection
- **Related:** Same missing-`old_root`-binding root cause as Finding 008, on a
  non-mutating path.

## Description

When a response arrives for a change the client has already applied (e.g. the broadcast
listener applied it first), `validate_and_apply_change` re-verifies the proof to extract
the writes but skips the data-commitment binding:

```rust
// sdk/src/changelog.rs:1408-1426
if response.change_id <= current_change_id {
    if response.pruned_merkle_tree.is_empty() { return Ok(Vec::new()); }
    return ChangeLog::verify_proof_and_validate(
        change,
        &response.pruned_merkle_tree,   // server-supplied
        &response.old_root,             // server-supplied — NOT checked against current DC
        &response.new_root,             // server-supplied
        response.change_id as usize,
    ).map_err(...);
}
```

Contrast the normal path a few lines below, which enforces
`response.old_root == current_data_commitment` (`changelog.rs:1437`). The already-applied
branch does not mutate committed state, so it cannot forge the DC — but the **returned
`writes`** come from an unanchored, server-chosen tree. Callers consume those writes:
`table.rs` uses them to read the auto-assigned insert row-id and to populate the local
cache (`update_cache_from_proven_writes`, `table.rs:~1345`; sibling auto-id sites at
`action.rs:~137`, `users.rs:~297`).

## Exploit / failure scenario

1. A client submits an insert; the broadcast listener applies the genuine change (through
   the checked path, so committed state is correct).
2. The direct response for the same `change_id` arrives and takes the already-applied
   branch. The malicious server supplies a self-consistent proof over a **different**
   tree (any `old_root`/`new_root` pair with a matching pruned tree), assigning a
   different row-id and different row content.
3. `verify_proof_and_validate` passes (self-consistent), and the SDK returns the
   attacker-chosen row-id to the caller and writes attacker-chosen content into the local
   cache. The application's subsequent id-keyed `update`/`delete`/read then targets the
   wrong row, and cached reads return forged content — even though the authenticated DC is
   correct. Issue #232's "never a false success" note covers the insert's *acceptance*
   but not the poisoned return value / cache.

## Recommended fix

- Bind the already-applied re-verification to trusted state: require
  `response.new_root` (or `old_root`) to match the client's committed data commitment at
  that `change_id`, or re-derive the writes from the client's own verified tree rather
  than the server-supplied proof.
- Do not feed writes from an unanchored proof into `update_cache_from_proven_writes` or
  into returned row-ids; source auto-assigned ids from state that has passed the
  `old_root`/DC binding.
