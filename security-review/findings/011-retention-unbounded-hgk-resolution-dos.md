# Finding 011 — Attacker-controlled `dgk_next` makes `resolve_current_hgk` grind unboundedly (retention DoS)

- **Severity:** Medium (authenticated, Space-wide denial of key resolution)
- **Component:** `retention/src/simple_line2/space_key.rs`
- **Status:** Confirmed by code inspection

## Description

`resolve_current_hgk` ratchets the local HGK forward until it matches the current
committed HGK, bounding the loop by a counter read from storage:

```rust
// retention/src/simple_line2/space_key.rs:153-175
let dgk_next = load_dgk_next(reader).await?;   // read from storage, NOT proof-constrained
let max_steps = dgk_next as usize + 1;
for _ in 0..max_steps {
    key = derivation.derive(&key, tag(HGK_DERIVE_TAG));   // Poseidon2 derive
    if derivation.commit(&key) == target {                // + Poseidon2 commit
        return Ok(key);
    }
}
Err(KeyManagerError)
```

`dgk_next` (`sl2/dgk/next`) is not constrained by the reduce/delete-keys STARK: the
verification input collector reads it only to locate row `dgk_next − 1` and never checks
`dgk_next == previous + 1` (`space_key.rs:566-628`). A malicious member can therefore
submit a `reduce` whose proof verifies while setting `dgk_next` to an arbitrary value
(e.g. `1_000_000_000`), plus a single genuine DGK row at `dgk_next − 1`.

## Exploit / failure scenario

1. Malicious member performs a `reduce`, setting `sl2/dgk/next = 10^9` with one valid DGK
   commitment row at index `10^9 − 1`. The STARK still verifies (it only constrains the
   ratchet/survivor slice, not the counter).
2. Any other member whose local HGK does not immediately match the current commitment —
   e.g. a client catching up after a missed rekey, or on a non-matching branch — calls
   `resolve_current_hgk`, which now grinds through up to `10^9` Poseidon2 derive+commit
   iterations before returning `Err`.
3. Key resolution (needed for reads and further group operations) stalls for a very long
   time per attempt, Space-wide, at the cost of a single authenticated `reduce`. The
   early-exit at line 161 spares clients that are already current, so the grind targets
   exactly the clients trying to recover — the worst time to be denied.

## Related (same file, lower severity)

- `validate_storage_shape` — the full structural-invariant check (monotone FGK
  `d_start`, contiguous D seqs, chain tiling, tail consistency) — is `#[cfg(test)]` only
  (`space_key.rs:236`). No read path enforces it at runtime, so malformed server-supplied
  retention tables surface as `Err`/DoS (node lookup misses → `KeyManagerError`) rather
  than being rejected early. This does not enable reading deleted data (the per-key
  commitment checks in `resolve_d_key` / `resolve_current_hgk` still bind returned keys),
  but it is an availability-hardening gap that compounds the unbounded-loop issue above.

## Recommended fix

- Constrain `dgk_next` in reduce/delete-keys verification: require
  `dgk_next == previous_dgk_next + 1` (it advances by exactly one per delete-keys), and/or
  hard-cap `max_steps` in `resolve_current_hgk` by a value derived from proven state
  rather than a raw stored counter.
- Promote `validate_storage_shape` to a runtime check on the retention read path (or fold
  its invariants into the transition proofs).
