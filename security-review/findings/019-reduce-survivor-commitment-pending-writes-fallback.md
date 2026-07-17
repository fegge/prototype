# Finding 019 — Reduce verification reads the survivor D-head commitment from `pending_writes` first (possible live boundary-key substitution)

- **Severity:** Low (does not expose deleted data; bounded to the live boundary key, and
  full exploitability is contingent — see caveat)
- **Component:** `retention/src/simple_line2/space_key.rs`
- **Status:** Confirmed code pattern; exploitability contingent on the Reduce op
  verifier's accepted `_retention` write set (not fully confirmed)

## Description

When rebuilding reduce public inputs, the survivor's D-head commitment is read
**preferentially from `pending_writes`** (the operation's own new rows), falling back to
`pre_state` only if absent:

```rust
// retention/src/simple_line2/space_key.rs:604-613
let effective_start = range_start.max(d_min_new);
let d_row = match load_d_row(pending_writes, effective_start).await {
    Ok(row) => row,                                   // <-- op-supplied value wins
    Err(_) => load_d_row(pre_state, effective_start).await?,
};
survivors.push(DeleteKeysSurvivor {
    d_head_seq: effective_start,
    d_head_commitment: d_row.commitment,              // fed into the STARK as a public input
});
```

A `reduce` legitimately writes **no** D rows (it advances `d_min` and rewrites GBCT/DGK
state), so under honest operation `load_d_row(pending_writes, …)` should always miss and
fall through to the canonical `pre_state`. The pending-writes-first order therefore only
matters when the operation bundles a **spurious** `sl2/d/row/{effective_start}/commitment`
write — which a malicious reducer controls. If accepted, the survivor's D-head commitment
becomes an attacker-chosen value that the reducer then proves consistency against (it also
builds the ciphertexts and the STARK), letting it substitute the live boundary node's key
with one it knows.

Contrast the neighboring reads (`old_hgk_commitment`, `fgk_next`, `d_min_old`, `next_d`)
which come from `pre_state` (canonical, signed) — only the survivor commitment and the
DGK/GBCT rows (legitimately written by reduce) come from `pending_writes`.

Impact is limited to the **live boundary key**: it can corrupt or hijack the boundary
node's current key as seen by honest members. It does **not** expose pre-cutoff (deleted)
data — that protection is the one-way ratchet and the absence of old keys, independent of
this value.

**Caveat / contingency:** full exploitability depends on whether the `Reduce` changelog-op
verifier (in `changelog_core`) accepts an arbitrary extra `sl2/d/row/.../commitment`
`_retention` write in the signed entry. If that write is rejected as not part of a
well-formed reduce, the fallback is never reachable with attacker data. This was not
fully confirmed; the finding documents the asymmetric read pattern and its worst case.

## Recommended fix

- Read the survivor D-head commitment from `pre_state` only (it is pre-existing canonical
  state that reduce does not rewrite), removing the `pending_writes`-first fallback for
  this value.
- Independently, have the `Reduce` op verifier reject any `_retention` write outside the
  exact set a reduce is defined to produce (DGK row, GBCT rewrites, `d_min` bump), so no
  spurious D-row commitment can be smuggled in.
