# Finding 013 — `parent_clc` is never verified on the apply path; independent users' changes can be reordered

- **Severity:** Medium (verifiable-history / ordering integrity; transient — detected at
  the next fast-forward)
- **Component:** `sdk/src/changelog.rs` (`validate_and_apply_change` / `apply_state_update`)
- **Status:** Confirmed by code inspection

## Description

Each signed `ChangelogEntry` carries `parent_clc`, the changelog-commitment root the
author built the change against (set at build/re-anchor time,
`reanchor_and_resign`, `changelog.rs:1770-1779`), and it is covered by the signature.
This field is the cryptographic pin of *where in history* the change was authored. The
client, however, **never compares an incoming change's `parent_clc` to its own
`current_clc_state.root`**. A grep of `sdk/src` shows `parent_clc` is only ever *written*
(the client's own re-anchoring at `changelog.rs:1779`) or default-constructed in tests —
never read/validated on the receive path.

Ordering on the apply path is therefore pinned only by:

- **per-user `sig_ref`** (`check_sigref_continuity`, `changelog.rs:1466`) — orders each
  user's *own* entries and blocks same-user replay; and
- **data continuity** `response.old_root == current_data_commitment`
  (`changelog.rs:1437`) — ensures each change applies to the running tree.

Neither pins the **relative order of *different* users' changes**. Because the
`ChangeResponse` roots are server-supplied and unsigned, a malicious server can construct
a valid proof chain for an alternate interleaving of independent users' entries: each
genuine signed entry applied to the running DC in an order different from the authentic
one. The `old_root` check still passes (each step chains to the previous `new_root`), and
each per-user `sig_ref` still lines up.

## Exploit / failure scenario

1. Authentic history: Bob writes `key=K, val=b` (change N), then Alice writes `key=K,
   val=a` (change N+1). Last-writer-wins ⇒ current value is `a`.
2. The malicious server delivers Alice's genuine entry first (proof: applied to DC before
   Bob's, `old_root = DC_{N-1}`), then Bob's genuine entry (applied on top). Both entries
   are validly signed; Alice's `sig_ref` points at her own prior change and Bob's at his,
   so `check_sigref_continuity` passes for both; each `old_root` chains correctly.
3. The client accepts the reversed interleaving and computes current `key=K` as `b`
   instead of `a` — a stale/incorrect value presented as authoritative, in contradiction
   to what actually happened. Had the client checked `parent_clc`, Alice's entry
   (authored against a CLC that already included Bob's change) would not match the CLC the
   server is trying to apply it onto, and the reorder would be rejected.

The divergence is eventually caught at the next fast-forward (the authentic CLC chain
differs, surfacing as branch-continuity failure / `StateDiverged`), so the window is
transient — but its duration is attacker-controlled, and application decisions made on the
reordered state in the meantime are not undone.

## Recommended fix

- On the apply path (single-change, broadcast, and ragged-FF), verify that each incoming
  change's signed `parent_clc` equals the client's `current_clc_state.root` at the point
  it is applied (captured atomically with `current_change_id`, as the reanchor logic
  already does for the client's own changes). Reject on mismatch.
- This makes the per-entry position cryptographically enforced rather than relying on the
  next FF to retroactively detect divergence.
