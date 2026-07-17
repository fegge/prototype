# Finding 008 — CRITICAL: fast-forward ragged tail does not bind each change's `old_root` to the client's data commitment (arbitrary state substitution)

- **Severity:** Critical — breaks the central "verifiable database" integrity guarantee.
  A malicious server can make an honest client adopt an **arbitrary, forged data
  commitment** while riding genuine user signatures, then serve attacker-chosen rows for
  every subsequent `SELECT`.
- **Component:** `sdk/src/changelog.rs` (`apply_fast_forward_from_anchor` ragged-tail
  loop + `apply_state_update`)
- **Status:** Confirmed by code inspection

## Description

The single-change apply path binds each response to the client's current data commitment
(DC):

```rust
// sdk/src/changelog.rs:1437 (validate_and_apply_change)
if response.old_root != current_data_commitment {
    return Err(SdkError::FastForwardRequired { .. });   // chain-continuity: base case + step
}
```

The fast-forward **ragged-tail** loop does not. Each ragged change is verified only for
*internal self-consistency* of server-supplied roots and then applied:

```rust
// sdk/src/changelog.rs:2339 (ragged loop)
let writes = ChangeLog::verify_proof_and_validate(
    change,
    &response.pruned_merkle_tree,   // server-supplied
    &response.old_root,             // server-supplied
    &response.new_root,             // server-supplied
    next_change_id,
)?;                                 // only proves: pruned_tree hashes to old_root,
                                    // and applying `change` to it yields new_root
...
self.apply_state_update(change, response, current_change_id, ...)?;
```

```rust
// sdk/src/changelog.rs:1505-1529 (apply_state_update)
self.with_state_mut(|state| {
    if state.current_change_id != current_change_id { return; }         // CAS on change_id
    if response.change_id != current_change_id + 1 { return; }          // sequencing
    state.current_data_commitment = response.new_root;                  // <-- NO old_root check
    state.current_change_id = current_change_id + 1;
    ...
    state.current_clc_state.append(&entry_bytes);
});
```

There is **no** `response.old_root == state.current_data_commitment` check anywhere in the
ragged path. The *first* ragged change is pinned to the proven `end_dc`
(`changelog.rs:2158`, inside the proof block), but changes `[1..]` are not chained to the
preceding change's `new_root`. And in the supported **`proof: None` + non-empty changes**
mode (comment at `changelog.rs:2389-2394`), the entire proof block — including the
`first_old_root != end_dc` pin — is skipped, so even the first ragged change is unbound.

The ragged entries themselves are genuine signed entries (their signatures are re-checked
at `changelog.rs:2409`), but the signature covers only the *entry* (op, kvs, `parent_clc`,
`sig_ref`, `uid`) — **never the `ChangeResponse` roots or the pruned tree**, which are
unauthenticated server data.

## Exploit / failure scenario

Malicious server, honest client fast-forwarding:

1. The server serves a valid FF proof to some `end_dc` (or uses `proof: None`). The first
   ragged change `E0` is (in proof mode) correctly anchored to the real `end_dc`.
2. For the next ragged change `E1`, the server takes a **genuine signed entry** authored
   by some member (e.g. Alice's real `insert key=K, val=v`, whose `sig_ref` chains
   correctly so `check_sigref_continuity` passes) and pairs it with a **forged
   `ChangeResponse`**: `old_root = X`, where `X` is a data tree the attacker constructs
   containing arbitrary forged rows for keys Alice's entry never touches; a
   `pruned_merkle_tree` that hashes to `X`; and `new_root = R` = applying Alice's writes
   to `X`.
3. `verify_proof_and_validate` passes (the pruned tree does hash to `X`, and applying `E1`
   to it does yield `R` — all self-consistent). `apply_state_update` sets
   `current_data_commitment = R` with no check that `X` equals `E0`'s `new_root`.
4. The client now trusts `R` — a tree of the server's choosing — as its authenticated
   data commitment. Every later `SELECT` verifies rows against `R`
   (`verify_query_proof_*`), so the server returns **forged rows** (fake membership,
   fake ACL rules, fake application data) that verify perfectly.
5. Deferred signature verification (`changelog.rs:2409`) resolves signing keys from
   `_users`/`_key_history` **read against the forged `R`** and checks the genuine `E1`
   signature — both pass. `verify_fast_forward_server_head` (`:2440`) compares only
   against the server-supplied head. Nothing detects the substitution.

The forged rows can include `_users` entries (fabricated members/keys), `_access_control`
rules, and any application table. Because the FF guest and query verifier are the client's
sole integrity boundary, this is a full break of "clients verify every server response":
the data commitment is no longer chained to previously verified state.

The only eventual backstop is a future *from-genesis* FF proof, which the malicious server
controls and can withhold indefinitely; and even then it yields a terminal `StateDiverged`
error, not silent correction — after the client has already acted on forged data.

## Recommended fix

- In the ragged-tail loop, **before** applying each change, enforce
  `response.old_root == state.current_data_commitment` (read atomically with
  `current_change_id`), exactly as the single-change path does at `changelog.rs:1437`.
  Equivalently, add the check inside `apply_state_update` so every one of the three
  callers (sequential, broadcast, ragged-FF) is covered.
- Reject `proof: None` together with a non-empty `changes` vector unless the first
  change's `old_root` is bound to a trusted commitment (the client's current DC), and
  chain every subsequent change to the prior `new_root`.
- Add a regression test: an FF whose ragged change `[1]` carries `old_root != changes[0].new_root`
  must be rejected; and a forged `old_root` on any ragged change must not change the
  client's committed state.
