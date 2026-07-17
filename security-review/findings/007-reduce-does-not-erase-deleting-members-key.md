# Finding 007 — `reduce()` (selective deletion) never ratchets/erases the deleting member's own key; "deletion" is reversible for any key-holder

- **Severity:** High (for the selective-retention guarantee) — the operation that is
  supposed to *be* cryptographic key erasure performs no local erasure.
- **Component:** `retention/src/simple_line2/space_key.rs`
- **Status:** Confirmed by code inspection

## Description

`SimpleLine2SpaceKey::reduce` deletes data before a cutoff by ratcheting the head group
key (HGK) forward one-way and re-encrypting surviving nodes' key material under fresh
keys, so that no *post-reduce* key can derive the pre-cutoff data keys. But `reduce`
**never advances or zeroizes the caller's local HGK**:

```rust
// retention/src/simple_line2/space_key.rs:830-918 (abridged)
pub async fn reduce(&mut self, before: &SimpleKeyId, builder: &mut dyn OperationBuilder)
    -> Result<(), KeyManagerError>
{
    let old_hgk = resolve_current_hgk(&self.hgk, builder).await?;   // pre-reduce master
    let new_hgk = derivation.derive(&old_hgk, tag(HGK_DERIVE_TAG));  // one-way ratchet
    ... build/prove/persist new ciphertexts ...
    Ok(())
    // NOTE: self.hgk is never reassigned.
}
```

Every sibling mutation *does* advance `self.hgk`: `apply_new_group_key`
(`space_key.rs:825`), `produce_group_key` (`:955`), `sync_group_key` (`:1002`),
`recover_group_key_from_candidate` (`:1015`). Only `reduce` leaves it at its pre-reduce
value. Because `self.hgk` sits at or before `old_hgk` on the forward derive chain,
`resolve_current_hgk(&self.hgk)` still walks *through* `old_hgk` to reach the new head —
so after a "deletion" the member can still trivially recompute `old_hgk` and, from it,
every supposedly-deleted D key (the pre-cutoff `d_head` ciphertexts and GB chain-links
are still present; see below).

`KeyMaterial` is `#[zeroize(drop)]` (`crypto/src/key_material.rs:21`), so the design
clearly intends old key material to be destroyed once no longer reachable. `reduce`
defeats that: the pre-reduce key stays reachable from `self.hgk`, so it is never dropped
or zeroized.

Compounding this, deletion never destroys ciphertext bytes. The GBCT/D "overwrites" in
`write_reduce_to_storage` are `_retention` **appends** (`sdk/src/changelog.rs` retention
append + "highest-id row is most recent", `sdk/src/retention.rs:56-79`), and the
changelog is append-only and replicated to every client. Superseded pre-reduce
ciphertexts remain in history. So the *only* thing standing between a key-holder and the
"deleted" plaintext is whether their key material was actually erased — which, per above,
it is not.

## Exploit / failure scenario

1. A member calls `space.reduce(before)` (or the app's delete action) intending to
   destroy all data before the cutoff. `reduce` succeeds and the STARK proof attests the
   ratchet was performed honestly.
2. `self.hgk` is unchanged. The member's device still holds a key from which `old_hgk`
   — and therefore every deleted D key — is derivable. Nothing in `reduce` triggers the
   `sync_group_key` ratchet that would move `self.hgk` to `new_hgk`; that is left to some
   later, unguaranteed call.
3. Result: on that member's own device, the "deleted" data is still fully recoverable.
   A device seizure, forensic image, backup, or subpoena *after* the deletion still
   yields the data the user believed was cryptographically erased. Any member who
   performs (or ever held the HGK before) the reduce and simply never ratchets retains
   permanent read access to the deleted data, using the persisted-but-shadowed
   ciphertexts.

This breaks the meaningful sense of "selectively delete data ... without re-encrypting
the entire Space": deletion is realized only against parties who *never held* a
pre-reduce HGK (future joiners) and the server — not as erasure from the deleter or any
current key-holder. For a feature whose purpose is deletion, the deleter's own copy
surviving is the sharp edge.

## Recommended fix

- In `reduce`, after proving/persisting, set `self.hgk = new_hgk` and let the previous
  value drop (and thus zeroize), mirroring `produce_group_key` / `apply_new_group_key`.
  Ensure no local variable keeps `old_hgk` alive past the point it is needed.
- If a two-phase "reduce then sync" is genuinely intended, make the erasure explicit and
  synchronous within `reduce` anyway — a deletion primitive must not depend on a
  later, optional call to actually erase the key.
- For true erasure against former members, additionally prune superseded
  `_retention`/changelog history for the deleted range (documented as out of scope
  today), since one-way ratcheting only helps parties who never held the old key.
- Add a test asserting that after `reduce(before)`, the same `SpaceKey` can no longer
  resolve any D key with `seq < before` (i.e. `resolve_d_key` errors), proving local
  erasure actually happened.
