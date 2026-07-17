# Finding 006 — Group-key recovery path installs a key without the canonical-commitment check its sibling performs (stale-epoch rollback / PCS)

- **Severity:** Medium (defense-in-depth gap). Not a clean break today — KEM hardness
  stops a malicious server forging a fresh key, and an incidental range-check on the
  backward chain walk probabilistically catches a stale key — but the explicit binding
  that would robustly prevent an epoch rollback is simply absent on this path.
- **Component:** `key_manager/src/no_retention.rs`
- **Status:** Confirmed by code inspection

## Description

Two code paths install a delivered group key. They are asymmetric in how they bind the
installed key to authenticated (signed) state.

The **apply** path cross-checks the delivered key against the canonical commitment stored
in the (signed) changelog/retention state:

```rust
// key_manager/src/no_retention.rs:142-162
async fn apply_new_group_key(&mut self, new_group_key, commitment, builder) -> ... {
    let new_id = current_id(builder).await?;
    let stored = builder.get(&commitment_key(&SimpleKeyId(new_id))).await?.ok_or(KeyManagerError)?;
    if stored != commitment.as_bytes() {   // <-- binds to canonical committed value
        return Err(KeyManagerError);
    }
    self.keys.insert(SimpleKeyId(new_id), new_group_key.clone());
    self.root_key = new_group_key;
    Ok(())
}
```

The **recovery** path (used when a client detects it missed a rekey, i.e. after a
`RemoveUser`) installs the candidate key with **no canonical-commitment check at all**:

```rust
// key_manager/src/no_retention.rs:202-217
async fn recover_group_key_from_candidate(&mut self, candidate, builder) -> ... {
    let root_id = current_id(builder).await?;
    self.root_key = candidate.clone();               // <-- installed unchecked
    self.keys.clear();
    self.keys.insert(SimpleKeyId(root_id), candidate);
    for target in (0..root_id).rev() {               // backward chain walk
        let key = resolve_key_from_chain(&self.root_key, root_id, target, builder).await?;
        self.keys.insert(SimpleKeyId(target), key);
    }
    Ok(())
}
```

The only checks in force on this path are:

1. The envelope's own `binding_commitment` check in `decrypt_group_key_envelope` — but
   that commitment is supplied *in the envelope* (server-controlled), so it is circular
   on its own; it proves the ciphertext decrypts to a preimage of *whatever* commitment
   accompanied it, not to the group's canonical current key.
2. The backward chain walk `resolve_key_from_chain` (`no_retention.rs:300-324`), which
   decrypts `ekey/{id}` with the key at `id+1`. This walk **does not compare any
   recovered key to its stored commitment** — `decrypt_stored_key` only calls
   `KeyMaterial::from_bytes`, a canonical-range check (`no_retention.rs:288-295`).

## Exploit / failure scenario

- **What is prevented incidentally.** A malicious server cannot *forge a fresh* key: to
  pass even the circular envelope check, `commit(decaps(sk, ct) − response)` must equal
  `binding_commitment`, and the server cannot steer `decaps(sk, ct)` without the
  recipient's secret key. So arbitrary-key injection is blocked by KEM hardness, not by
  this function.
- **What is not robustly prevented — epoch rollback.** A malicious server can **replay a
  previous epoch's honestly-generated delivery envelope** while reporting the newer
  `current_id`. That old envelope is internally consistent and the recipient can decrypt
  it to the *old* group key. Because the recovery path never checks the installed key
  against `commitment_key(current_id)`, the recipient would install a **stale** key as
  current. The stale key may be one a **removed member still knows** — precisely the key
  the rekey after `RemoveUser` was meant to retire — so post-removal data the victim now
  encrypts under this "current" key becomes readable by the removed member, breaking the
  post-compromise-security intent of removal. Today this is caught only probabilistically
  by the backward walk: decrypting `ekey/{root_id−1}` with the wrong (old) key yields
  bytes that usually (~99.6% per step) fail the `KeyMaterial::from_bytes` range check.
  That is an incidental side effect, not a designed integrity check, and it is not a
  guarantee.

## Recommended fix

- Add the same explicit canonical-commitment check `apply_new_group_key` performs to
  `recover_group_key_from_candidate`: after computing the candidate, require
  `derivation.commit(&candidate) == canonical_group_key_commitment(builder)` (the value
  at `commitment_key(current_id)`), and reject otherwise.
- Additionally, verify each backward-walked historic key against its stored
  `commitment_key(id)` inside `resolve_key_from_chain`, so chain reconstruction is
  authenticated rather than relying on the field-range check to reject wrong keys.
- Add an epoch/key-id field to `GkDeliveryEnvelope` and check it against `current_id` so
  a replayed older envelope is rejected up front (see also Finding 005/mVE envelope
  binding notes).
