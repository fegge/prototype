# Encrypted Spaces — Critical & High Severity Findings

Consolidated report of the Critical- and High-severity issues from the security review.
Each section is self-contained: it explains the vulnerability, gives a concrete
exploit/failure scenario, and recommends a fix. Per-finding files (including all
Medium/Low findings and the verified-safe analysis) live alongside this report in
`security-review/findings/` and are indexed in `security-review/README.md`.

## Background needed to read this report

Encrypted Spaces is a framework for collaborative apps over an **untrusted server**. The
server stores only ciphertexts and proof material and relays messages; it is assumed
hostile. Security rests entirely on each client **verifying every server response
locally** against cryptographic commitments it maintains:

- **Changelog** — an append-only, hash-chained log of signed operations
  (`ChangelogEntry`). Its running hash is the **changelog commitment (CLC)**.
- **Verifiable database** — current state as a Merkle-ized key/value store; its root is
  the **data commitment (DC)**. Each accepted change carries a Merkle proof that it
  transforms the previous DC into the new DC.
- **Members** are tracked in an internal `_users` table (their signing/verification keys
  and KEM public keys live there). Per-table **access-control rules** and schema-declared
  **actions** constrain who may write what.
- **Fast-forward (FF) proofs** — succinct RISC Zero zkVM proofs that let a client skip
  ahead in the changelog without replaying every operation. The client trusts a
  build-time-pinned guest image ID.
- **Group key distribution** uses **multi-recipient verifiable encryption (mVE)**; a
  removed member triggers a **rekey**; selective deletion (**reduce**) ratchets keys
  one-way so future members and the server cannot read deleted data.

The client verifier (shared with the FF zkVM guest as `changelog_core`) is therefore the
**sole integrity boundary**. Several findings below are gaps in that boundary.

## Severity summary

| # | Severity | Title |
|---|----------|-------|
| 008 | **Critical** | Fast-forward ragged tail doesn't bind `old_root` to the client's data commitment → arbitrary state substitution |
| 014 | High (Critical w/ real-proofs) | FF recursion verifies the prior chunk against an unconstrained, input-supplied image ID → forgeable proof chain |
| 004 | High | Action `self.*` context is attacker-forged for Delete/Update legs → assertion bypass + ACL-free cascade delete |
| 007 | High | `reduce()` never erases the deleting member's own key → deletion is reversible |
| 010 | High | Joining client has no genesis root of trust → the server can fabricate an entire Space |
| 003 | High | Malformed member `update_key` panics every rekey/invite → insider denial of service |
| 017 | High | Unauthenticated stack-overflow crash via unbounded `StoredValue` postcard recursion (pre-auth) |

---

## 008 — CRITICAL: Fast-forward ragged tail doesn't bind `old_root` to the client's data commitment

**Component:** `sdk/src/changelog.rs` (`apply_fast_forward_from_anchor`, `apply_state_update`)
**Guarantee broken:** verifiable database / integrity.

### What's wrong

Every accepted change carries a `ChangeResponse` with `old_root`, `new_root`, and a pruned
Merkle proof. Integrity of the chain depends on checking that each change applies to the
state the client currently holds, i.e. `response.old_root == current_data_commitment`.

On the **single-change** path this check exists:

```rust
// sdk/src/changelog.rs:1437
if response.old_root != current_data_commitment {
    return Err(SdkError::FastForwardRequired { .. });
}
```

But a fast-forward response can also carry a **"ragged tail"** of changes appended after
the last FF proof, and those are applied through a different loop that **omits the
check**. The per-change work is only a *self-consistency* check of server-supplied roots:

```rust
// sdk/src/changelog.rs:2339 (ragged-tail loop)
let writes = ChangeLog::verify_proof_and_validate(
    change,
    &response.pruned_merkle_tree, // server-supplied
    &response.old_root,           // server-supplied — never compared to current DC
    &response.new_root,           // server-supplied
    next_change_id,
)?;
self.apply_state_update(change, response, ...)?; // commits new_root as the DC
```

and `apply_state_update` blindly adopts the new root:

```rust
// sdk/src/changelog.rs:1505-1529
if state.current_change_id != current_change_id { return; } // CAS on change_id
if response.change_id != current_change_id + 1 { return; }  // sequencing
state.current_data_commitment = response.new_root;          // <-- no old_root binding
...
state.current_clc_state.append(&entry_bytes);
```

The first ragged change is pinned to the proven `end_dc` (`changelog.rs:2158`) **only in
proof mode**, and changes after the first are never chained to the previous `new_root`. In
the supported `proof: None` + non-empty-changes mode (`changelog.rs:2389-2394`) even the
first ragged change is unbound. The ragged entries are genuinely signed, but the signature
covers only the entry — **never the `ChangeResponse` roots or the pruned tree**, which are
unauthenticated server data.

### Exploit / failure scenario

A malicious server, serving a client that fast-forwards:

1. Serve a valid FF proof to some `end_dc` (or use `proof: None`). The first ragged change
   is correctly anchored.
2. For the next ragged change, take a **genuine signed entry** from any member (e.g.
   Alice's real `insert key=K`, whose `sig_ref` chains correctly) and pair it with a
   **forged `ChangeResponse`**: `old_root = X` where `X` is an attacker-built tree
   containing arbitrary forged rows; a `pruned_merkle_tree` that hashes to `X`; and
   `new_root = R` = Alice's writes applied to `X`.
3. `verify_proof_and_validate` passes (everything is internally consistent), and
   `apply_state_update` sets `current_data_commitment = R` — never noticing that `X` is not
   the previous change's `new_root`.
4. The client now trusts `R`, a tree of the server's choosing, as authenticated state.
   Every later `SELECT` verifies against `R` and returns **forged rows** — fabricated
   `_users` (members/keys), `_access_control` rules, or application data — all of which
   verify perfectly. Deferred signature checks resolve keys from the forged `_users` and
   pass; the server-head cross-check compares only against server-supplied values.

The only eventual backstop is a future *from-genesis* FF proof, which the malicious server
controls and can withhold; even then it surfaces as a terminal error after the client has
acted on forged data.

### Fix

- In the ragged-tail loop, enforce `response.old_root == current_data_commitment` (read
  atomically with `current_change_id`) before applying each change — the same check the
  single-change path performs at `changelog.rs:1437`. Best placed **inside**
  `apply_state_update` so all three callers (sequential, broadcast, ragged-FF) are
  covered (this also closes finding 012).
- Reject `proof: None` with a non-empty `changes` vector unless the first change's
  `old_root` is bound to the client's current DC, and chain every subsequent change to the
  prior `new_root`.
- Add regression tests: a ragged change whose `old_root != previous new_root` must be
  rejected.

---

## 014 — HIGH (Critical with real proofs): FF recursion verifies the prior chunk against an unconstrained, input-supplied image ID

**Component:** `ffproof/methods/guest/src/bin/extend_ff.rs`, `ffproof/src/verifier.rs`
**Guarantee broken:** verifiable history / fast-forward soundness.
Masked in default builds (dev-mode receipts are already non-cryptographic); becomes live —
and Critical — for any deployment relying on real FF proofs (`--features real-proofs`).

### What's wrong

FF proofs are chainable: each chunk's zkVM guest recursively verifies the previous chunk's
receipt. The recursion image ID is **read from untrusted guest input and used
unconstrained**:

```rust
// ffproof/methods/guest/src/bin/extend_ff.rs:12-27
if !is_first {
    ...
    let mut PROGRAM_ID = [0u32; 8];
    env::read_slice(&mut PROGRAM_ID);          // attacker-supplied
    let inputs = &serde::to_vec(&previous_io).unwrap();
    env::verify(PROGRAM_ID, inputs).unwrap();  // verify prior receipt under ANY id
}
```

`PROGRAM_ID` is not hardcoded to the honest guest's own image ID, not compared to any
trusted constant, and not committed to the journal (`FastForwardRange` has no program-id
field). The verifier only pins the **outer** receipt:

```rust
// ffproof/src/verifier.rs:57-66
let extend_ff_id: Risc0Digest = expected_image_id.into(); // pinned FF_GUEST_IMAGE_ID
if proof.receipt.verify(extend_ff_id).is_err() { return false; }
let io: FastForwardRange = proof.receipt.journal.decode()?; // no program id inside
```

So the client is assured only that the *outermost* execution ran the pinned guest. That
guest will recursively accept a prior receipt from **any program the prover names**,
because RISC Zero composition only requires the prover to actually possess a valid receipt
for `(PROGRAM_ID, journal)` — which a malicious prover trivially has for a guest they
wrote.

### Exploit / failure scenario

A malicious prover (e.g. a compromised server operator with proving capability):

1. Writes a trivial guest `G'` that reads a `FastForwardRange` from input and `commit`s it
   verbatim, performing **no** changelog verification. They prove `G'` once, getting a
   valid receipt `R'` whose journal is an arbitrary **forged** range: `start = genesis`
   (to satisfy the client's genesis checks), `end = (D*, C*)` chosen by the attacker,
   arbitrary `sigref_map`.
2. Runs the honest, pinned `extend_ff` guest for a final chunk with `is_first = false`,
   feeding `previous_io = <forged range>`, `PROGRAM_ID = image_id(G')`, and a small set of
   genuine entries that validly chain from `D*/C*`.
3. `env::verify(image_id(G'), …)` succeeds (R' discharges the assumption), the continuity
   asserts pass, and the final chunk verifies honestly. The outer receipt verifies against
   the pinned `FF_GUEST_IMAGE_ID`.
4. The client accepts a `VerifiedFfOutput` whose `[0, end)` range is "proven from genesis"
   — but the entire prefix `[0, D*/C*)` was never verified by any honest guest. The
   attacker has forged arbitrary history (membership, ACL, data) for that prefix, capped
   with a small genuine tail. The whole point of the succinct proof — that the range is a
   valid rule-following evolution from genesis — is defeated.

### Fix

- Constrain the recursion image ID **in-circuit**: the guest must verify the previous
  chunk against a fixed, trusted image ID equal to its own, not an input value. Either
  commit the assumed `PROGRAM_ID` into the journal and have `verify_ff` enforce
  `journal.program_id == expected_image_id` (uniform self-recursion), or bake the trusted
  recursion image ID into the guest as a constant and assert `PROGRAM_ID == THAT_CONSTANT`
  before `env::verify`.
- Until fixed, treat the pre-final-chunk prefix of any FF output as unauthenticated; do
  not rely on FF succinctness for security.
- Add a negative test: a proof whose inner `PROGRAM_ID` differs from the pinned guest ID
  must fail verification.

---

## 004 — HIGH: Action `self.*` context is attacker-forged for Delete/Update legs

**Component:** `ffproof/changelog_core/src/ops/action_op.rs` (with `delete_op.rs`)
**Guarantee broken:** cryptographically-enforced access control. The FF guest runs the
same `changelog_core` code, so fast-forwarded clients accept the forged operation too.

### What's wrong

Actions are schema-declared operations with `assert` predicates and one or more legs
(insert/update/delete/cascade_delete). Assertions and cascade foreign-key selection
evaluate against a `self.*` row context that the verifier builds from the **values of the
primary leg's key/value pairs in the signed entry**:

```rust
// ffproof/changelog_core/src/ops/action_op.rs:145-147
let primary_kvs = &per_leg_kvs[0];
let self_row = self_row_from_leg_kvs(primary_kvs);          // reads kv.value bytes
evaluate_action_asserts(&action_name, &action.asserts, &self_row, entry.uid, reader)?;
```

```rust
// action_op.rs:269-292 (abridged)
if let Ok(value) = bytes_to_value(&kv.value) {             // value from the signed entry
    if let Some(i) = value.as_i64() { out.insert(column, i); }
}
// only `self.id` is taken from the authenticated column KEY, not the value.
```

This is sound only for an **Insert** primary leg (there `InsertOp` validates the values
against schema and write-ACL). For a **Delete** primary leg it is not: `DeleteOp`
(`delete_op.rs:15-95`) decides what to delete from the column **keys** only and reads the
*stored* values from the tree for ACL — it **never inspects or constrains `kv.value`** and
never requires it to be empty. So a malicious member can put **arbitrary values** in a
delete leg's kvs, and every `self.<col>` other than `id` becomes attacker-chosen. That
forged `self_row` then drives (1) action assertions and (2) cascade-delete FK selection,
where the cross-table cascade path has **no `where_self_column == "id"` guard**
(`action_op.rs:421-473`).

### Exploit / failure scenario

Both require an app schema that declares an action of the relevant shape (attackers can't
define actions, but both shapes are ordinary, documented usage):

- **Assertion bypass.** An action `delete_post { assert "self.author_id == auth.user_id"; delete }`
  with no redundant per-row `allow delete` rule. Attacker (uid 99) deletes a victim's post
  (the row key names the victim's row) and stuffs the `author_id` kv value with `99`.
  `self.author_id` resolves to 99, `99 == 99` passes, the delete succeeds — "only the
  author may delete" is broken.
- **ACL-free cascade to arbitrary rows (privilege escalation).** An action
  `delete_folder { delete; cascade_delete table="documents" where="row.folder_id == self.folder_id" }`.
  The attacker deletes a folder they legitimately own (primary-leg ACL passes against the
  stored owner) but sets the forged `self.folder_id` to a **victim's** folder id. The
  cascade reads the `documents` index for that victim id and deletes **every** document in
  it, with no per-row ACL. "Delete my own folder" escalates to "delete any user's
  documents."

In both cases the entry is validly signed by the attacker, passes the verifier, mutates
the authenticated DC, and is accepted by fast-forwarding clients too. `exists(...)` gates
inside assertions are weakened the same way.

### Fix

- For non-Insert primary legs, build `self.<col>` from **authenticated stored state**
  (read the primary row from the tree, as `DeleteOp` already does for its ACL), not from
  the signed entry's kv values.
- Restrict cross-table `CascadeDelete.where_self_column` to `"id"` (or a stored,
  ACL-covered value), mirroring the same-table path's existing guard.
- Optionally reject non-empty `kv.value` on delete-leg kvs.
- Add regression tests for a delete-primary action gated only by `assert "self.<col> == auth.user_id"`
  and for a non-`id` cross-table cascade.

---

## 007 — HIGH: `reduce()` never erases the deleting member's own key; deletion is reversible

**Component:** `retention/src/simple_line2/space_key.rs`
**Guarantee broken:** selective data retention (cryptographic deletion).

### What's wrong

Selective deletion (`reduce`) is supposed to be **cryptographic key erasure**: ratchet the
head group key (HGK) forward one-way and re-encrypt survivors so no post-reduce key can
derive the pre-cutoff data keys. But `reduce` **never advances or zeroizes the caller's
own HGK**:

```rust
// retention/src/simple_line2/space_key.rs:830-918 (abridged)
pub async fn reduce(&mut self, before: &SimpleKeyId, builder: ...) -> ... {
    let old_hgk = resolve_current_hgk(&self.hgk, builder).await?; // pre-reduce master
    let new_hgk = derivation.derive(&old_hgk, tag(HGK_DERIVE_TAG));
    ... build / prove / persist ...
    Ok(())
    // self.hgk is never reassigned.
}
```

Every sibling mutation *does* advance `self.hgk` (`apply_new_group_key` `:825`,
`produce_group_key` `:955`, `sync_group_key` `:1002`). Because `self.hgk` sits at or before
`old_hgk` on the forward derive chain, `resolve_current_hgk(&self.hgk)` still walks
*through* `old_hgk`, so the member can trivially recompute it and every "deleted" data key.
`KeyMaterial` is `#[zeroize(drop)]`, so the design intends old key material to be
destroyed — `reduce` keeps it reachable, so it never is. Compounding this, deletion never
destroys ciphertext bytes: the GBCT/D "overwrites" are `_retention` **appends** (the table
keeps all versions and reads the highest-id row), and the changelog is append-only and
replicated. Superseded pre-reduce ciphertexts remain in history.

### Exploit / failure scenario

1. A member calls `reduce(before)` to destroy all data before the cutoff. It succeeds and
   the STARK proof attests the ratchet was performed honestly.
2. `self.hgk` is unchanged; the member's device still holds a key from which `old_hgk` —
   and every deleted D key — is derivable. Nothing in `reduce` triggers the
   `sync_group_key` ratchet that would move `self.hgk` forward.
3. On that member's device the "deleted" data remains fully recoverable: a later device
   seizure, forensic image, backup, or subpoena yields data the user believed was
   cryptographically erased. Any member who performed (or ever held the HGK before) the
   reduce and never ratchets retains permanent read access to the deleted data via the
   persisted-but-shadowed ciphertexts.

Deletion is thus realized only against parties who *never held* a pre-reduce HGK (future
joiners) and the server — not as erasure from the deleter or any current key-holder.

### Fix

- In `reduce`, after proving/persisting, set `self.hgk = new_hgk` and let the previous
  value drop/zeroize (mirroring `produce_group_key`); ensure no local keeps `old_hgk`
  alive past use.
- If a two-phase "reduce then sync" is intended, make erasure synchronous within `reduce`
  anyway — a deletion primitive must not depend on a later, optional call to erase the key.
- For true erasure against former members, additionally prune superseded
  `_retention`/changelog history for the deleted range.
- Add a test asserting that after `reduce(before)`, the same `SpaceKey` can no longer
  resolve any D key with `seq < before`.

---

## 010 — HIGH: A joining client has no genesis root of trust

**Component:** `sdk/src/changelog.rs` (`extract_auth_key_from_create_space_change`),
`sdk/src/lib.rs` (`Space::join`), `sdk/src/users.rs` (`SpaceInvite`)
**Guarantee broken:** verifiable history / authenticity on join.

### What's wrong

The system's premise is that clients need not trust the server because they verify
everything cryptographically. For a **joining** client that verification has no anchor
identifying the genuine Space:

- `CreateSpace` authorship is trust-on-first-use: the verifying key is read from the
  entry's own `_users.auth_key` and checked against that same key
  (`changelog.rs:1114-1153`, `:1332-1352`). Any self-consistent `CreateSpace` verifies.
- The only compiled-in anchors are `initial_dc` and `ff_image_id`, both **per-app
  constants** identical for every Space built from the same schema. The FF check
  `start_dc == initial_dc` (`changelog.rs:2026`) doesn't distinguish one Space from
  another (the chain root has no `space_id` salt).
- `space_id` is `SpaceId::random()`, a routing token never committed into state.
- The group-key delivery envelope is unauthenticated (only a `commit == binding_commitment`
  self-consistency check).
- `SpaceInvite` carries `space_id` and provisional keypairs but **no out-of-band pin** of
  the real creator key or genesis commitment.

Downstream key resolution reads all later signing keys from `_users`/`_key_history`, so if
genesis is forged, every subsequent "authenticity" check is circular against
attacker-populated state.

### Exploit / failure scenario

1. A user is invited and receives a `SpaceInvite` over a trusted out-of-band channel, then
   calls `Space::join` through a malicious server.
2. The server fabricates an entire changelog: a `CreateSpace` naming the attacker's key as
   creator, attacker-authored membership and `_access_control` rows, and a valid FF proof
   over it (the guest happily proves a self-consistent, validly-signed chain rooted at the
   universal `initial_dc`). It delivers a group-key envelope wrapping a server-known key to
   the invitee's provisional update public key (which the server knows).
3. Every local check passes: FF verifies, `start_dc == initial_dc` holds, the envelope is
   self-consistent, key resolution succeeds against the attacker-populated `_users`. The
   victim lands in a **fully attacker-controlled Space** with attacker keys trusted as
   admins and a group key the server knows.
4. The victim cannot read the *real* Space's data (confidentiality holds — they never get
   the real group key), but they now transact in a fake Space whose membership,
   access-control, and history are entirely the server's, believing it is the Space they
   were invited to.

### Fix

- Carry an **out-of-band genesis pin** in `SpaceInvite`: the real creator's public
  identity key and/or the genuine post-genesis data commitment, delivered over the same
  trusted channel as the invite. On join, require the observed `CreateSpace`/FF `start` to
  match that pin.
- Salt the initial commitment with a per-Space identifier so `initial_dc` /
  `initial_clc_state` are not universal constants, and bind `space_id` into genesis.
- Authenticate the group-key delivery envelope against the pinned creator/epoch.

---

## 003 — HIGH: A malformed member `update_key` panics every rekey/invite (insider DoS)

**Component:** `crypto/src/pke/xwing_ristretto255.rs`, group-key delivery in
`key_manager` / `sdk`
**Guarantee broken:** insider robustness ("malicious insiders cannot cause denial of
service for other members").

### What's wrong

A member's KEM public key (`update_key`) is stored as an opaque plaintext blob in `_users`
and later used as an mKEM recipient key when the group rekeys or invites. Deserialization
validates **length only**, never that the encoded point is a valid curve point:

```rust
// crypto/src/pke/xwing_ristretto255.rs:106-121
impl<'de> Deserialize<'de> for XWingRistrettoPublicKey {
    ... if bytes.len() != XWING_RISTRETTO_PK_SIZE { return Err(...); }  // length only
    Ok(Self(pk))                                                        // raw bytes, unvalidated
}
```

Validity is deferred to encapsulation time, where it is a **panic**, not an error:

```rust
// crypto/src/pke/xwing_ristretto255.rs:566-569 (multi-recipient encaps)
let pk_point = pk_r.decompress()
    .expect("public key should be valid Ristretto point");            // panics on bad point
```

Recipient keys come straight from verified `_users` rows with no validation
(`sdk/src/users.rs:340-341`), and the changelog verifier treats `update_key` as an ordinary
plaintext column — it never parses it as a curve point, so a malformed key enters
authenticated state legitimately.

### Exploit / failure scenario

1. Mallory (a member, or invited as one) sets `_users.update_key` to a 1216-byte blob whose
   Ristretto component is a non-canonical encoding (correct length, invalid point). She
   signs the entry, so it verifies and commits.
2. Later, any honest member performs an operation that encapsulates the group key to the
   whole recipient set — a **rekey on member removal** or an **invite** — feeding Mallory's
   `update_key` into `encaps`.
3. `.decompress().expect(...)` panics; the operation cannot complete. Because Mallory's row
   persists, **every** future rekey/invite that includes her panics the same way. The group
   can no longer rotate keys, remove members, or add members — a persistent denial of the
   core membership machinery. Removing Mallory is itself a rekey, so the group may be unable
   to evict the member causing the problem through the normal path.

### Fix

- Validate KEM public keys at deserialization: decompress the Ristretto component (and
  validate the ML-KEM key per FIPS 203) and reject invalid encodings, so a bad key can
  never enter a member record.
- Never `expect()` on externally-supplied key material — make the `encaps` paths return
  `Result`/`Option` and propagate an error.
- Validate `update_key` in the changelog verifier when an `InviteUser`/`RefreshKeys`/
  `CreateSpace` entry writes it, rejecting malformed keys at the authenticated-state
  boundary.

---

## 017 — HIGH: Unauthenticated stack-overflow crash via unbounded `StoredValue` postcard recursion

**Component:** `backend/storage-encoding/src/stored_value.rs`, `backend/server/src/db.rs`
**Guarantee broken:** availability. Unauthenticated, single small frame, aborts every
Space on the instance.

### What's wrong

`StoredValue`, the on-merk column value type, is recursively nested and decoded with
postcard, which imposes **no recursion/depth limit** (unlike serde_json's default 128):

```rust
// backend/storage-encoding/src/stored_value.rs:34-44, 106-109
pub enum StoredValue { ... Array(Vec<StoredValue>), Object(Vec<(String, StoredValue)>) }
pub fn bytes_to_value(bytes: &[u8]) -> Result<Value> {
    let stored: StoredValue = postcard::from_bytes(bytes) ... ?;  // recurses per level
    Ok(stored.into())                                             // From impl ALSO recurses
}
```

Both the postcard deserialize and the `From<StoredValue> for Value` conversion recurse one
stack frame per nesting level; each level costs ~2 bytes on the wire, so tens of KB
overflow the thread stack (SIGABRT). Critically, this decoder runs on client bytes
**before any signature or identity check**:

```rust
// backend/server/src/db.rs:2870-2885
pub async fn handle_change_with_proofs(&mut self, change, auth, retention_proofs) -> ... {
    self.verify_retention_proofs_from_change(...).await?; // (A) decodes _retention values FIRST
    self.handle_change(change, auth).await                // (B) signature check is in here
}
```

`verify_retention_proofs_from_change` → `extract_retention_writes_from_change`
(`db.rs:231`) calls `bytes_to_value` directly on `kv.value` for any entry whose key parses
as a `_retention` column (`db.rs:261/265/293/297`). `handle_change`'s signature and
`auth.uid == entry.uid` checks run only afterward, and server authentication is a spoofable
base64 query param.

### Exploit / failure scenario

1. An unauthenticated attacker opens a WebSocket and sends one `DbRequest::Change` frame
   with a single entry: key = a `_retention` placeholder column (`"key"` or `"value"`),
   value = a deeply-nested postcard `Array(Array(Array(…)))` of a few tens of KB.
2. `handle_change_with_proofs` → `verify_retention_proofs_from_change` →
   `extract_retention_writes_from_change` → `bytes_to_value` recurses per level; the stack
   overflows and the process aborts — before any signature, membership, or valid `space_id`
   is checked.
3. Because all requests are serialized through the single global request queue, the crash
   takes down **every Space** on the instance.

### Fix

- Bound recursion when decoding untrusted `StoredValue`: set an explicit depth limit on the
  postcard deserializer, cap nesting during decode, or make decoding iterative; also bound
  the `From<StoredValue> for Value` conversion.
- Apply size/shape limits to change entries and decode `_retention` values only **after**
  the entry's signature and `auth.uid == entry.uid` are verified.
- Optionally run request handling on a bounded-stack worker that converts overflow into an
  error response.
