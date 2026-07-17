# Finding 003 — A malicious member's malformed `update_key` panics every rekey/invite (insider DoS)

- **Severity:** High (within the prototype's own threat model) — directly breaks the
  stated **insider-robustness** goal: "malicious insiders cannot ... cause denial of
  service for other members."
- **Component:** `crypto/src/pke/xwing_ristretto255.rs`, group-key delivery in
  `key_manager` / `sdk`
- **Status:** Confirmed by code inspection

## Description

A member's KEM public key (`update_key`) is stored as an opaque plaintext blob in the
`_users` table and later used as an mKEM recipient key when the group rekeys or invites.
Deserialization of that key validates **length only**, never that the encoded point is
a valid curve point:

```rust
// crypto/src/pke/xwing_ristretto255.rs:106-121
impl<'de> Deserialize<'de> for XWingRistrettoPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> ... {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != XWING_RISTRETTO_PK_SIZE {          // <-- only a length check
            return Err(...);
        }
        let mut pk = [0u8; XWING_RISTRETTO_PK_SIZE];
        pk.copy_from_slice(&bytes);
        Ok(Self(pk))                                          // raw bytes, unvalidated
    }
}
```

`from_bytes` (line 66) is likewise a raw wrapper. The validity check is deferred to
encapsulation time, where it is a **panic**, not a recoverable error:

```rust
// crypto/src/pke/xwing_ristretto255.rs:566-569 (multi-recipient encaps loop)
let pk_point = pk_r
    .decompress()
    .expect("public key should be valid Ristretto point");   // <-- panics on bad point
```

(The same `.expect("public key should be valid Ristretto point")` appears in the
single-recipient `encaps_deterministic` paths at lines 401-402 and 445-446.)

Recipient keys are pulled straight from the verified `_users` rows with no validation:

```rust
// sdk/src/users.rs:340-341
let remaining_pks: Vec<SpacePublicKey> =
    remaining.iter().map(|u| u.update_key.clone()).collect();
```

The changelog verifier that admits an `InviteUser` / `RefreshKeys` entry treats
`update_key` as an ordinary plaintext column — it checks the column is present and the
entry signature is valid, but never parses the bytes as a curve point. So a malformed
key enters authenticated state legitimately.

## Exploit / failure scenario

1. Mallory is (or is invited as) a member. In her join / `RefreshKeys` change she sets
   `_users.update_key` to a 1216-byte blob whose 32-byte Ristretto component is a
   non-canonical encoding (e.g. all `0xFF`), keeping the length correct so
   deserialization succeeds. She signs the entry with her own key, so it verifies and
   is committed.
2. Later, any honest member performs an operation that encapsulates the group key to
   the whole recipient set — a **rekey on member removal**, or an **invite** — which
   feeds Mallory's `update_key` into `DefaultMkem::encaps`.
3. `.decompress().expect(...)` panics. The rekey/invite operation cannot complete.
4. Because Mallory's row persists in authenticated state, **every** future rekey and
   invite that includes her as a recipient panics the same way. The group can no
   longer remove members, rotate keys, or add members — a persistent denial of the
   core membership machinery for all other members. Removing Mallory is itself a
   rekey, so the group may be unable to evict the very member causing the problem
   through the normal path.

Note the workspace builds with `panic = "unwrap"` (Cargo.toml), so this unwinds rather
than aborting, but it still fails the operation and, depending on where `catch_unwind`
sits, can poison locks or wedge the client task.

## Recommended fix

- **Validate KEM public keys at deserialization.** In `Deserialize` / `from_bytes`,
  decompress the Ristretto component (and validate the ML-KEM encapsulation key per
  FIPS 203) and reject invalid encodings with an error, so a bad key can never enter a
  member record. This is the correct layer: reject on ingest.
- **Never `expect()` on externally-supplied key material.** Change the `encaps` paths
  to return `Result`/`Option` and propagate a decapsulation/encapsulation error
  instead of panicking, so even a key that slips through cannot crash a peer.
- **Validate `update_key` in the changelog verifier** when an `InviteUser` /
  `RefreshKeys` / `CreateSpace` entry writes it, so malformed keys are rejected at the
  authenticated-state boundary and never reach the delivery path at all.
