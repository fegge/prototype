# Finding 002 — Changelog signatures bind no Space identity or domain separator (cross-Space replay)

- **Severity:** Medium (latent) — authenticity / integrity. Not exploitable under the
  current fresh-key-per-join flow, but becomes directly exploitable under the
  persistent-identity-key auth model the project explicitly plans (README:
  "something signed using the user's identity key").
- **Component:** `ffproof/changelog_core` (entry serialization), `crypto/signature`,
  `backend/src/sign_change.rs`
- **Status:** Confirmed by code inspection

## Description

Every changelog entry is authenticated by signing its serialized bytes:

```rust
// backend/src/sign_change.rs:12-19
pub fn sign_change<S: Signature<Message = [u8]>>(change: &mut ChangelogEntry, key_pair: ...) {
    change.signature.clear();
    let bytes = change.as_bytes();          // postcard of the ChangelogEntry
    change.signature = key_pair.sign(&bytes).as_ref().to_vec();
}
```

`ChangelogEntry` (`ffproof/changelog_core/src/changelog.rs:88`) has fields
`timestamp, uid, parent_change, message, sig_ref, parent_clc, signature`. **There is
no `space_id` field**, so the signed message contains no Space identity. The signature
primitives add no space binding either:

- **Ed25519** signs the raw bytes with *no* domain-separation context at all
  (`crypto/src/signature/ed25519.rs:24-26`: `sk.sign(msg)`).
- **ML-DSA-65** uses a single static context `b"Encrypted Spaces MLDSA v1"`
  (`crypto/src/signature/mldsa.rs:6,109`) — a protocol/version tag, but still not
  Space-specific and not per-purpose.

The one field that *could* provide implicit Space binding, `parent_clc` (the parent
changelog commitment), does **not**, because the chain root is not Space-specific:

```rust
// ffproof/changelog_core/src/changelog.rs:289-292
pub fn initial_clc_state(initial_dc: &[u8; 32]) -> ClcState {
    let mut tree = MmrTree::new();
    tree.initialize(initial_dc);   // root derives ONLY from initial_dc
    ...
}
```

`initial_dc` is the schema-derived data commitment (`sdk_codegen::DATA_COMMITMENT`),
with no `space_id` salt. The reference server applies **one schema template to every
new Space** (`--schema`, see `backend/server/README.md`). Therefore any two Spaces
created from the same app schema have a **byte-identical initial commitment and an
identical hash-chain starting point**, and a signed entry positioned at the start of
one chain (`parent_change = 0`, `sig_ref = 0`, `parent_clc = shared initial CLC`) is
equally valid at the start of the other.

## Exploit / failure scenario

Precondition for a live exploit: the same signing key is a valid `_users.auth_key`
in two Spaces that share a schema. This does **not** occur in the current join flow
(each join mints a fresh auth keypair), so the issue is **latent today**. It becomes
exploitable in either of these situations:

1. **Persistent identity keys (planned).** The README states real authentication will
   be "something signed using the user's identity key." If a user's long-lived
   identity key is reused across the Spaces they belong to, a malicious server can
   lift a signed entry the user authored in Space X (e.g. an `insert` into a shared
   table) and inject it into Space Y — same schema, user present with the same key —
   at the matching chain position. Space Y clients verify the signature against the
   user's `_users.auth_key`, the `parent_clc`/`sig_ref` line up at the shared prefix,
   and the forged-origin row is accepted as a genuine, user-authored change in
   Space Y that the user never made there.
2. **Any deliberate or accidental key reuse** between Spaces (e.g. a client that
   caches/reuses an identity keypair, key-import features, or test fixtures promoted
   to prod) opens the same replay.

The consequence is a break of the "verifiable history / authenticated authorship"
guarantee across Space boundaries: the server can attribute to a user, in one Space,
an operation they only authorized in another.

## Recommended fix

- **Bind the Space (and protocol context) into what is signed.** Prepend a
  domain-separation frame to the signed message, e.g.
  `sign( "encrypted-spaces:changelog-entry:v1" || space_id || entry_bytes )`, and
  verify against the same frame. `space_id` (a `SpaceId`) is already available at
  both signer and verifier.
- **Give Ed25519 a domain-separation context too** (it currently has none), matching
  ML-DSA, and make the context include the Space identity rather than only a static
  version string.
- **Salt the initial commitment with `space_id`** so `initial_dc` /
  `initial_clc_state` differ per Space even for identical schemas. This adds
  defense-in-depth: replayed entries would fail the `parent_clc` / chain-continuity
  checks even if signature binding were somehow bypassed.
- Do this **before** introducing persistent identity keys, since that change is what
  turns this from latent to live.
