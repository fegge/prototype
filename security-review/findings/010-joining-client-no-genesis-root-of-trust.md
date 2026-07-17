# Finding 010 — A joining client has no root of trust binding it to the real Space genesis

- **Severity:** High (integrity/authenticity on join). Related to the auth-placeholder
  caveat and to Finding 002 (no Space binding in signatures), but a distinct code-level
  gap: even the client-side crypto verification has no genesis anchor for a joiner.
- **Component:** `sdk/src/changelog.rs` (`extract_auth_key_from_create_space_change`),
  `sdk/src/lib.rs` (`Space::join`), `sdk/src/users.rs` (`SpaceInvite`)
- **Status:** Confirmed by code inspection

## Description

The design's premise is that clients need not trust the server because they verify every
response cryptographically. For a **joining** client, that verification has no root of
trust that identifies the genuine Space:

- `CreateSpace` authorship is trust-on-first-use: the verifying key is read from the
  entry's own `_users.auth_key` and the entry is checked against that same key
  (`changelog.rs:1114-1153`, `:1332-1352`). Any self-consistent `CreateSpace` verifies.
- The only compiled-in anchors are `initial_dc` and `ff_image_id`, both **per-app
  constants** — identical for every Space built from the same schema. The FF check
  `start_dc == initial_dc` (`changelog.rs:2026`) does not distinguish one Space from
  another (see also Finding 002: the chain root has no `space_id` salt).
- `space_id` is `SpaceId::random()` (`lib.rs:210`), a routing token never committed into
  state or bound into genesis.
- The `GkDeliveryEnvelope` is unauthenticated (only a `commit == binding_commitment`
  self-consistency check; see Finding 006).
- `SpaceInvite` (`users.rs:198-201`) carries the `space_id` and provisional keypairs but
  **no out-of-band pin** of the real creator key or genesis commitment.

Downstream key resolution (`resolve_signing_key_for_change`, `users.rs:608-699`) reads
all later signing keys from the `_users`/`_key_history` tables — so if genesis is forged,
every subsequent "authenticity" check is circular against attacker-populated state.

## Exploit / failure scenario

1. A user is invited and receives a `SpaceInvite` (space_id + provisional secret keys)
   over a trusted out-of-band channel. They call `Space::join` through a malicious server.
2. The server fabricates an **entire changelog**: a `CreateSpace` naming the attacker's
   key as creator, attacker-authored membership and `_access_control` rows, and a valid
   FF proof over it (the FF guest happily proves a self-consistent, validly-signed chain
   rooted at the universal `initial_dc`). It delivers a `GkDeliveryEnvelope` wrapping a
   server-known group key to the invitee's provisional update public key (which the
   server knows; wrapping a known key to a known public key is something anyone can do).
3. Every local check on join passes: FF verifies, `start_dc == initial_dc` holds, the
   envelope's commitment is self-consistent, key resolution succeeds against the
   attacker-populated `_users`. The victim lands in a **fully attacker-controlled Space**
   with attacker keys trusted as admins, and a group key the server knows.
4. The victim cannot read the *real* Space's data (they never receive the real group
   key — confidentiality holds), but they will now transact in a fake Space whose
   membership, access-control, and history are entirely the server's, believing it is
   the Space they were invited to.

## Recommended fix

- Carry an **out-of-band genesis pin** in `SpaceInvite`: the real creator's public
  identity key and/or the genuine post-genesis data commitment, delivered over the same
  trusted channel as the invite. On join, require the fabricated/real `CreateSpace` (and
  the FF `start`) to match that pin, rejecting any Space that does not.
- Salt the initial commitment with a per-Space secret/identifier (see Finding 002) so
  `initial_dc` is not a universal constant, and bind `space_id` into genesis so the
  routing token is authenticated.
- Authenticate the `GkDeliveryEnvelope` against the pinned creator/epoch (see Finding 006).
