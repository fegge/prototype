# Finding 016 — "Deniable sender authentication" is not provided; authorship uses non-repudiable, transferable signatures

- **Severity:** Medium (privacy / stated-guarantee gap). Not a broken check — the
  mechanism chosen for authorship is the cryptographic opposite of the stated goal, and
  users relying on deniability are materially harmed.
- **Component:** `crypto/src/signature/*`, `backend/src/sign_change.rs`, `sdk/src/users.rs`
- **Status:** Confirmed by code inspection

## Description

One of the four stated security properties is **deniable sender authentication**:

> "Members can authenticate the author of each data object without producing
> publicly-verifiable cryptographic evidence of user relationships." (README)

The implementation does the reverse. Every changelog entry — and therefore every data
object's authorship — is authenticated by an **individually-keyed, publicly-verifiable
digital signature**:

- Each user holds their own `SignatureKeyPair` (`sdk/src/users.rs:26,40`), default
  `DefaultSignature` = **Ed25519** (`crypto/src/signature/ed25519.rs`); ML-DSA-65 is the
  alternative — both are standard non-repudiable signature schemes.
- The user's **public verification key** is published in `_users.auth_key`
  (`users.rs:60,189`) and replicated to every member.
- `sign_change` signs the entry bytes with the author's secret key
  (`backend/src/sign_change.rs:12-19`); `verify_change_signature` checks them against the
  published verification key.

There is **no** deniability construction anywhere in the codebase — no ring signature, no
designated-verifier signature, no shared-key MAC, no OTR-style deniable authentication.
(Grepped `crypto/`, `sdk/`, `key_manager/`, `backend/`, `ffproof/`.)

Consequently, authorship is **non-repudiable and transferable**: anyone in possession of
the (decrypted) changelog and the `_users` table — any current member, any former member
who retained a copy, or any third party they hand it to — can produce a cryptographic
proof that "user X authored data object Y" that is verifiable by *anyone* using standard
Ed25519/ML-DSA verification. That is exactly the "publicly-verifiable cryptographic
evidence of user relationships" the goal says must not be produced.

## Exploit / failure scenario

1. Alice, believing the system provides deniable authentication, posts sensitive content
   to a Space.
2. Bob (a member, or a member who is later removed but kept a copy of the changelog and
   `_users`) extracts Alice's signed entry, her verification key, and the signature.
3. Bob hands this triple to a third party (journalist, court, adversary). The third party
   runs `ed25519_verify(alice_vk, entry_bytes, sig)` and obtains transferable,
   non-repudiable proof that Alice authored that specific content — the precise outcome
   deniable authentication is meant to prevent.

Unlike the README's three explicitly-flagged caveats (placeholder auth, dev-mode proofs,
DoS), deniable authentication is listed as a delivered security property without a
"not implemented" note, so a user could reasonably rely on it. The gap is therefore a
privacy hazard, not merely an unfinished feature.

## Recommended fix

- Until a deniable-authentication construction is implemented, **document clearly** that
  the current signatures are non-repudiable and that deniable authentication is not yet
  provided — do not list it among delivered guarantees.
- To actually provide the property, replace (or augment) per-entry non-repudiable
  signatures with a deniable authenticator among members, e.g.:
  - a **MAC / authenticator keyed on a secret every member holds** (the shared group key
    already exists), so any member could have produced it → deniable to outsiders; or
  - **ring / group signatures** over the current membership set (author is one-of-N,
    unprovable which); or
  - a **designated-verifier** scheme so a recipient cannot transfer the proof.
  Each has different trust/anonymity trade-offs against a *member* adversary; the
  whitepaper's intended construction should be the reference.
- Note the tension with Finding 002/verifiable-history: the same signature currently
  serves both non-repudiable history integrity *and* (nominally) authorship; separating
  "integrity of the log" from "deniable authorship of content" is likely required.
