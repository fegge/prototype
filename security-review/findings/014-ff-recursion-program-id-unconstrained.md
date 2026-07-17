# Finding 014 — Fast-forward recursion verifies the previous chunk against an *unconstrained, input-supplied* image ID (forgeable proof chain)

- **Severity:** High — and **Critical for any deployment that relies on real
  fast-forward proofs** (`--features real-proofs`), which is the entire purpose of the
  feature. In default dev-mode builds FF receipts are already non-cryptographic, so this
  is masked there.
- **Component:** `ffproof/methods/guest/src/bin/extend_ff.rs`, `ffproof/src/verifier.rs`,
  `ffproof/changelog_core` (`FastForwardRange` journal)
- **Status:** Confirmed by code inspection

## Description

Fast-forward proofs are chainable: each chunk's guest recursively verifies the previous
chunk's receipt via `env::verify`. In the guest, the recursion image ID is **read from
untrusted guest input and used unconstrained**:

```rust
// ffproof/methods/guest/src/bin/extend_ff.rs:12-27
if !is_first {
    ...
    previous_io.set_from_bytes(&io_bytes).unwrap();

    #[allow(non_snake_case)]
    let mut PROGRAM_ID = [0u32; 8];
    env::read_slice(&mut PROGRAM_ID);            // <-- attacker-supplied

    let inputs = &serde::to_vec(&previous_io).unwrap();
    env::verify(PROGRAM_ID, inputs).unwrap();    // verify prior receipt under ANY id
}
```

`PROGRAM_ID` is:
- **not hardcoded** to the honest guest's own image ID,
- **not compared** to any trusted constant in-circuit, and
- **not committed** to the journal — `FastForwardRange` (`changelog.rs:338-370`) has no
  program-id field.

The verifier only pins the **outer** receipt:

```rust
// ffproof/src/verifier.rs:57-66
let extend_ff_id: Risc0Digest = expected_image_id.into();   // pinned FF_GUEST_IMAGE_ID
if proof.receipt.verify(extend_ff_id).is_err() { return false; }
let io: FastForwardRange = proof.receipt.journal.decode()?;  // journal carries no program id
```

So the client is assured only that the *outermost* execution ran the pinned guest. That
guest, in turn, will recursively accept a prior receipt produced by **any program the
prover names**, because it verifies against a `PROGRAM_ID` the prover supplies and no
one ever checks that this equals the honest guest's own image ID. RISC Zero composition
only requires the prover to actually possess a valid receipt for `(PROGRAM_ID, journal)`
— which a malicious prover trivially has for a guest *they* wrote.

## Exploit / failure scenario (real-proofs mode)

1. A malicious prover (e.g. a colluding/compromised server operator with proving
   capability) writes a trivial guest `G'` that reads a `FastForwardRange` from input and
   `env::commit`s it verbatim, performing **no** changelog verification. They prove `G'`
   once, obtaining a valid receipt `R'` whose journal is an arbitrary, **forged**
   `previous_io`: `start_dc = initial_dc`, `start_clc_state = initial_clc_state(initial_dc)`
   (to satisfy the client's genesis checks), and `end_dc = D*`, `end_clc_state = C*`,
   `sigref_map = …` all chosen by the attacker.
2. They run the **honest, pinned** `extend_ff` guest for a final chunk with
   `is_first = false`, feeding `previous_io = <forged range>`, `PROGRAM_ID = image_id(G')`,
   and a small set of genuine entries that validly chain from `D*/C*`. The guest's
   `env::verify(image_id(G'), serde(previous_io))` succeeds (R' resolves the assumption),
   the continuity asserts pass (`verify_range.start == previous_io.end`), and the final
   chunk verifies honestly.
3. The outer receipt verifies against the pinned `FF_GUEST_IMAGE_ID`. The client accepts a
   `VerifiedFfOutput` whose `[0, end)` range is "proven from genesis" — but the entire
   prefix `[0, D*/C*)` was never verified by any honest guest. The attacker has forged
   arbitrary history (membership, ACL, data) for that prefix, capped with a small genuine
   tail.

This defeats the soundness of the fast-forward mechanism: the succinct proof no longer
attests that the committed range is a valid rule-following evolution from genesis.
Combined with the client's genesis anchor checks (which the forged `previous_io`
satisfies), nothing else catches it.

## Recommended fix

- **Constrain the recursion image ID in-circuit.** The guest must verify the previous
  chunk against a *fixed, trusted* image ID equal to its own, not an input value.
  Standard approaches:
  - Commit the assumed `PROGRAM_ID` into the journal (`FastForwardRange`), and have
    `verify_ff` enforce `journal.program_id == expected_image_id` — i.e. require uniform
    self-recursion against the pinned guest.
  - Or bake the trusted recursion image ID into the guest as a constant (via the standard
    two-stage/self-image build) and assert `PROGRAM_ID == THAT_CONSTANT` before
    `env::verify`.
- Until fixed, treat real-proofs FF output as unauthenticated for the pre-final-chunk
  prefix; do not rely on FF succinctness for security.
- Add a negative test: a proof whose inner `PROGRAM_ID` differs from the pinned guest ID
  must fail verification.
