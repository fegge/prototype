# Finding 005 — Deployed mVE soundness is 96-bit, not 128-bit (weakens insider-robustness / targeted-exclusion resistance)

- **Severity:** Medium — soundness margin below a 128-bit target; the safer parameter
  set is already implemented and one const-generic away.
- **Component:** `zkp/src/mve/mod.rs`, `key_manager/src/lib.rs`
- **Status:** Confirmed by code inspection

## Description

The multi-recipient verifiable encryption (mVE) cut-and-choose proof's soundness is
governed by `(k, u)` where the offline forgery work factor is `C(k, u)`. The parameter
table offers a 128-bit set but the constants **default to a 96-bit set**:

```rust
// zkp/src/mve/mod.rs:32-40
pub const MVE_PARAMS: [(usize, usize); 4] = [
    (247, 30), // 128-bit security
    (100, 50), // 96-bit security
    (126, 30), // 96-bit security: balanced
    (443, 16), // 96-bit security
];
pub const MVE_DEFAULT_K: usize = 126;
pub const MVE_DEFAULT_U: usize = 30;
```

`log2(C(126, 30)) ≈ 96`. Every group-key operation in `key_manager` instantiates the
prover/verifier with the default generics — no `(K, U)` override — so the deployed
configuration for **both invite and rekey** is 96-bit:

```rust
// key_manager/src/lib.rs
PoseidonMve::<DefaultMkem>::prove(  ... )   // :115 (rekey), :195 (invite)
PoseidonMve::<DefaultMkem>::verify( ... )   // :320 (verify_rekey), :336 (verify_invite)
```

The 128-bit `(247, 30)` set is defined but never referenced anywhere in the workspace.

## Exploit / failure scenario

What the cut-and-choose actually protects is **robustness**, i.e. that a malicious
inviter/rekeyer cannot silently exclude or target a member. (It does *not* protect key
agreement — the Poseidon2 commitment binding at decrypt already forces any accepting
recipient onto the unique committed key, so equivocation to *distinct* keys is
impossible regardless of `(k,u)`.)

A malicious member running a rekey can craft the multi-recipient ciphertext so a chosen
victim's slot decrypts to non-committing garbage (each recipient slot is an independent
pad, so per-recipient forgery is possible). The victim then rejects that slot and is
**silently excluded** from the new epoch, keeping only the old key — a denial /
targeted-exclusion attack on a specific member. The forgery is caught only if one of the
bad slots lands in the `k−u` **opened** set; success requires all `u` **kept** indices
to coincide with the attacker's bad indices, which the attacker cannot steer (the
Fiat-Shamir challenge picks them). The attacker therefore grinds the transcript offline
until the kept set matches, at expected cost `C(k, u)`.

At the deployed `(126, 30)` that cost is `≈ 2^96` offline hash evaluations — no server
interaction, no rate limit. `2^96` is below a modern 128-bit security target, and the
codebase already ships a `2^128` option. For a construction whose entire purpose is
insider robustness, deploying the weaker margin by default is a real, avoidable
weakness.

## Recommended fix

- Change the `key_manager` call sites to instantiate the 128-bit parameters, e.g.
  `PoseidonMve::<DefaultMkem, 247, 30>`, or set `MVE_DEFAULT_K = 247` so the default is
  the 128-bit set.
- Document the security level next to the deployed constant, and add a compile-time
  assertion (`const _: () = assert!(log2_binomial(K, U) >= 128)` equivalent) so the
  default can't silently regress below target.
