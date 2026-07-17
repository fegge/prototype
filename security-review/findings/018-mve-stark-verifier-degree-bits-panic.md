# Finding 018 — mVE/STARK verifier panics on attacker-controlled `proof.degree_bits`

- **Severity:** Medium (panic-based DoS of the proof verifier on malformed input)
- **Component:** `zkp/src/mve/poseidon2.rs` (and the p3-uni-stark `setup_preprocessed` path)
- **Status:** Confirmed by code inspection (verified against `p3-uni-stark 0.5.3` source)

## Description

The STARK verifier reads `degree_bits` directly from the deserialized proof and passes it
to `setup_preprocessed` with no bounds check:

```rust
// zkp/src/mve/poseidon2.rs:722-725
let proof: p3_uni_stark::Proof<KoalaBearStarkConfig> =
    postcard::from_bytes(narg_string).map_err(|_| VerificationError)?;
let degree_bits = proof.degree_bits.saturating_sub(config.is_zk());   // attacker-controlled usize
let preprocessed = setup_preprocessed(&config, self, degree_bits);    // panics below
```

Inside `setup_preprocessed` (p3-uni-stark-0.5.3 `preprocessed.rs`):

- `let init_degree = 1 << degree_bits;` — for `degree_bits >= 64` this is a **shift
  overflow** (panic in debug; masked in release).
- `assert_eq!(preprocessed.height(), init_degree, "preprocessed trace height must equal
  trace degree");` — the honest height for `MveAirKoalaBearPoseidon2_16` is derived purely
  from verifier-side data (`(1 + kept_commitments.len()).next_power_of_two()`),
  **independent of `proof.degree_bits`**. So any `degree_bits` other than the honest value
  makes this `assert_eq!` fire (panic in debug **and** release).

`proof.degree_bits` is a plain field of the postcard-deserialized proof, fully
attacker-controlled and unvalidated. The same unvalidated pattern appears at
`poseidon2.rs:775-776` for the transition-statement verifier. Reachable from the public
`PoseidonMve::verify` entry point (`poseidon2.rs:409` → `MveAirKoalaBearPoseidon2_16::verify`
at `:720`). The crate itself carries the TODO "don't panic/assert in this lib"
(`zkp/src/mve/mod.rs:22`).

(Note: the initially-hypothesized *allocation blowup* from a huge `degree_bits` is
**refuted** — the preprocessed-trace allocation is bounded by verifier-reconstructed
`expected_blocks`, and `natural_domain_for_degree(1 << degree_bits)` is only reached
*after* the `assert_eq!`. The real, reachable impact is a panic, not memory exhaustion.)

## Exploit / failure scenario

1. An attacker takes any otherwise-valid mVE/STARK proof (or crafts one) and sets
   `proof.degree_bits` to any value other than its honest `log2(height)(+is_zk)` — e.g.
   `0`, or `>= 64`.
2. `postcard::from_bytes` accepts it; `setup_preprocessed` then panics (shift overflow or
   `assert_eq!` mismatch) instead of returning `Err(VerificationError)`.
3. Whoever runs the verifier crashes: on the reference server this is inside the
   single-threaded `REQUEST_QUEUE`, so a rekey/invite carrying a crafted mVE proof aborts
   the process for all Spaces; on a client verifying a proof it crashes that client.

## Recommended fix

- Validate `proof.degree_bits` against the expected trace height **before** calling
  `setup_preprocessed`: compute the expected height from the verifier-reconstructed data
  (`expected_blocks.len().next_power_of_two().trailing_zeros()`, adjusted for `is_zk`) and
  return `VerificationError` on mismatch. Apply the same at `poseidon2.rs:775-776`.
- Upstream: avoid `assert!`/shift-overflow on deserialized proof fields in the verifier;
  return errors. Aligns with the existing `mod.rs:22` TODO.
