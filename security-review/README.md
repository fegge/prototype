# Encrypted Spaces — Security Review

In-depth security review of the Encrypted Spaces prototype. Each confirmed issue is a
separate markdown file in [`findings/`](./findings), with a description, a concrete
exploit/failure scenario, and a recommended fix.

> Context: the repository is explicitly a research prototype ("DO NOT USE IN
> PRODUCTION") and already concedes three limitations — placeholder server
> authentication, dev-mode fast-forward proofs by default, and incomplete DoS
> hardening. This review focuses on issues that go **beyond** those known caveats,
> especially ones that break the four stated security guarantees (verifiable history,
> selective retention, insider robustness, deniable authentication). Where a finding
> overlaps a known caveat, it documents a *specific, novel consequence*.

## Confirmed findings

| # | Severity | Title | Guarantee affected |
|---|----------|-------|--------------------|
| [008](findings/008-CRITICAL-ff-ragged-tail-unbound-data-commitment.md) | **Critical** | FF ragged tail doesn't bind `old_root` to the client DC → arbitrary state substitution | Verifiable history / integrity |
| [014](findings/014-ff-recursion-program-id-unconstrained.md) | High (Critical w/ real-proofs) | FF recursion verifies prior chunk against an unconstrained, input-supplied image ID → forgeable proof chain | Verifiable history / FF soundness |
| [004](findings/004-action-self-row-forged-authorization-bypass.md) | High | Action `self.*` forged for Delete/Update legs → assertion bypass + ACL-free cascade | Access control |
| [007](findings/007-reduce-does-not-erase-deleting-members-key.md) | High | `reduce()` never erases the deleting member's own key; deletion is reversible | Selective retention |
| [010](findings/010-joining-client-no-genesis-root-of-trust.md) | High | Joining client has no genesis root of trust → server can fabricate the whole Space | Verifiable history (join) |
| [003](findings/003-malformed-member-public-key-panics-rekey.md) | High | Malformed member `update_key` panics every rekey/invite | Insider robustness (DoS) |
| [002](findings/002-signature-missing-space-and-domain-separation.md) | Medium (latent) | Signatures bind no Space id / domain separator → cross-Space replay | Authenticity |
| [005](findings/005-mve-default-soundness-96-bit.md) | Medium | Deployed mVE soundness is 96-bit, not 128-bit | Insider robustness |
| [006](findings/006-recover-path-missing-canonical-commitment-check.md) | Medium | Key-recovery path lacks the canonical-commitment check → epoch rollback | Insider robustness / PCS |
| [009](findings/009-broadcast-changeresponse-unwrap-client-panic.md) | Medium | Malicious broadcast frame panics the wasm client | Availability |
| [011](findings/011-retention-unbounded-hgk-resolution-dos.md) | Medium | Attacker-controlled `dgk_next` → unbounded HGK-resolution grind | Availability |
| [012](findings/012-already-applied-branch-cache-poisoning.md) | Medium | Already-applied re-verify returns writes from an unanchored proof (cache/row-id poisoning) | Local integrity |
| [013](findings/013-parent-clc-unchecked-cross-user-reorder.md) | Medium | `parent_clc` never verified on apply → independent users' changes reorderable | Verifiable history (ordering) |
| [001](findings/001-unauthenticated-file-upload-memory-exhaustion.md) | Medium | Unauthenticated file upload buffers whole body before size check | Availability |

### Cross-cutting theme

Findings **008, 010, 012, 013** share a root cause: the client verifier's chain-continuity
checks (`old_root == current_data_commitment`, `parent_clc`, genesis pin) are enforced on
the primary single-change path but **missing or incomplete on the fast-forward / join /
already-applied paths**. Since the client verifier is the sole integrity boundary against
an untrusted server, these gaps are the highest-value area to harden. 008 is the most
serious (silent arbitrary-state substitution).

## Verified safe (checked, no issue found)

- **Query/SELECT proof completeness** — the client re-derives expected `ReadOp` ranges
  and checks exact set-equality against the tracer proof's walked ranges
  (`verify_read_ops`), and the Merkle range proof proves every key in each range. A
  server cannot omit rows. (Solid design.)
- **Timestamp policy & MMR** — domain-separated leaf/internal/initial tags
  (second-preimage resistant), `tree_size` cross-checked; timestamp HWM bounds are sound
  (one documented, deliberate proof-mode inactivity-freshness gap).
- **ACL predicate evaluator** — fail-closed on missing/typed operands; integer-only
  comparisons; `Err → AclDenied`.
- **`only_via_actions` gate, `update cols` allowlist, index/row consistency,
  `auth.user_id`↔signature binding** — all fail-closed / authenticated.
- **mVE key agreement** — Poseidon2 commitment binding at decrypt prevents equivocation
  to *distinct* keys regardless of `(k,u)`; recipient set is authenticated against
  `_users` and omission is rejected (honest server). The non-uniform challenge sampling
  bias (~2⁻⁵⁷) is inconsequential.
- **Retention one-wayness** — `HGK_DERIVE`/`D_DERIVE` ratchets and re-encryption are
  proven by STARK and genuinely sever post-reduce paths for future joiners; no cutoff
  off-by-one; fresh CSPRNG randomness. (The erasure gap is 007, about the *deleter's*
  key, not the ratchet.)
- **AES-256-CTR field encryption** — fresh random 128-bit nonce per field; no key/counter
  reuse.
- **CLC extension** — the exact signed entry bytes are what gets appended; no unsigned
  server field enters the commitment.

## Candidate / not independently confirmed (flagged by analysis, need follow-up)

These surfaced during review but were not verified to the same depth as the confirmed
findings; listed so they are not lost:

- **Concurrent reader observes provisional FF/broadcast state** during the deferred
  signature-verification window (reads take no `serialize_mutations`/`ff_in_progress`
  guard). If FF later rolls back on a bad signature, the app may have already consumed
  unverified-authorship data. (Medium; needs a concrete race PoC.)
- **`collect_reduce_verify_inputs` prefers `pending_writes` for the survivor D-row
  commitment** (`space_key.rs:~605`), possibly allowing a live boundary-key substitution
  by a malicious reducer. Does not expose deleted data. (Low.)
- **Attacker-controlled `proof.degree_bits`** into `setup_preprocessed` in mVE verify
  (`zkp/src/mve/poseidon2.rs:~724`) — possible allocation-blowup DoS if plonky3 allocates
  before validating against the expected trace height. (Needs a p3-verifier check.)
- **Unbounded predicate-parser recursion** (`backend/acl-types`, `predicate.pest` /
  `ast_build.rs`): stack overflow on deeply nested predicates. Reachable mainly at
  operator-supplied schema-load time (lower reachability); client-written `_access_control`
  `rule_json` is serde_json (recursion-limited). (Low–Medium.)
- **postcard depth** on client-supplied proof/action/retention structures (no explicit
  recursion cap). (Low–Medium; consistent with the README DoS caveat.)

## Method

Architecture and threat model were mapped first (see the design/threat-model summary in
the session), then the four core guarantees were adversarially probed: the client
verifier, query-proof completeness, the ACL/action verifier, mVE/rekey key distribution,
and the retention key-erasure construction. Findings were verified against the actual code
(file:line) before being written up; each file states the confidence and, where relevant,
the mitigating conditions.
