# ADR-0014: M2 statement shape — padded binding with counts, scalar public inputs, single-token bundles, size 4/4/2

- Status: Accepted; proof mechanics/device assumptions amended by [ADR-0018](0018-stwo-private-proving.md); push output and operation binding amended by [ADR-0021](0021-push-only-payments.md); external intent and total return-output accounting amended by [ADR-0023](0023-return-notes-and-adapter-compatibility.md)
- Date: 2026-09-20
- Deciders: broody
- Amends: spec §2 (bundle maxima), §6.2/§6.5 (transition commitment), §7.2
  (public inputs gain `deadline`), §7.3.6 (binding encoding). Supersedes the
  non-padded binding choice in the original freeze.

## Context

Generalizing the inner circuit from the 1-in/1-out draft to the full §7
statement forced four design decisions:

1. **Variable-length public arrays vs fixed circuits.** gnark circuits are
   fixed-size; the frozen binding hashed *non-padded* spans ("loop bound =
   public count"). A variable-length Poseidon sponge in-circuit requires a
   dynamic absorb (conditional permutation per slot, parity-dependent tail) —
   ~26 permutations of dead weight and a classic bug farm.
2. **Groth16 public-input vectors are fixed-length**, but `SpendPublicInputs`
   carries variable spans. The on-chain verifier cannot take the spans.
3. **Per-token conservation** with arbitrary token addresses requires either
   in-circuit grouping/sorting or conditional-sum machinery (each withdrawal
   token × all note slots).
4. **Phone proving budget.** A fixed-shape circuit pays its full size on every
   proof. At 16/16/4 the statement is ~1,400 permutations (~66 M constraints
   with the general emulated layer; ~11 M optimized) — the proving key alone
   would be phone-hostile, and M4's <10 s target unreachable. Real bundles are
   overwhelmingly ≤ 2-in/2-out; large consolidations can chain transactions.

Also resolved here: the §6.5 transition-commitment serialization needed the
circuit to tie the controller-signed commitment to the actual legs, and the
original formula `H(tag, ctx, canonical(transition), deadline, nonce)` could
not reference `statement_binding` (circular: the binding embeds the
transition_commitment).

## Decision

1. **Padded binding with explicit counts** (both sides): `statement_binding =
   H(TX_BIND_TAG, version, chain, pool, root, n_in, nullifiers[4] zero-padded,
   n_out, commitments[4] zero-padded, n_wd, withdrawals[2] as (token, low,
   high) zero-padded, controller, deadline, transition_commitment,
   actions_hash)`. Fixed 27-felt preimage = 14 permutations; the circuit
   absorbs witness arrays raw, and binding equality pins the padding to zeros
   and the counts to the true spans (the contract pads with zeros when
   recomputing). Zero-value guards on real slots are unchanged.
2. **Scalar Groth16 public inputs (8)**: `protocol_version, chain_id,
   pool_address, tree_root, controller, deadline, transition_commitment,
   statement_binding`. Every array field enters via the binding; the pool
   passes exactly this scalar vector to `IVerifier.verify`.
3. **Single-token bundles**: all notes and withdrawals in a bundle share one
   `token` (witness, pinned transitively by the openings and the withdrawal
   zip). Conservation is a plain sum: `Σ in = Σ out + Σ withdrawals`. Multi-token
   operations are multiple bundles.
4. **Bundle maxima 4/4/2** (`MAX_INPUT_NOTES=4, MAX_OUTPUT_NOTES=4,
   MAX_WITHDRAWALS=2`): ~430 permutations per proof (~20 M constraints general
   emulated; ~3–4 M with the optimized limb layer, ADR-0008) — laptop-trivial
   and phone-plausible. Bigger consolidations chain txs.
5. **Transition commitment over the padded legs** (breaks the circularity):
   `transition_commitment = H(TRANSITION_COMMIT_TAG, version, chain, pool,
   n_in, nullifiers[4], in_amounts[4], n_out, commitments[4], out_amounts[4],
   n_wd, withdrawals[2] (token, low, high), controller, deadline, nonce)`. The
   circuit recomputes it from the same witnesses and asserts it whenever
   `controller ≠ 0`. It covers exactly the legs (nullifiers+amounts in,
   commitments+amounts out, withdrawals), so the controller's signature binds
   the real transition — the §6.5 bespoke serialization is replaced by this
   padded preimage. `deadline` joins `SpendPublicInputs` (u64, 0 for ordinary
   spends) and the pool zip-asserts it equals the `ControllerApply` action's
   deadline.

## Alternatives considered

- **Dynamic-count sponge over the non-padded flattening** — rejected: ~2× the
  binding cost and a parity-dependent tail in-circuit, for zero security gain
  over explicit counts.
- **Serialize full `SpendPublicInputs` spans into the verifier call** —
  impossible: Groth16 verifies over a fixed public-input vector.
- **Multi-token conservation via per-withdrawal-token conditional sums** —
  rejected for v2: 2×32 conditional selects per bundle plus token-identity
  wiring; single-token covers real usage and multi-token txs chain.
- **Size classes (2/2/1, 4/4/2, 16/16/4 circuits)** — rejected: one ceremony,
  one verifier, predictable budget. Size classes remain possible later (the
  binding format is size-independent; each class is its own circuit+ceremony).
- **Keep 16/16/4** — rejected: the phone budget is the binding constraint and
  4-in consolidation chains fine.

## Consequences

- The M2 circuit is a single fixed shape; the ceremony covers exactly one
  circuit (ADR-0008's one-ceremony posture preserved).
- `SpendPublicInputs` gains `deadline`; the Cairo binding switches to the
  padded+counts encoding; the verifier payload becomes the 8-scalar vector.
  The zip, nullifier, root-ring, and context checks are untouched.
- Spec §6.5's serialization table is replaced by the padded legs preimage
  (simpler; data-minimization unchanged — the controller sees the legs
  off-chain, signs only the hash).
- Every proof pays the full 4/4/2 shape even for 1-in transfers (padded slots
  are dead permutations); this is the price of one-ceremony simplicity and is
  what the optimized limb layer (M4 critical path) must absorb.
- Deferred, flagged: the custom limb-folding layer (~6–8k constraints/perm vs
  ~47.5k general emulated) is M4-critical but is hand-rolled field arithmetic —
  it needs an audit pass before any ceremony, and is *not* part of this change.

## Native capacity review

[The 2026-09-21 review](../native-shape-review.md) demonstrates larger synthetic native statements and compares fixed padding with counted active entries under a 16 GiB cap. It recommends reviewing the encoding and qualifying resource-informed limits. The funded reference remains at 4/4/2; these measurements do not silently replace its format.
