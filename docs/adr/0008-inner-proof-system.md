# ADR-0008: Inner proof system selection

- Status: Superseded by [ADR-0018](0018-stwo-private-proving.md) (originally accepted 2026-09-19 by benchmark)
- Date: 2026-09-19 (proposed), 2026-09-19 (resolved)
- Deciders: broody
- Benchmark: [`bench/adr8/`](../../bench/adr8/) (gnark v0.16.3, BN254, validated
  against the Cairo VM's Poseidon test vector)

## Context

ADR-0005 commits to a user-generated inner ZK proof of the spend statement
(ADR-0004 membership + nullifier + conservation; ADR-0006 controlled transitions +
controller signature). Requirements:

- **Zero-knowledge** (mandatory — the outer operator is blind by construction).
- **Phone-provable** (M4 target: < 10 s on mid-range Android).
- **Verifiable inside Cairo** (the outer virtual block must verify the inner proof;
  Garaga-class Cairo verifiers exist for Groth16/PLONK over BN254).
- Hash compatibility with the on-chain state model: felt252-Poseidon must be
  cheap in the circuit too (spec §1 cross-field caveat).

Candidates: Groth16 (smallest proofs, per-circuit trusted setup), PLONK (universal
setup, larger proofs), Halo2 (no cheap Cairo verifier today), Stwo-native small
circuit (no ZK mode yet).

## Benchmark (measured, not estimated)

The dominant cost is **non-native felt252 arithmetic over BN254**. We
implemented the canonical Starknet Poseidon permutation (x³ S-box, r_f=8,
r_p=83, sha256-derived round constants, small MDS — Python reference validated
bit-exact against corelib's `poseidon_hash_span([1,2])` vector) as a gnark
circuit and ran both proof systems:

| Config | System | Constraints | Setup | Prove | Verify | Proof |
|---|---|---|---|---|---|---|
| 3×84-bit limbs | Groth16 | 47,501 | 3.6 s **per circuit** | 154 ms | 1 ms | 196 B |
| 4×64-bit limbs | Groth16 | 49,703 | 3.5 s | 162 ms | 1 ms | 196 B |
| 3×84-bit limbs | PLONK | 197,173 SCS gates | 0.4 s (universal SRS) | 1.61 s | 2 ms | 584 B |

Key findings:

1. **Permutation cost**: ~47.5 K constraints with gnark's general `emulated`
   package (~222 constraints per 252-bit mul; a permutation costs 214 non-native
   muls — every partial round still cubes one element — plus linear ARK/MDS).
   Audited custom limb-folding targets ~15–30 constraints/mul → **~6–8 K per
   permutation**, consistent with the spec §1 estimate. M2 must use optimized
   limb arithmetic; the general emulated package is the upper bound and still
   functional.
2. **Limb tuning**: 3×84 ≈ 4×64 (±4%); 2×126 (the theoretical minimum) overflows
   the BN254 scalar field in carry constraints — limb budget is a real
   engineering constraint, not a free parameter.
3. **Groth16 vs PLONK on the same circuit**: Groth16 proves **10× faster**
   (154 ms vs 1.61 s), proofs are **3× smaller** (196 B vs 584 B), SNARK-level
   verify is trivial for both. PLONK's setup is universal/reusable (0.4 s),
   Groth16's is per-circuit + ceremony (3.6 s mechanical work + MPC logistics).
4. **M2 budget extrapolation** (per input note: Merkle path 64 × H where
   H(a,b) = the contract's `poseidon_hash_span` 2-element sponge = 2
   permutations, + note derivations ≈ 14 permutations → ~142 permutations):
   ≈ 1.1 M constraints/input-note with optimized arithmetic, ≈ 6.7 M with
   general emulated. A 4-input bundle: ~4.5 M optimized — comfortable for
   Groth16 (seconds of proving, GBs of memory, same order as our Stwo
   outer-proof measurements); heavy but not fatal with general emulated.

## Decision

**Groth16 over BN254** for the M2 inner statement, with an optimized non-native
felt252 layer (custom limb-folding, 3×84-bit limbs, target ≤ 8 K constraints per
Poseidon permutation).

Rationale: client-side proving speed (the M4 phone requirement is the binding
constraint — 10× matters there), smallest proofs for calldata and outer
verification, and the strongest Cairo-verification path (Garaga's battle-tested
Groth16 verifier). The per-circuit trusted setup is accepted because (a) the
statement is **frozen** (spec freeze) — v2 ships exactly one circuit, so the
ceremony is a one-time, public, re-runnable event whose transcript we publish;
(b) the alternative (PLONK) buys setup convenience at 10× proving cost, which
the phone-provability requirement cannot afford. The setup posture (one
published per-circuit ceremony) is a documented public-facing property of the
pool (see Consequences).

PLONK remains the documented fallback if the Groth16 ceremony logistics fail or
if M2's optimized limb layer misses the constraint budget by enough to hurt
proving on mobile (PLONK's universal setup allows circuit iteration without
re-ceremony — valuable while the circuit is young).

## Alternatives considered

- **PLONK with universal setup** — rejected as primary: 10× prove time and 3×
  proof size vs Groth16 on the identical circuit; setup convenience is real but
  the frozen statement makes it less valuable. Kept as fallback.
- **Halo2** — no setup, but no cheap Cairo verifier today; would break the M3
  outer-block requirement.
- **Stwo-native small circuit** — no ZK mode yet; rejected (would stall M3 on an
  upstream roadmap item we do not control).
- **Skip the inner proof until Stwo ZK ships** — rejected for the same reason.

## Consequences

- M2 builds the statement circuit in a Groth16-compatible stack (gnark R1CS or
  circom) with a custom non-native felt252 layer; the golden reference vectors
  in `packages/pool/src/tests/test_hashes.cairo` are the correctness target
  byte-for-byte (circuit ↔ contract agreement).
- A one-time per-circuit setup ceremony must be planned before any mainnet
  deployment: circuit hash pinned, ceremony transcript published. Listed as a
  launch requirement (PLAN §M3/M4).
- The contract-side verifier seam (`IVerifier` in `packages/pool/src/spend.cairo`)
  gets a Garaga-style Groth16 verifier contract in M2; signature-stable — no
  pool changes needed.
- Follow-up benchmark (M2): witness/prove times on WASM/mobile for the real
  statement (feeds M4); Cairo verifier step count for the chosen proof shape
  (feeds the outer-block gas budget, spec §9.2).
