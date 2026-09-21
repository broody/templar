# ADR-0015: gnark multicommit ↔ Garaga incompatibility — custom limb layer becomes the production circuit path

- Status: Superseded by [ADR-0018](0018-stwo-private-proving.md)
- Date: 2026-09-20
- Deciders: broody
- Amends: ADR-0008 (M2 circuit stack), ADR-0014 (consequences — ceremony gating).

## Context

M2's reference circuit (`packages/circuit`) implements the §7 statement over
gnark's `std/math/emulated` non-native felt252 layer. While wiring the
on-chain verifier (ADR-0010: Garaga-style Groth16 verification on Starknet) a
hard incompatibility surfaced:

1. gnark v0.16.3's emulated package unconditionally uses `std/multicommit` for
   its deferred multiplication checks — a BSB22-style pedersen commitment
   inside the Groth16 proof, with the Fiat-Shamir challenge derived from it.
   There is no compile option to disable it.
2. Measured evidence: the exported verifying key has **34 IC entries**
   (32 public limb wires + base + commitment slot) and
   `PublicAndCommitmentCommitted` has one entry; `groth16.Setup` builds a
   pedersen key. gnark's own verifier requires exactly this layout.
3. Garaga's Cairo verifier (and its `calldata` tooling) is **vanilla Groth16
   only** — no commitment extension. Its pairing pre-check rejects the
   exported proof. No limb/one-wire reordering fixes this; the proof *shape*
   is unsupported.

So: any circuit built on gnark's general emulated package cannot be verified
by Garaga on-chain. The reference circuit is otherwise correct — solver-level
checks for ordinary (2/2/1) and controlled (1/1/1) bundles pass, and the full
Groth16 path works in gnark (12,553,351 constraints at 4/4/2; prove 17.8 s,
verify 1.6 ms on an 18-core desktop).

## Decision

1. **The production M2 circuit uses a custom felt252 limb layer** (plain R1CS
   constraints, no gnark emulated package, no committer) targeting ADR-0008's
   ~6–8k constraints per permutation. This was already the M4 performance path
   — the measured 12.55 M constraints / 17.8 s desktop prove for 4/4/2 is far
   over the phone budget — and is now also the verifier-compatibility path.
2. **The emulated-based circuit stays as the correctness reference**: golden
   vectors, binding encoding, and the adversarial battery are shared fixtures;
   the custom layer must match it byte-for-byte (`gen_fixture.py` is the
   oracle).
3. **Public inputs in the custom layer are 8 native BN254 wires** (every public
   felt252 < p_stark < r_bn254), keeping the pool's `IVerifier` payload at 8
   scalars — no seam change. (The emulated circuit's 32 limb wires were the
   other incompatibility surfaced; the custom layer must decompose publics
   in-circuit.)
4. **The Groth16 ceremony gates on the custom layer + audit.** Hand-rolled
   limb arithmetic is the classic circuit-bug class (missed range checks →
   soundness holes); ADR-0008's "audited custom limb-folding" language is now
   load-bearing, not aspirational.

## Alternatives considered

- **circom + snarkjs** (vanilla Groth16, Garaga's best-supported path): a full
  circuit rewrite whose big-int layer is the same custom work, with worse
  tooling for our test harness. Rejected — the limb layer is unavoidable
  either way; keep gnark.
- **Extend the verifier with the pedersen commitment check**: new
  cryptographic contract code — exactly what Garaga exists to avoid writing.
  Rejected.
- **Downgrade gnark** below the multicommit introduction: fragile, loses
  fixes. Rejected.

## Consequences

- M2's remaining work is the limb layer + diff-testing + Garaga integration
  (vk export → `garaga gen` → on-chain gas measurement → `set_verifier`).
- `packages/circuit` documents the gnark quirks found along the way (witness
  misalignment, `f.Select` non-reduction, `api.Or` booleanity, zero-value
  limbs) — they remain relevant to anyone touching the reference circuit.
- The finding itself is the deliverable to date: it is now impossible to
  reach the ceremony with an unverifiable circuit, and the performance and
  compatibility workstreams are unified into one.
