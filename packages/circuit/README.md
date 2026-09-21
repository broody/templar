# TemplarPool v2 — inner spend statement circuit (M2)

The Groth16/BN254 circuit for the frozen spend statement (`docs/pool-v2-spec.md`
§7, shape per ADR-0014): up to 4 input notes / 4 output notes / 2 public
withdrawals per bundle, tree depth 32 (ADR-0013), V3 derivations
(ADR-0011/0012), single-token bundles, ordinary or controlled (§6).

## Layout

- `felt.go` — non-native felt252 (Starknet field) arithmetic over BN254 via
  gnark's general `emulated` package (4×64 limbs; ~47.5k constraints per
  Poseidon permutation — the ADR-0008 upper bound; the custom limb-folding
  layer targeting ~6–8k is M4-critical-path follow-up and needs an audit).
- `statement.go` — the `SpendStatement` circuit: derivation chain
  (note_secret → inner → commitment), Merkle membership, nullifiers,
  controller consistency, single-token conservation, padded statement binding,
  transition commitment (controlled bundles).
- `gen_fixture.py` — fixture generator; asserts the derivations byte-equal
  against `packages/pool/src/tests/test_hashes.cairo` (the contract/circuit
  agreement target) and builds both bundle shapes over a reference sparse tree.
- `statement_test.go` — solver checks for both shapes + adversarial battery
  (`TestSpendStatement`) and the heavyweight Groth16 setup/prove/verify
  (`TestSpendStatementGroth16`, ~12.6 M constraints — minutes, tens of GB).
- `cmd/exportvk` — exports a local-test verifying key + proof + public inputs
  for `garaga gen` (on-chain verifier). **Not** the ceremony artifact.
- `sponge_test.go` — sponge byte-agreement vs Cairo VM (arities 1..8) and the
  padded binding layout vs the fixture.
- `probe*.go`, `dump2_test.go` — debugging scaffolding for the gnark issues
  below; kept as regression probes.

## Run

```sh
python3 gen_fixture.py          # writes fixture.json (golden-asserted)
go test -run 'TestSponge|TestSelect|TestBinding' .   # fast
go test -run 'TestSpendStatement$' -v .              # solver-level, ~70 s
go test -run 'TestSpendStatementGroth16' -v .        # full setup+prove, heavy
go run ./cmd/exportvk                                # writes vk/proof/publics
```

## Known issues (gnark v0.16.3 workarounds — do not "clean up")

1. **Witness misalignment**: an array of emulated Elements declared before
   other Element witness fields shifts the witness vector (unsat on true
   witnesses). All Element arrays/slices go LAST in `SpendStatement`;
   `probe4_test.go` pins this.
2. **`f.Select` does not auto-reduce**: sponge outputs are lazy
   non-normal-form; `Reduce` before `Select` in the Merkle fold
   (`merkleFold`), or limbs silently carry unreduced values.
3. **`api.Or` boolean-constrains its inputs** — emulated limbs are not
   boolean; zero-detection must accumulate with `Add` (`isZeroEmulated`).
4. **Zero-value `emulated.Element` has nil limbs** — padded witness slots must
   be explicitly zero-filled (`buildAssignment` does this; missing slots fail
   with "can't set fr.Element with <nil>").
5. **`statement_binding` is hashed over the PADDED arrays + counts**
   (ADR-0014) — padded withdrawal slots absorb token `0` (selected), never the
   bundle token.

Groth16 public inputs are the 8 scalars (ADR-0014): protocol_version, chain_id,
pool_address, tree_root, controller, deadline, transition_commitment,
statement_binding.

## Invoice-output correction and desktop experiment (2026-09-20)

Input witnesses retain their owner key and salt. Output witnesses now contain
`OutInner` from the recipient's invoice; the paying wallet needs no recipient
private key or salt. Fixture outputs omit both fields. The adversarial suite
also rejects a substituted invoice inner against the fixed output commitment.
The corrected reference circuit has 12,000,740 constraints (4/4/2); previous
setup/VK/proof files predate this change and must not be used with this circuit.

The [desktop benchmark](../../bench/desktop/README.md) separately tests native
BN254 Poseidon2 and a real ordinary payment flow; it is not a production port.

## The hard boundary (ADR-0015)

The emulated-based circuit **cannot be the production circuit**: gnark v0.16's
`std/math/emulated` mul-checks unconditionally use `std/multicommit`
(BSB22-style pedersen commitment inside the proof), and Garaga's on-chain
verifier is vanilla Groth16 only. This package is the *correctness reference*;
the production circuit is the custom felt252 limb layer (plain R1CS, no
committer), diff-tested against these fixtures. The 12.55 M-constraint / 17.8 s
(prove) measurements here are the upper bound the limb layer must beat toward
the ~6–8k-constraints-per-permutation target.
