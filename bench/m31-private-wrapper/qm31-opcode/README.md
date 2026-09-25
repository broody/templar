# Native M31 arithmetic (the QM31 opcode): what it would buy

2026-09-24. Cairo has a native QM31 multiply-add opcode, with `core::qm31::{qm31, m31_ops}` on
top, and the Cairo verifier we use has a `qm31_opcode` build. Starknet does not allow the `qm31`
libfuncs in contract classes yet: the compiler warns that `qm31_unpack` is not in the default list,
and the sequencer allowlist (July 2026 snapshot) has no `qm31` entry. This experiment measures what
allowing them would change, using standalone Cairo runs and local virtual-OS captures, neither of
which enforces the allowlist.

**Bottom line:**
- **Server wrapping:** the opcode trims the bridge by about 25–30%, but the transaction still does
  not fit PROOF1. The limiting components are Blake2s and the calldata Poseidon, which the opcode
  does not touch.
- **One pool for both architectures:** a Poseidon2-M31 permutation drops from about 12k to about
  4.5k Cairo steps. That would bring an M31 spend in Cairo to roughly 0.5M steps (an estimate, not
  a measured spend), still about 2.5× the largest statement proved with PROOF1. A device-side
  PROOF1 path on the same M31 pool comes closer but is not shown: bounded-memory proving has not
  been run at that size, and PROOF1's per-component limits may bind before step count does.

## A. The R0 bridge and statement account, with and without the opcode

Same real R0 V3 client proof (`target/v3-transfer`); `bridge-r0v3` rebuilt with
`stwo_circuit_air/qm31_opcode` and `stwo_verifier_core/qm31_opcode`. Both runs produce the
identical binding, and the virtual OS emits the identical message.

| | Default | `qm31_opcode` |
| --- | ---: | ---: |
| Bridge, standalone: steps | 1,977,217 | 1,394,141 (−29%) |
| Bridge, standalone: range checks | 235,657 | 134,970 (−43%) |
| Statement account, CASM felts | 61,353 | 47,756 (−22%) |
| Virtual OS transaction: steps | 3,331,920 | 2,510,504 (−25%) |
| Blake2s compressions (PROOF1 budget 8,192) | 13,645 | 11,889 |
| … bootloader / OS / account bridge | 1,914 / 7,926 / 3,805 | 1,914 / 6,170 / 3,805 |
| Poseidon (proof calldata) | unchanged | unchanged |
| Components over 2²⁰ | `blake_g`, `cube_252`, `range_check_252_width_27` | the same three |

The OS's Blake share is almost all hashing the account's executed bytecode, which shrinks with the
smaller CASM. The account's own Blake is the client proof's Merkle openings, unchanged. Fitting
PROOF1 would still need about 3,700 fewer Blake compressions (for example fewer FRI queries plus
roughly another 30% less executed account code) and packed calldata for the Poseidon limit; see
`../server-log20/` for those levers.

Component sizes come from `capacity trace` and Blake attribution from `blake_sites` on each OS PIE
(`results/summary.json`).

## B. Poseidon2-M31 in Cairo

Width 24, 8 full and 22 partial rounds, x⁵, the pool's round constants; outputs checked against
the independent Python reference (`bench/m31-pool/gen_perm.py`) for one and two permutations.
Steps per permutation from runs of 2 and 11 permutations.

| Implementation | Steps per permutation |
| --- | ---: |
| Pool's unrolled felt252 arithmetic with lazy reduction (`perm_unrolled.cairo`, one tree node) | 12,172 |
| Generic loop over `stwo_verifier_core::M31`, default (`perm-probe`) | about 89,500 |
| Same, `qm31_opcode` | about 63,000 |
| **Straight-line on `m31_ops`, constants inlined (`perm-unrolled-probe`, 3,894 field ops)** | **about 4,500** |

The generic loop is dominated by array and constant-conversion overhead; the straight-line version
is the fair comparison. With the opcode, a permutation is about 2.7× cheaper than the pool's
optimized felt252 code and needs no range checks.

**An R0 spend in Cairo** hashes about 100 permutations: 64 tree nodes on two paths, four note
commitments of four permutations each, key, receiver, inner, nullifier and identity hashes. That
is about 1.2M steps with felt252 arithmetic, too large for PROOF1, but about 0.46M with the opcode.
Adding decoding and conservation, that is around 0.5M steps. This is an estimate from the measured
permutation, not a measured spend.

That is about 2.5× the largest statement proved with PROOF1, before the virtual OS adds its own
steps. The largest proved is the counted 16/16/8 shape, at 196,470 virtual-OS steps and 15.4 GiB
peak with the stock prover; the 32/32/16 (290,245 steps) and 64/64/32 (495,408 steps) shapes were
killed at the 16 GiB memory cap
([`native-counted-shapes`](../../native-counted-shapes/results/measurements.md)). Bounded-memory
proving has not been run at that size. Step count may not bind first either: PROOF1 also caps each
component, notably Blake2s at 8,192 compressions, and the OS hashes the executed bytecode with
Blake. For the R0 statement account that hashing alone took 7,355 compressions
(`../server-log20/`).

Pool gas would fall too: every on-chain commitment and tree append is dominated by these
permutations.

## Reproduce

```bash
cd perm-unrolled-probe && scarb build
echo '["0x2"]' > args.json && scarb execute --no-build --arguments-file args.json --print-program-output --print-resource-usage
# perm-probe: add --features qm31_opcode to compare the two field implementations
```

Part A rebuilt `target/bridge-r0v3` with the two features, ran `validate_bridge_proving.run` on
the real proof, captured each account with `client-port/capture_os.py`, then ran the
`server-log20` tools on the PIEs. The run directory is `~/.local/share/templar/runs/qm31-experiment`.
