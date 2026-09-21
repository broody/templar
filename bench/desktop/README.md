# Desktop feasibility experiment — 2026-09-20

**Result: native BN254 hashing is the preferred next implementation path.**
The experimental ordinary-payment circuit proves within a small fraction of the
6 GiB client ceiling and closes the deposit → invoice payment → recipient
withdrawal loop through a generated Garaga verifier. Keeping Starknet Poseidon
inside the pinned Noir/bignum stack fails the 32 GiB offline compilation budget
before a full-statement proof can be produced.

This is a pathfinding result, not an audited production implementation. The
production pool retains its existing hash/ABI. See [ADR-0017](../../docs/adr/0017-desktop-native-hash-pathfinding.md).

## Resource envelope and methodology

Target: a **16 GB desktop**, preferably ≤4 GiB client working set, hard ceiling
6 GiB; preferably ≤30 seconds preparation, maximum 60 seconds. Compilation is
an offline distribution/build step with a separate 32 GiB / 300 s ceiling.

`bench.py` runs each stage in a systemd user service with **MemoryMax=6G,
MemorySwapMax=0, CPUQuota=400%, CPUAffinity=0 1 2 3**, and a 180 s diagnostic
timeout. Compiler stages use MemoryMax=32G. The timeout is a diagnostic bound,
not the product's latency acceptance threshold. CPU IDs 0–3 are four distinct
cores on this i9-10980XE. bb uses HARDWARE_CONCURRENCY=4; Noir uses
RAYON_NUM_THREADS=4. Raw `/usr/bin/time -v` and systemd termination logs are
retained. Tests and offline code generation have separate budgets.

This constrains resources on an 18-core / 125 GiB host; it does **not** reproduce
a specific consumer CPU, thermal envelope or browser runtime. Native CLI only.
CRS is cached; first-download latency is excluded. The initial sweep overlapped
another compiler experiment, so its timings are indicative. The final 2/2/1
measurement was rerun after the large compiler jobs finished. Timings are
process wall times, not UI/network latency. Memory figures below are peak RSS
per process; enforced cgroup limits cover the whole launched process tree.

Toolchain: nargo 1.0.0-beta.16, bb 3.0.0-nightly.20251104, Garaga 1.1.0,
Scarb/Cairo 2.16.1, snforge/snforge_std 0.63.0. Full versions and artifact hashes
are captured in each `results/summary.json`. The production pool tests use its
existing Scarb 2.18.0 pin. All bb proofs use `ultra_honk --oracle_hash keccak`,
with ZK enabled. Changing the circuit hash does not change the transcript flavour.

## Measured client results

| Workload | Gates | Median prove | Peak prover RSS | Proof bytes |
|---|---:|---:|---:|---:|
| Starknet hash, 1 chained pair | 81,912 | 1.28 s | 175 MiB | see per-case summary |
| Starknet hash, 8 chained pairs | 630,138 | 9.18 s | 1,268 MiB | see per-case summary |
| Starknet hash, 16 chained pairs | 1,256,684 | 22.11 s | 2,502 MiB | see per-case summary |
| Native hash, 32 chained pairs | 2,424 | 0.10 s | 23 MiB | see per-case summary |
| Native hash, 256 chained pairs | 19,000 | 0.40 s | 55 MiB | see per-case summary |
| **Native ordinary 2/2/1, depth 32** | **12,965** | **0.26 s** | **39.2 MiB** | **8,256** |
| Native ordinary 4/4/2, depth 32 | 20,336 | 0.40 s | 56.9 MiB | 8,640 |

The native 2/2/1 circuit compiles in 0.15 s / 63.4 MiB, and witness generation
is 0.12 s / 59.7 MiB. Proof-to-Garaga-calldata generation takes approximately
2 seconds and ~104 MiB, so **complete native preparation is a few seconds**,
not just the 0.26 s proof number. Stage details: [flow-proving.json](results/flow-proving.json).
These memory measurements leave substantial room for an ordinary desktop app;
its complete runtime and distribution package still need measurement.

Both the 32-pair Starknet-hash case and the ordinary 2/2/1 emulated statement
were **OOM-killed by the 32 GiB compile limit**, after approximately 169 s and
195 s respectively. They used zero swap. No full-statement proving time or RAM
is claimed for that candidate. This is a result for this pinned implementation,
not a lower bound for all compilers or a proof that custom emulation cannot work.

The 4/4/2 native variant successfully proves a 2/2/1 witness under the larger
fixed shape. Its cost is modest here: shrinking the shape is useful but the
field choice is the dominant finding. The wide variant has native verification
only; the Cairo flow below uses 2/2/1. Neither experimental shape includes controllers.

## What the statement and flow actually enforce

The experimental format has recipient-side note-secret derivation, invoice
`inner` outputs, depth-32 membership, nullifiers, distinct inputs, u128 amount
bounds, single-token conservation, counts/zero padding, and an eight-field
public vector. The binding covers chain, pool, root, token, counts, nullifiers,
commitments, withdrawal amount and recipient. It uses the same note-domain tag
strings as the reference for comparison, but a separate protocol version
`TEMPLAR_DESKTOP1` and a different binding layout; it is **not wire-compatible**.

`fixtures.py` constructs Alice's two funded notes (700 + 400), Bob's invoice
(600), Alice's change (460), and a public withdrawal (40). Alice's proving
witness contains only her input secrets and output `{inner, amount}` invoices.
Bob's separate witness spends his 600 note. The recipients' private keys never
appear in Alice's witness. Tests use deterministic dummy keys and a shared test
relayer, not production wallet software.

`cairo/src/pool.cairo` is a deliberately minimal experimental harness: fixed
single token/verifier, internal tree writes, known-root and nullifier checks,
reentrancy guard, exact verification of all returned public inputs, and mock
ERC20 transfers. It omits production fees, events, bounded root history,
controllers and governance. It is kept under `bench/` to prevent confusing it
with the production pool.

## Cairo costs and end-to-end verification

The native hash uses the **pinned bb BN254 Poseidon2 parameters**, width 4,
8 full / 56 partial rounds, and a rate-3 sponge with input length in the
capacity (`len * 2^64`). Cairo arithmetic is generated using Garaga ModuloCircuit.
Python/Cairo vectors cover several lengths and near-modulus inputs; Noir and
Cairo also agree through the complete proved flow. Noncanonical u256 hash
inputs are rejected. Roots, commitments and nullifiers remain u256; there is
no modulo-felt252 truncation.

| Cairo measurement | L2 gas estimate |
|---|---:|
| 32 Starknet pair hashes, no storage | 424,384 |
| 32 native BN254 pair hashes, no storage | 50,474,956 |
| Setup-only prefix (deploy/init; not per payment) | 90,056,706 |
| Two funded deposits, net of setup | 153,441,764 |
| **Alice payment, net of funded setup** | **396,275,467** |
| **Bob withdrawal, incremental after Alice** | **271,134,283** |

The native hash is much more expensive in Cairo than Starknet's builtin. The
full-flow measurement captures that cost alongside actual proof verification
and state updates. Deltas subtract matching test prefixes; they are **not
production transaction fee estimates**. Account validation, calldata pricing,
production fee prices and transaction packaging are excluded. Do not add every
row: they overlap. No transaction was broadcast.

The tests use a local Sepolia fork pinned to block **15,348,508** for Garaga
maintained dependencies. Both fresh proofs verify through the deployed local
verifier and pool; the final token balances are 640 withdrawn and 460 remaining.
Replay and destination substitution reject. [Raw flow log](results/flow-tests.log).
The ordinary circuit also rejects wrong owner, inflation, duplicate input and
bad Merkle path witnesses. [Adversarial evidence](results/adversarial.json).

## Production correctness fixes included in this work

- Moved tree insertion out of the production ABI into the internal component
  trait; added the depth-32 capacity guard. Only the test mock exports a writer.
  Regression: direct insertion fails without changing count/root. Pool suite:
  **57 tests pass** (`results/pool-tests.log`).
- Changed the gnark reference output witness from recipient salt/key to invoice
  `OutInner`; fixtures contain no recipient secrets on the paying side.
  The corrected 4/4/2 reference has 12,000,740 constraints and passes ordinary,
  controlled and adversarial solver checks (`results/reference-tests.log`).
  Previously exported gnark proof/VK fixtures predate this circuit change.

These fixes do not resolve controller destination authorization, admin verifier
replacement, token behavior assumptions or all possible circuit bugs. The
prototype and its generated hash code have not been audited.

## Reproduce

Required tools are the pinned versions above, Python 3.12, Linux systemd user
services, and the Garaga venv (currently `/tmp/garaga-venv`, recreate if absent).
The host must permit setting CPU affinity to 0–3; adjust explicitly on another
machine and record the change. Commands below start at `bench/desktop`.

```bash
python3 generate_cases.py
python3 generate_statement.py
python3 fixtures.py
python3 sweep.py > results/sweep.log 2>&1
python3 bench.py statement-felt > results/statement-felt-driver.log 2>&1
# The previous command is expected to stop at its compile resource limit.
python3 bench.py statement-native
/tmp/garaga-venv/bin/python generate_cairo.py
# Regenerate the verifier if the circuit changed; its three source modules are
# also copied into cairo/src for the integrated pool tests.
garaga gen --system ultra_keccak_zk_honk --vk statement-native/results/vk --project-name desktop_verifier
cp desktop_verifier/src/honk_verifier*.cairo cairo/src/
cd cairo
# Use explicit installed toolchain paths on this workstation.
export PATH="/usr/bin:$HOME/.asdf/installs/scarb/2.16.1/bin:$HOME/.asdf/installs/starknet-foundry/0.63.0/bin:$PATH"
"$HOME/.asdf/installs/starknet-foundry/0.63.0/bin/snforge" test export_context > ../results/context.log 2>&1
cd ..
python3 prepare_flow.py
python3 bench.py statement-native
python3 prove_flow.py
python3 check_adversarial.py
cd cairo
"$HOME/.asdf/installs/starknet-foundry/0.63.0/bin/snforge" test flow_tests --detailed-resources > ../results/flow-tests.log 2>&1
cd ..
python3 generate_wide.py
python3 bench.py statement-native-wide
python3 report.py
```

`prove_flow.py` preserves separate proof/public/calldata files for both wallets.
`prepare_flow.py` binds their witnesses to the local test deployment addresses;
regenerate them whenever a contract change changes those addresses. The
machine-readable [report](results/report.json) links all per-case measurements.

The result supports further work on native hashing. Remaining decision work:
independent cryptographic review, production ABI/storage migration design,
real ERC20 and account transaction integration, production fee/limit measurement,
and an actual consumer desktop/runtime check. No mobile performance claim is made.
