# ADR-0016 benchmark: Noir + UltraKeccak-ZK-Honk

**Small-circuit loop verified, 2026-09-20.** The felt252-Poseidon Noir circuit
passes its Cairo golden vector, bb native verification, and the generated
Garaga verifier in a local snforge Sepolia fork. Full-statement scaling is
unresolved. This is evidence for [proposed ADR-0016](../../docs/adr/0016-noir-honk-feasibility.md),
not a production stack migration or a deployed transaction.

## Circuit and toolchain

`src/main.nr` implements Starknet Poseidon over `2^251 + 17*2^192 + 1`, using
noir-bignum `BigNumParams<3, 252>` with three 120-bit limbs. `hash_pair` matches
`poseidon_hash_span([1,2])` and executes two permutations. Its public output is
three limbs, not the production pool's eight scalar public inputs. This is a
hash microbenchmark, not the M2 membership, authorization, nullifier and balance statement.

| Component | Version |
|---|---|
| nargo | 1.0.0-beta.16 (`2d46fca7203545cbbfb31a0d0328de6c10a8db95`) |
| bb | 3.0.0-nightly.20251104 |
| Garaga Python and Cairo | 1.1.0 |
| noir-bignum | vendored v0.9.2; incompatible test/benchmark module declarations removed |
| Scarb / Cairo | 2.16.1 |
| snforge | 0.63.0 |
| generated snforge_std | 0.57.0 (runner warns about version mismatch; test passes) |

The Noir/bb pairing agrees with [Garaga's release notes](https://github.com/keep-starknet-strange/garaga/releases).
Do not substitute the latest bb: serialized VK/proof layouts differ across versions.
ZK is enabled by default in this bb; no `--disable_zk` flag is used.

## Measured results

Host: Intel i9-10980XE, 18 cores / 36 logical CPUs, 125 GiB RAM, Linux x86_64.
`HARDWARE_CONCURRENCY=32`; three runs with cached CRS. The separate scale
compilation occupied one core during the runs, so this is not an idle-host benchmark.

| Metric | Two-permutation golden circuit |
|---|---:|
| ACIR opcodes | 35,185 |
| bb circuit_size (unpadded gates) | **81,889** |
| Padded domain, from VK log size 17 | 131,072 |
| Gates / permutation (includes shared overhead) | 40,944.5 |
| `bb prove` wall time | **0.653 s median**, runs 0.653 / 0.648 / 0.659 s |
| Prover peak RSS | 211,436–212,056 KiB (~207 MiB) |
| Proof | **9,408 bytes**, 294 field elements |
| Separate public inputs / VK | 96 / 1,888 bytes |
| Garaga calldata, including hints | **3,051 felts** (97,632 bytes at 32 bytes/felt) |
| Native verification | Passed on all three proofs |
| Tampered public input | Native verifier rejects, exit 1 |
| Garaga fork verification | Passed; checks all three returned hash limbs |
| snforge L2 gas estimate, fresh fixture | **269,913,831 (~269.9 M)** |

Timing includes proving-key construction inside `bb prove`; it excludes Noir
compilation, witness generation, separate `write_vk`, native verification,
calldata generation and CRS download. Raw timings, versions, sizes and hashes
are in [results/summary.json](results/summary.json); `/usr/bin/time -v` logs
are retained beside it. `out/test.log` retains the golden-vector test output.

The fork is pinned to Sepolia block **15,348,508**. The test uses a local
library dispatcher and forked Garaga dependencies. Gas is the test's Sierra
execution estimate, including harness/assertion work; it excludes transaction
account overhead, deployment, pool logic and real calldata/DA fees. Its zero
L1 gas fields do not establish a zero L1 fee for a submitted transaction.
No live transaction was sent. Freshly regenerated verifier sources matched
`honk_verifier/src` byte-for-byte (`results/honk_verifier/src`). The inherited
proof fixture measured ~270.35 M gas; the fresh ZK proof has different hints
and measured ~269.91 M. These are fixture-specific estimates.

## Scaling and implications for ADR-0016

The inherited `../adr16-scale` experiment chains 64 hashes (128 permutations).
Its `nargo compile` was stopped after **9m12s at ~99.3 GiB RSS** to avoid
exhausting this host, before any compiled artifact or proof was obtained.
See [compile-attempt.json](../adr16-scale/results/compile-attempt.json).
This is a compiler resource observation, not prover memory or a completed scaling measurement.

The earlier draft's 5.02 M gates, ~22 s proving, ~11.5 KB proof and native
verification success for that circuit had no retained supporting artifacts;
they are withdrawn. So are the derived ~60 s full-statement prediction and
laptop slowdown claims. A smaller scale sweep or compiler/memory investigation
is needed before making full-statement latency claims.

The generated verifier explicitly specializes on `log_circuit_size` and loops
over it. The measured gas cannot be asserted constant for larger circuits or
more public inputs. Regenerate and measure at each size.

Honk removes the need for a **new per-circuit ceremony**, but still depends on
a trusted universal KZG SRS. It is not trust-free; see the
[Aztec Ignition ceremony and its trust assumption](https://github.com/AztecProtocol/ignition-verification).
Also, `bb prove --scheme ultra_honk --oracle_hash poseidon2` still produces
Honk, not Groth16. This benchmark supplies no Noir-to-Groth16 fallback or
measured Groth16/Honk gas ratio.

The successful microbenchmark establishes Garaga compatibility. It does not
establish production soundness, an audited limb implementation, full-statement
feasibility, or phone feasibility. M4 remains as currently recorded in PLAN.md;
dropping it requires a separate explicit decision.

## Reproduce

Use the versions above. On this machine Garaga is installed at
`/tmp/garaga-venv/bin/garaga` (a temporary location; recreate the venv if absent).

```bash
export PATH="$HOME/.nargo/bin:$HOME/.bb:/tmp/garaga-venv/bin:$PATH"
cd bench/adr16
nargo test
nargo execute witness
python3 measure.py

# Generate separately so local test configuration is preserved.
cd results
garaga gen --system ultra_keccak_zk_honk --vk vk --project-name honk_verifier
cd ..
diff -qr results/honk_verifier/src honk_verifier/src
garaga calldata --system ultra_keccak_zk_honk --proof results/proof \
  --vk results/vk --public-inputs results/public_inputs \
  --format snforge --output-path results
cp results/proof_calldata.txt honk_verifier/tests/proof_calldata.txt
cd honk_verifier
export PATH="/usr/bin:$HOME/.asdf/installs/scarb/2.16.1/bin:$HOME/.asdf/installs/starknet-foundry/0.63.0/bin:$PATH"
"$HOME/.asdf/installs/starknet-foundry/0.63.0/bin/snforge" test --detailed-resources
```

The explicit paths avoid an old `~/.local/bin/snforge` 0.20.0 and a `~/bin/cc`
shim. The fork requires the configured public RPC endpoint to be available.
`measure.py` accepts `--project`, `--name`, and `--runs` for future scaling
experiments, once their bytecode and witness have been generated.
