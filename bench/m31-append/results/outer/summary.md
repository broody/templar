# Unchanged PROOF1 integration attempt

Status: **blocked before PROOF1 generation**. The public inner proof verifies in
Cairo and the unchanged virtual OS executes it, but the pinned outer prover
cannot complete this workload with its current fixed domain configuration.
There is no successful outer proof, original outer-verifier result, or local
contract settlement result from this experiment.

| Attempt | L2 gas allowance | Server cap | Observed result |
|---|---:|---:|---|
| `single` | 100,000,000 | 16 GiB | Account execution runs out of gas before proving |
| `verified/single` | 1,000,000,000 | 16 GiB | Virtual OS passes; cgroup OOM during Cairo proof generation |
| `cap64/single` | 1,000,000,000 | 64 GiB | Virtual OS passes; `Not enough twiddles!` during Cairo proof generation |

Directory names are attempt labels, not success assertions. The final attempt
used four pinned CPU workers, no swap, and a 600-second request timeout. Its
sampled process peak was **29.27 GiB RSS** and cgroup peak **29.24 GiB**. These
are failed server-run peaks, not completed proving requirements. The preceding
16 GiB OOM is not a measurement of the minimum required memory.

The successful virtual execution contained **8,062,701 Cairo steps**, 857,719
range checks, 22,409 Poseidon instances, and eight Pedersen instances. Its
recorded OS phase was 4.382 seconds. The later Cairo-proof stage failed before
recursive proof generation, serialization, or original proof verification.
These are single-run diagnostics, not latency distributions.

## Why adding memory is insufficient

The preserved `privacy_circuit_verify` configuration has Cairo trace log size20,
blowup log3 and lifting log23. Its recursive circuit has trace log21, blowup log2
and lifting log23. `prepare_recursive_prover_precomputes` therefore allocates
twiddles for log23. The panic checks that a requested polynomial domain fits
that allocation. Source also requires committed column domains to fit the
lifting size, and builds the recursive verifier from those fixed parameters and
preprocessed roots.

The observed panic establishes that a domain request exceeded the precomputed
capacity. The exact offending component has not been profiled. The configured
trace size is **not** a universal Cairo instruction-count limit: component rows
and VM steps are different quantities. Raising the twiddle allocation alone
would not establish compatibility with the unchanged PCS and recursive verifier.
Changing those verifier parameters would be a separately versioned experiment,
not a successful unchanged-PROOF1 result.

`summary.json` pins the relevant unchanged source files, binary-backed attempts,
configuration, and scope. The pinned outer prover and original verifier were
not patched. No weaker parameters or substituted proof facts were used.

## Consequence

Do not repeat the other four outer cases against this same capacity blocker.
The five native append proofs, standalone Cairo verification, and fixture
reconstruction remain useful evidence. The contract fixture stager and 14
contract tests remain unexecuted because authentic verified outer facts do not
exist yet. Fact injection alone would not satisfy that gate.

The next focused task is to profile the Cairo verifier's largest trace
components and determine whether it can fit the preserved outer capacity. If
that requires an impractical reduction, evaluate a supported larger or different
outer route explicitly. These server findings do not change the measured
17–31 MiB public client footprint and do not establish private-payment or browser
readiness. The state anchor is synthetic and local; no network finality or
full-node proof attachment was tested.
