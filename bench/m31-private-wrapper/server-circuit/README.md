# Public server circuit and final-wrapper capacity

2026-09-22. **The specialized hash circuit produces a proof that verifies natively
and in Cairo. The unchanged PROOF1 prover still cannot wrap that Cairo execution:
its fixed twiddle/domain capacity is exceeded. No PROOF1 was produced.**

This is a capacity experiment for a future server verifier of the frozen
[private Blake client](../../m31-private-blake/README.md). It proves a representative
public hash workload, not the client's full Merkle/transcript/AIR/OOD/FRI checks.
It receives only messages extracted from the already-public proof; no note,
Merkle witness, masking seed or private key is passed to the server.

## Construction

The circuit uses the pinned `stwo-circuits` BlakeG and TripleXor AIR components.
The local `full_blake` helper preserves all eight 32-bit output words; upstream's
reduced-M31 `HashValue` helper would not match the client protocol. Each variable
input word is constrained to `(low16, high16, 0, 0)`. Boolean decomposition forces
partial-word padding to zero. Standard IV, ten rounds, counters and finalization
implement ordinary unkeyed Blake2s-256.

The representative batch contains 82 actual messages from retained Blake proof1:
one claims leaf, one trace leaf, sixteen small leaves and 64 internal nodes.
It covers 57,046 bytes and 934 compression calls. Unlike the earlier 954-call
cost fixture, these messages come directly from the completed Blake32/salt96
proof and use its real node digests.

The circuit additionally computes two bindings, requiring 942 more compressions:

```
input_binding  = Blake2s256(concat(u32LE(length_i), zero_word_pad(message_i)))
output_binding = Blake2s256(concat(Blake2s256(message_i)))
```

Lengths/order are fixed topology parameters. Both bindings are computed from
one set of variable message words and occupy sixteen packed-u32 public outputs.
Native verification checks them against a standard-library calculation. The
Cairo account verifies the circuit proof and emits a full-width digest binding
the trusted preprocessing root and all public outputs, plus its class, actual
chain and experiment domain. A separate Python calculation derives the exact
expected outer message from public jobs; proof claims do not set that expectation.

Preprocessing is built separately from `NoValue` topology and compared with
the concrete assignment circuit. The generated Cairo verifier pins its root,
all 45 preprocessing columns, sixteen outputs and full PCS config. Parameters
are the existing circuit configuration: PoW26, blowup-log2, 35 queries, fold4,
last-degree-log0, lifting22; interaction PoW20. No client parameter changes or
unproved host acceptance flags are introduced.

## Measurements and outcome

One native run, four pinned CPU workers, 16GiB cap, no swap:

| Stage | Result |
| --- | ---: |
| Server circuit proving | 6.753 s |
| Native circuit proof verification | 2.16 ms |
| Native process peak RSS | 3.534 GiB |
| Circuit trace | log20; padded BlakeG component log18 |
| Cairo proof encoding | 46,596 felts |
| Standalone Cairo verification | 5,018,523 steps; 0.780 GiB peak RSS |
| Standalone Cairo execution harness | 2.495 s |
| Virtual OS execution | 7,301,958 steps; 4.571 s |
| Final PROOF1 attempt | **Failed: `Not enough twiddles!`** |
| Final prover process peak RSS | 34.353 GiB under a 64GiB cap |

The final run used the exact preserved transaction-prover binary and synthetic
state reconstructed by the pinned sequencer helper. There was zero swap and no
OOM. The failure is the existing domain-versus-precomputed-twiddle assertion,
not a memory-cap termination. Because no proof was produced, the original
PROOF1 verifier and its fact/proof mutation checks were not reached. No network
transaction, Sepolia acceptance or node attachment is claimed.

The extra proof layer moves the hash work into an intermediate S-two circuit,
but its generic Cairo verifier still exceeds the preserved final wrapper's
capacity. This fails before scaling to all 43,166 cached authentication
compressions or adding the remaining membership verifier checks. Raising RAM
alone will not resolve this assertion; another unchanged run is unwarranted.

**Next gate:** identify the Cairo bridge's dominant trace components and reduce
that cost, or establish a supported final-wrapper configuration with sufficient
capacity and the corresponding verifier compatibility. Resolve that boundary
before implementing the complete client verifier in this circuit. The measured
client remains unchanged: the server RSS above is not browser memory.

## Validation and review

Five tests pass: two existing config/wire fixtures and three new circuit tests
covering thirteen message lengths, high digest bits, malformed word limbs and
upper coordinates, invalid padding, altered output/G-result wires and topology
independence from message contents. Assignment mutations use native semantic
`Circuit::check`; the corresponding AIR constraints were independently inspected.
They are not presented as malicious-trace AIR prover tests.

Native proof verification rejects four mutations. Cairo independently accepts
the saved proof with its exact expected output and rejects seven mutations:
output, interaction nonce, config, trusted root, trace root, trailing and
truncated data. The [postimplementation review](../server-circuit-review.md)
found no source blocker for this public workload and explicitly records the
failed final capacity gate. This is research evidence, not a production audit.

[Consolidated results](../results/server-circuit/summary.json),
[native proof](../results/server-circuit/proof/report.json),
[Cairo validation](../results/server-circuit/cairo-validation.json),
[final attempt](../results/server-circuit/outer/report.json).

## Reproduction

Use the recorded source/binary pins and build logs in
`../results/server-circuit/`. Rust uses the pinned nightly2026-01-15 toolchain;
Cairo uses Scarb2.18.0. `prepare_server_jobs.py` reconstructs and checks the exact
public batch. Build this crate with `--release --locked --offline`, then run
its binary with `jobs.json` and a fresh output directory. `measure_server.py`
records the exact command, CPU/memory limits and process peak.

`build_server_bridge.py` copies the preserved Cairo vendor into an isolated
ignored build tree and regenerates only its two topology files from the trusted
build manifest. `prepare_server_outer.py` recomputes expected bindings;
`validate_server_bridge.py` runs the positive and negative Cairo cases.
`run_server_outer.py` retains byte-pinned outer binaries and exact fact checks.
Saved commands/fixtures describe the failed run; do not rerun it until a
capacity-relevant implementation change has been made.


The [bridge capacity follow-up](../bridge-capacity/README.md) now records a
15.37% Cairo step reduction from checked M31 inversion and passing proof
regressions. Expanded trusted geometry builds, but its actual proof run OOMs
under a96GiB server cap. This remains a public hash-circuit result; no new
outer proof or full membership verification has been established.
