# Bridge optimization and enlarged-wrapper capacity

2026-09-22. **Checked M31 inversion reduces execution by about 15%, but an
enlarged final wrapper exhausts a 96 GiB server cap before producing a proof.**
This is an isolated public hash-circuit experiment. It does not prove private
membership or payments, change the client prover, or establish new PROOF1
acceptance. Production code and the preserved prover/verifier are unchanged.

## Measured results

| Stage | Baseline | Checked-inverse bridge |
| --- | ---: | ---: |
| Standalone Cairo verification | 5,018,523 steps | 4,247,207 steps (15.37% less) |
| Actual virtual OS execution | 7,301,958 steps | 6,206,195 steps (15.01% less) |
| Proof checks | Valid + 7 rejections | Same valid output + all 7 rejections |

The optimized executions overlapped a build, so their wall time and RSS are
not comparable benchmarks. Step counts are deterministic execution counts.
The [K3 validation](../results/bridge-capacity/optimized/k3-validation/README.md)
also records two direct inversion tests: boundary values/products and zero
rejection. The account was recompiled into a fresh synthetic authenticated
state fixture; actual OS execution emitted the exact expected class, domain,
chain and full digest. No network transaction was submitted.

The [baseline profile](../results/bridge-capacity/profile/pass3/README.md)
attributes 27.49% of execution inclusively to M31 inversion. `setup_optimized.py`
copies the baseline Cairo workspace and replaces Fermat exponentiation with
Cairo's checked `u256_inv_mod`. It retains zero rejection, canonical conversion
back into M31 and an explicit `x * inverse == 1` check. The standard primitive's
multiplication guarantees remain verified; there is no unchecked hint result.
Proof parameters, transcript, statement and trusted server-circuit root stay
the same. The new account class hash changes with its implementation.

## Why the old capacity is still insufficient

`capture.rs` compiles the preserved runner modules verbatim and saves their
actual virtual-OS PIE. `capacity.rs trace` replays the original privacy
bootloader and generates actual AIR columns without attempting a proof. The
[baseline trace](../results/bridge-capacity/trace-baseline/claim.json) has
log22 components, including BlakeG, cube252 and a range-check component.
Several instruction components reach log21. General Cairo step counts alone
do not describe this capacity requirement.

The optimized replay still has **17,557 Blake compression instructions**,
with no generic or QM31 opcode. Padding cascades through compression, round
and G components: 17,557 compressions pad to 32,768, their ten rounds pad to
524,288, and eight G operations per round require 4,194,304 rows (log22).
Consequently this bridge cannot fit the preserved log20 configuration merely
by lowering its instruction count. The source-derived minimum in the older
full-workload analysis remains a lower bound, not an exact padded trace size.

## Larger geometry experiment

`setup_large.py` makes isolated copies of the pinned Cairo and circuit
dependencies. It extends the small preprocessing variant with sequence21
and sequence22, updating all four metadata sites: 158 columns and 16,453,232
cells. Roots are rebuilt from public preprocessing, never supplied by a proof.
The helper accepts only the ceiling supported by its linked variant (original
log20 or experimental log22).

The new Cairo configuration has trace22/lifting25. Its generated recursive
verifier circuit has trace22/lifting24 and a new trusted root. Blowup, query
counts, grinding, interaction checks and the fixed privacy-bootloader program
are retained. This is **a different trusted verifier configuration**, even
though the research serializer uses the upstream version envelope.

Generating the [trusted geometry](../results/bridge-capacity/large/shape/config.json)
succeeded in 3.52 seconds with 2.94 GiB peak RSS. The subsequent actual run used
the optimized captured OS execution, four pinned CPU workers, a 96 GiB cgroup
cap, no swap, and polynomial-coefficient retention disabled. It was
**OOM-killed after 71.26 seconds**, with sampled process peak 95.79 GiB and
cgroup peak 96.00 GiB. No Cairo proof or final recursive proof was produced.
[Run evidence](../results/server-circuit/capacity-prove-log22-optimized/summary.json).

The configured serialized-proof verifier and its five rejection controls are
implemented but unexecuted because generation did not finish. No compatibility
result for a larger proof is claimed. The separate `stock.rs` helper links
preserved original dependencies; it accepts the known earlier PROOF1 positive
control. Its JSON boolean, not its process exit code, reports acceptance.

## Reproduction and next decision

Scripts use this workspace's pinned local dependency/toolchain paths. Build
`capture`/`capacity`/`stock` with `build.py KIND --out FRESH_DIR` for original
dependencies. Run `setup_optimized.py` in a fresh target, then build its bridge
and account with Scarb 2.18.0. Saved commands under each result directory show
the validation and authenticated execution inputs.

For the larger variant, run `setup_large.py`, then Cargo with the pinned
nightly2026-01-15 toolchain, `RUSTFLAGS='-C target-cpu=native'` and an isolated
target directory. Use `capacity shape 22 OUT` for trusted geometry and
`capacity prove 22 CAPTURED_PIE OUT` for the actual attempt, through the bounded
measurement runner. The measured source and dependency/input identities are
retained under `results/bridge-capacity/large/`; a later argument guard leaves
the measured log22 computation unchanged.

Both requested experiments are complete. Raising the geometry alone has not
made this bridge practical. Further work should target proof serialization,
OS hashing/padding and the generic Cairo prover's retained allocations before
another large run. Proof-calldata packing is a concrete candidate: the current
46,597-felt payload drives substantial public OS hashing, but its benefit and
remaining Blake limit have not been measured. Full client-verifier integration
remains an open milestone.

[Consolidated postimplementation review](../bridge-capacity-review.md).
