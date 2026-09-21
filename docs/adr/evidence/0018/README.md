# Evidence for ADR-0018

Recorded 2026-09-20. These are preserved measurement and validation records
from the isolated S-two experiments. They support the
[accepted architecture decision](../../0018-stwo-private-proving.md). The
[V1 follow-up](v1/README.md) demonstrates live Sepolia proof acceptance;
production integration and desktop qualification remain incomplete.

## V1 follow-up: live Sepolia success

The [preserved V1 records](v1/README.md) supersede the earlier conclusion that
Templar must wait for PROOF2. Genuine V1 proofs verified for ordinary,
controlled and maximum workloads, at 18.59–19.59 s request time and
13.50–14.34 GiB peak RSS under the same four-core / 16 GiB / no-swap limits.
The ordinary proof succeeded through the official gateway in block 15,357,460,
incremented the acceptance counter and emitted the expected binding. The
tested Zan estimator rejected V1 despite the successful live transaction.
See that archive for the actual receipt, provider limitations and scope.

## Current V2 service against Sepolia

The ordinary Templar fixture uses two inputs, two outputs and one withdrawal,
with depth-32 membership and the existing felt252/Poseidon format. The prover
ran on four physical i9-10980XE cores, under a 16 GiB cgroup limit with swap
disabled. The pipeline used stock allocation behavior.

- Prover tag: `PRIVACY-0.14.4-RC.0`.
- Sequencer commit: `0ee373ac5f50d475ab0efd59edbda4a9215c12cf`.
- Proving dependency: `2b495a36d57a4bd754cdfa1c2b5bda8d92b37ec3`.
- Rust nightly-2026-01-15, release, `-Ctarget-cpu=native`.
- Scarb/Cairo 2.18.0; Cairo 0 build dependency 0.14.3a3; sncast 0.63.0.
- Base block 15,355,440 on `SN_SEPOLIA`, Starknet 0.14.4.
- RPC: `https://api.zan.top/public/starknet-sepolia/rpc/v0_10`.

| Record | What it establishes |
|---|---|
| [summary.json](summary.json) | Timings, RSS, proof size/hash, caps and outcome |
| [prove-summary.log](prove-summary.log) | Request time and public proof outputs |
| [prover.log](prover.log) | Startup, virtual OS and recursive proving stage timers |
| [prover-cgroup.txt](prover-cgroup.txt), [prover-process-status.txt](prover-process-status.txt) | Memory limits, peak memory, CPU affinity and zero swap |
| [local-verification.log](local-verification.log) | Pinned V2 verifier accepts; modified output/program/proof rejects |
| [proof-output-validation.json](proof-output-validation.json) | Public values and message digest match the reference computation |
| [proof-estimate-raw.json](proof-estimate-raw.json) | Successful contract simulation and estimated gas/fee |
| [changed-binding-negative.json](changed-binding-negative.json) | Contract rejects a changed binding |
| [gateway-submission-response.json](gateway-submission-response.json) | Official Sepolia gateway rejects PROOF2 |
| [declaration-final-receipt.json](declaration-final-receipt.json), [deployment-final-receipt.json](deployment-final-receipt.json) | Successful test-contract setup on L2 |
| [count-after.json](count-after.json) | Zero accepted spends after attempted submissions |
| [base-block.json](base-block.json) | Chain version and proof base-block context |

The native verifier check used the same pinned sequencer's
`starknet_proof_verifier::verify_proof`. Its 123 ms timing was a separate local
check, not part of the capped prover request. RPC simulations skipped account
validation after adding proof facts to a captured query transaction; they are
not proof of live gateway acceptance. The live signed submission returned
`StarknetErrorCode.PROOF_VERSION_NOT_ALLOWED` both through Zan and directly from
`https://alpha-sepolia.starknet.io/gateway/add_transaction`. The test contract
holds no assets and did not exercise production token movement.

The first proving request used a stale block whose storage proof was already
pruned by the RPC. Refreshing to a current finalized block resolved it. The
upstream image also required a local rebuild because its binary used the
unsupported `vpermi2b` instruction. `sncast --dry-run` omitted proof fields;
proof-aware estimates therefore used direct RPC calls. These observations are
integration findings, not changes to proof security parameters.

## Earlier standalone experiment

[standalone-metadata.json](standalone-metadata.json) pins proving revision
`cd7bc5f4697fb188a27e09f9242f1dd76df8afdc` and hashes the reference and prototype
files. Its privacy-verifier root differs from the current V2 service. The
experimental staged allocation path preserved security parameters while
releasing the Cairo-stage tree and buffers before recursive proving.

| Case | Whole test time | Peak RSS | Raw record |
|---|---:|---:|---|
| Ordinary 2/2/1 | 11.74 s | 8.61 GiB | [standalone-ordinary.json](standalone-ordinary.json) |
| Controlled 1/1/1 | 11.89 s | 8.68 GiB | [standalone-controlled.json](standalone-controlled.json) |
| Maximum ordinary 4/4/2 | 12.00 s | 8.44 GiB | [standalone-maximum.json](standalone-maximum.json) |

All used four physical cores, a 10 GiB cap and zero swap. Whole-test time
includes proof generation, verification and teardown, while compilation and
initial PIE generation are excluded. These were standalone Cairo executions,
not the current virtual-OS service. Do not apply their lower RAM figures to
the current Sepolia route. [Public-binding checks](standalone-public-binding-checks.json)
record the matching scalar vectors and proof hashes.

## Provenance

[SHA256SUMS](SHA256SUMS) identifies the original V2 and standalone records;
[v1/SHA256SUMS](v1/SHA256SUMS) identifies the V1 follow-up. The records were
copied without modification from `/tmp/templar-stwo-privacy-dtgn6e8l` and its
`templar-eval` and `sepolia-test` subdirectories. Paths inside original logs and
metadata identify that experiment; the ADR's evidence links use this archive.
This is a results archive, not a self-contained build harness. Full proof,
source and build artifacts remain in the original experiment directory and
must be promoted separately when implementing M2. No account keys, signed
submission requests or private-witness files are included here.

Upstream rollout context: [V1/V2 protocol acceptance, PR #15120](https://github.com/starkware-libs/sequencer/pull/15120)
and [gateway version switches, PR #15122](https://github.com/starkware-libs/sequencer/pull/15122).
Both merged September 15; this does not establish the deployed gateway's
activation date or effective configuration.
