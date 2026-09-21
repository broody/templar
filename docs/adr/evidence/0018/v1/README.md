# PROOF1 evaluation on Sepolia 0.14.4

Recorded 2026-09-20 for [ADR-0018](../../../0018-stwo-private-proving.md).

## Result

A genuine V1 S-two recursive ZK proof of the ordinary Templar spend statement
was accepted by the official Sepolia gateway, executed successfully on L2,
incremented the test contract's acceptance counter to one and emitted the
expected binding. This is a demonstrated V1 route, not a relabeled V2 proof.

- Transaction: [0x27eaa862…90c5f85](https://sepolia.voyager.online/tx/0x27eaa86230d34e8a2874ec93d0c91027d782cd2d896f7f6bde9added90c5f85).
- Block: 15,357,460; `ACCEPTED_ON_L2 / SUCCEEDED`.
- Contract: `0x053dc37e936254b8ed9ef597ddd8e84504ea43ee53c128b3869cb322b45fabf2`.
- Class: `0x05f568449caecc9a116012e2e4b110b9689d4dca702fd0bcdfcce923fcde9328`.
- Actual fee: approximately 1.48924712 test-STRK; 77,423,200 L2 gas,
  zero L1 gas and 384 L1 data gas.
- Submission: `https://alpha-sepolia.starknet.io/gateway/add_transaction`.

The contract is an asset-free acceptance sink. It checks the proof-facts
version, virtual OS, statement class/context, message binding and replay map.
It does not implement the production pool's root/nullifier state, controller
authorization, deadline enforcement or token movement. The controlled fixture
tests the private statement's controlled branch, not real controller signatures.

## Measurements

Unmodified upstream allocations; four physical i9-10980XE cores, CPU affinity
0–3, a 16 GiB cgroup limit and zero swap. Each workload used a fresh service
process with one proving request and no remote private-witness prefetch.

| Case | Request | Virtual OS stage | Proving stage | Peak process RSS | Proof bytes | Local verification |
|---|---:|---:|---:|---:|---:|---:|
| Ordinary 2/2/1 | 18.592 s | 5.929 s | 12.631 s | 13.50 GiB | 237,232 | 155 ms |
| Controlled 1/1/1 | 18.844 s | 6.483 s | 12.326 s | 13.98 GiB | 239,116 | 161 ms |
| Maximum ordinary 4/4/2 | 19.588 s | 6.469 s | 13.083 s | 14.34 GiB | 236,518 | 172 ms |

Request time includes RPC state reads and virtual OS execution. Compilation,
fixture preparation, startup (1.42–1.46 s) and local verification are separate.
The verifier check was outside the capped prover process. RSS comes from
Linux `VmHWM`; cgroup peaks and limits are recorded separately. These are
single runs on a larger host, not qualification of a physical 16 GiB desktop.
The memory headroom remains too small to assume comfortable everyday use.

Every proof's eight public values, class and message hash matched the reference
computation. The pinned cryptographic verifier accepted each proof and rejected
changed message digests, program hashes and corrupted proof bytes. Only the
ordinary proof was submitted on-chain.

## Version and build provenance

- Prover tag: `PRIVACY-0.14.3-RC.2`.
- Sequencer: `e6b6fd2e9932909107833579e5b6efd6c75fa0af`.
- Proving-utils: `3035dd00421daa541894297bd754db6e2787807b`.
- S-two: `489a0f3ee44a59e03944ad9aa4f3e5a91a3d3f08`.
- S-two Cairo: `9b6be2710e4d7124bc93fe80a5af36556d42ed29`.
- S-two circuits: `5ef951a12727e3489a2ee991c580a5b925c59c69`.
- Virtual OS: `0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1`.
- Rust nightly-2026-01-15, release, `-Ctarget-cpu=native`, original lockfile.
- Scarb/Cairo 2.18.0 for the test contract; sncast 0.63.0 for signing.
- Cairo 0 build dependency: 0.14.3a3.

The pinned [V1 privacy prover](https://github.com/starkware-libs/proving-utils/blob/3035dd00421daa541894297bd754db6e2787807b/crates/privacy_prove/src/lib.rs)
calls `add_zk_blinding` in the recursive privacy pipeline. The local check used
the same sequencer revision's `starknet_proof_verifier::verify_proof`, which
dispatches PROOF1 to its V1 verifier. Source and binary hashes are preserved.
This records the intended ZK construction, not an independent privacy audit.

The prebuilt V1 image exited with code 132 / signal 4, without an OOM. Rebuilding
the unmodified source for the host succeeded. A portable CPU baseline still
needs qualification. The build used a separate 24 GiB cap; runtime measurements
used 16 GiB. The original V2 source and binaries were left intact.

## RPC findings and incomplete negative checks

State reads and the successful receipt were served by
`https://api.zan.top/public/starknet-sepolia/rpc/v0_10`. Its fee estimator
rejected PROOF1 as disallowed under its protocol configuration, even though
the official gateway subsequently accepted it. The version guard prevented
the attempted changed-binding simulation from reaching the contract.

The Cartridge `v0_10` endpoint reported spec 0.10.2 and returned
`PROOF_FACTS_LENGTH` in replay and changed-binding estimates despite proof
fields in the request. Those responses do not establish that the intended
replay or binding branches were exercised. A missing-facts request also failed
with `PROOF_FACTS_LENGTH`, as expected. Contract-level replay and binding
mutation tests remain to be run through a compatible environment.

`sncast --dry-run` omitted proof fields in the earlier V2 investigation, so
this run captured a signed proof-bearing transaction locally and submitted
that transaction directly to the official gateway. Maximum fee exposure was
bounded below four test-STRK. No private witness was submitted to the gateway;
the submitted payload contained the proof, public facts and public call data.

## Archived records

| Record | Purpose |
|---|---|
| [summary.json](summary.json), [source-pins.json](source-pins.json) | Measurements, binary/source fingerprints and scope |
| [ordinary/benchmark.json](ordinary/benchmark.json), [controlled/benchmark.json](controlled/benchmark.json), [maximum/benchmark.json](maximum/benchmark.json) | Per-case timings, RSS, proof hashes, public facts and messages |
| [ordinary/local-verification.log](ordinary/local-verification.log), [controlled/local-verification.log](controlled/local-verification.log), [maximum/local-verification.log](maximum/local-verification.log) | Positive and adversarial cryptographic checks |
| [ordinary/proof-output-validation.json](ordinary/proof-output-validation.json), [controlled/proof-output-validation.json](controlled/proof-output-validation.json), [maximum/proof-output-validation.json](maximum/proof-output-validation.json) | Public/reference binding checks |
| [gateway-submission-response.json](gateway-submission-response.json), [accept-final-receipt.json](accept-final-receipt.json) | Live gateway acceptance and successful L2 execution |
| [accept-validation.json](accept-validation.json), [count-after.json](count-after.json) | Expected binding event and resulting counter |
| [declaration-final-receipt.json](declaration-final-receipt.json), [deployment-final-receipt.json](deployment-final-receipt.json) | Successful contract setup |
| [proof-estimate-raw.json](proof-estimate-raw.json), [changed-binding-negative.json](changed-binding-negative.json) | Zan rejects V1 before the intended execution check |
| [cartridge-replay-negative.json](cartridge-replay-negative.json), [cartridge-changed-binding-negative.json](cartridge-changed-binding-negative.json) | Cartridge simulations do not supply usable facts to the contract |
| [missing-proof-facts-negative.json](missing-proof-facts-negative.json) | Contract rejects absent facts |
| [prebuilt-startup.json](prebuilt-startup.json), [cleanup.json](cleanup.json) | Image startup failure and experiment cleanup |

Each case directory also contains its finalized base-block header, service
log and cgroup limits/peaks. [SHA256SUMS](SHA256SUMS) covers all archived files.
Records were copied from
`/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test`; generated benchmark records
summarize the raw sampler and service logs there. Full proof binaries, source,
harness and raw samples remain in that directory. This archive contains no
account keys, signed submission requests or private-witness files, and is not
a self-contained reproduction harness. Promote that harness during integration.
