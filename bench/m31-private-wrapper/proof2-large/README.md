# PROOF2 large-path wrapping

2026-09-23. **The measured bridge workload produces a genuine PROOF2 through
Starknet v0.14.4's large-proof path in 138 s at 61.4 GiB peak RSS.** The
proof is accepted by the V2 recursive-circuit verifier that the sequencer
uses, and three altered inputs are rejected. The same workload OOMed at
96 GiB with the enlarged PROOF1 geometry and does not fit PROOF1's log20.

This is the public hash-batch bridge, not the complete private-client
verifier. The PIE comes from a synthetic local fixture, so its facts are not
submittable to Sepolia. No network transaction was sent.

## Results

Both runs used `proving@2b495a3` (the commit linked from the
[v0.14.4 prerelease notes](https://community.starknet.io/t/starknet-v0-14-4-prerelease-notes/116341)),
`privacy_prove::privacy_recursive_prove_large`, a 105 GiB cgroup cap, zero
swap and four pinned workers (`run.sh`).

| | StarkWare sample tx | Templar optimized bridge |
| --- | ---: | ---: |
| Cairo steps (privacy bootloader) | 275,933 | 6,405,669 |
| Leaf verifier | log25 | log25 |
| Prove wall time | 87 s | 138 s |
| Peak RSS | 42.1 GiB | 61.4 GiB |
| Proof bytes (gateway cap 480,000) | 249,312 | 252,319 |
| V2 verification | accepted, 0.10 s | accepted, 0.10 s |
| Rejects changed output / flipped byte / truncation | yes / yes / yes | yes / yes / yes |

The sample is `crates/privacy_prove/test_data/privacy_tx_cairo_pie.zip` from
the same commit. Its cost is roughly the floor of any large proof, since the
smallest leaf verifier is log25. The Templar input is
`results/bridge-capacity/optimized/os-capture/os.pie.zip` (virtual OS program
hash `0x53f6…daa1`, allowed by 0.14.4). Peak RSS comes from `/usr/bin/time`;
the systemd cgroup peak line is not meaningful for this wrapper.

## What PROOF2 is

Sequencer main verifies V1 through `proving-utils` and V2 through
`proving@2b495a3`. V2's `verify_recursive_circuit` accepts either the small
log20 root or a leaf verifier from `large_proofs_circuit_registry.json`
(Cairo trace log25–29, ZK blinding on; Cairo blowup log1, 70 queries,
fold 1). Versioned constants: 0.14.3 allows PROOF1 only; 0.14.4 and 0.14.5
allow PROOF1 and PROOF2. Sepolia ran 0.14.4 and mainnet 0.14.3 on
2026-09-23; mainnet's 0.14.4 upgrade is scheduled for 2026-10-05 pending
governance. The official Sepolia gateway rejected PROOF2 on 2026-09-20
while already on 0.14.4, so gateway acceptance is a separate rollout switch
(sequencer PR #15122).

## Blake attribution for the small path

`blake-attribution/` tags each of the 17,557 Blake compressions in the
optimized replay by issuing code segment: bootloader hashing the virtual OS
program 1,914; virtual OS 10,340, dominated by the compiled-class hash of the
account's executed bytecode segments (193 of 273 segments, 73,898 of 79,033
felts); the bridge verifier itself 5,303. This corrects
`results/bridge-capacity/os-attribution/README.md`, which attributed the
dominant share to `compute_program_hash_chain` over the account. Those
numbers matter only for fitting the cheaper log20 path.

## Open

- Gateway acceptance of PROOF2 on Sepolia and mainnet, checked by an actual
  submission with authentic chain state.
- Cost with the complete private-client verifier in the bridge.
- Repeated runs and an independent-verifier check of the saved proof bytes.
