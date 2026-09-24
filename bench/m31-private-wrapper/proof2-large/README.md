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

## Bounded memory (2026-09-24)

**The large path now runs at 28 GiB instead of 51 GiB, with byte-identical proofs**: +9% prove
time, fitting a hard 30 GiB cap (zero swap). This is the client's coefficient-backed PCS mode
(`bench/bounded-memory`, ported to the client fork), applied to both server stages: the Cairo leaf
proof and the Cairo-verifier circuit proof.

The branch `templar/bounded-server` starts at `proving@2b495a3`, the commit the sequencer's V2
verifier pins. It carries no arithmetic-profile or blinding changes, so the registered circuits
are untouched. Its patches are in `bounded/`:
- `0001`, `0002`: the PCS port, conflicts resolved for this commit, with a test that bounded proofs
  equal unbounded ones field for field;
- `0003`: `prove_cairo_bounded`, `prove_leaf_bounded` and `privacy_recursive_prove_large_bounded`,
  plus the `prove_large` harness. The existing functions are unchanged. `prove_leaf` also drops
  the Cairo VM runner after the adapter.

`run.sh` now uses this build with 16-column FRI batches by default;
`TEMPLAR_BOUNDED_CAIRO_COLUMNS` and `TEMPLAR_BOUNDED_CIRCUIT_COLUMNS` override the batch size, and
0 restores default storage. `bounded.py` runs one proof under a cap and samples the cgroup twice a
second, attributing each sample to a prover stage from the span log.

All runs below used the policy-note release PIE (3.41M virtual-OS steps, log25 leaf), four pinned
cores, a 115 GiB cap unless stated, and zero swap. Every proof verified, and every completed
bounded proof is byte-identical to the default-storage proof ([results](results/bounded/)).

| Storage | Peak RSS | Prove time |
|---|---:|---:|
| Default | 51.1 GiB | 111.6 s |
| Bounded, FRI batch 16 | 29.1 GiB | 121.3 s |
| Bounded, batch 16, runner dropped early | 28.3 GiB | 122.1 s |
| Same, batch 4 / batch 64 | 27.8 / 28.3 GiB | 123.1 / 120.8 s |
| Same, hard caps | passes at 32G and 30G; killed at 28G and 26G | |

Where the memory goes, default → bounded (peak GiB in each interval):

| Interval | Default | Bounded |
|---|---:|---:|
| Base-trace witness generation | 15.0 | 14.6 |
| Preprocessed / base / interaction commitments | 22.2 / 32.5 / 35.3 | 24.7 / 27.3 / 22.6 |
| Cairo STARK proving (composition, openings, FRI) | **50.2** | 24.0 |
| Cairo-verifier circuit stage | 44.0 | 26.4 |

The Cairo STARK stage no longer holds every tree's extended evaluations. The peak has moved to the
commitments, each of which still expands its whole tree before hashing, and to the circuit stage's
own commitments on top of about 16–20 GiB of retained state. The FRI batch size therefore barely
matters.

**Next lever:** stream each commitment. Extend 16 columns at a time, in the leaf hasher's
size-sorted order, and feed them to the Blake2s leaf builder, which already absorbs columns
16 at a time with one state per row. Rebuild openings the same way. `bench/bounded-memory` has a
tested column-provider Merkle API for this. We estimate it would remove roughly 6–10 GiB per
commitment, giving a floor near the retained ~20 GiB; this is not measured.

**Build note:** the prover must be built with `RUSTFLAGS="-C target-cpu=native"`. A default build
of the same source proves in about 193 s instead of 112 s, with identical per-stage memory.

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
felts); the bridge verifier itself 5,303. So the dominant Blake cost is the OS
hashing the account's executed bytecode, not the bootloader's
`compute_program_hash_chain`, which hashes only the OS program. Those numbers
matter only for fitting the cheaper log20 path.

## Open

- Gateway acceptance of PROOF2 on Sepolia and mainnet, checked by an actual
  submission with authentic chain state.
- Cost with the complete private-client verifier in the bridge.
- Repeated runs and an independent-verifier check of the saved proof bytes.
