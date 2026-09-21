# M0 Benchmark — client-phase workload, Cairo VM steps & Stwo proving

Latest desktop pathfinding: [bench/desktop/README.md](bench/desktop/README.md).
Native BN254 ordinary 2/2/1 proves in 0.26 s / 39.2 MiB and completes the real
Garaga pool flow; emulated compilation reaches its 32 GiB cap. See limitations
and the on-chain cost tradeoff there.

For the later Noir/Honk microbenchmark feeding ADR-0016, see
[bench/adr16/README.md](bench/adr16/README.md): 81,889 gates, 0.653 s median
desktop prove, 9,408-byte proof and ~269.9 M L2 gas in a Garaga fork test.
Full-statement scaling remains unmeasured.

**What is measured.** The upstream protocol's client phase (`compile_actions`, executed
inside the prover's virtual Starknet block) for a representative private transfer:

- 1 × `OpenChannel` + `OpenSubchannel` (channel key derivation, ECDH channel-info
  encryption to a fresh recipient, subchannel markers, outgoing-channel encryption)
- 2 × `UseNote` (nullifiers + note ids)
- 2 × `CreateEncNote` (salted masked amounts)
- 1 × `Withdraw` (ECDH user-address encryption)
- one-time `SetViewingKey` registration (key derivation + ECDH private-key encryption)

The crypto is a **verbatim copy** of upstream `packages/privacy/src/hashes.cairo` and
the ECDH/encryption helpers of `utils.cairo` (Stark-curve ops via `core::ec`, Poseidon
via `poseidon_hash_span`). Source: [`bench/src/lib.cairo`](bench/src/lib.cairo).

**Environment**: i9-10980XE (18C/36T @ 3.0 GHz), 125 GB RAM, Linux; scarb 2.14.0
(Cairo 2.14.0); Stwo prover via `scarb prove` (dev-profile execution; note:
`scarb execute --release` is not supported in scarb 2.14).

## Execution — Cairo VM resources (`scarb execute --print-resource-usage`)

| transfers | steps | poseidon | ec_op | range_check |
|----------:|------:|---------:|------:|------------:|
| 1 | 2,861 | 82 | 10 | 41 |
| 10 | 24,380 | 757 | 64 | 347 |
| 50 | 120,020 | 3,757 | 304 | 1,707 |
| 100 | 239,570 | 7,507 | 604 | 3,407 |

**Marginal cost per transfer: ≈ 2,388 steps, ≈ 75 Poseidon permutations, ≈ 6 EC scalar
multiplications, ≈ 34 range checks** (linear fit from the 1→100 delta). The pool's own
crypto is *tiny*: one hundred full private transfers ≈ 0.24 M Cairo steps.

## Proving — S-two via `scarb prove --execute` (default params, 36 threads)

| transfers | ~steps | prove wall | max RSS | proof size |
|----------:|-------:|-----------:|--------:|-----------:|
| 1 | 2.9 k | 4.73 s | 2.72 GB | 2.6 MB |
| 10 | 24 k | 3.85 s | 2.74 GB | 2.6 MB |
| 50 | 120 k | 4.55 s | 2.85 GB | 2.6 MB |
| 100 | 240 k | 5.25 s | 3.03 GB | 2.6 MB |
| 100 @ 6 threads | 240 k | 6.33 s | 3.01 GB | 2.6 MB |
| 1,000 | 2.4 M | 15.40 s | 5.85 GB | 2.6 MB |

## Findings

1. **Proving cost is dominated by a fixed frame (~4 s / ~2.7 GB on this machine)** —
   the 69-component Cairo AIR's preprocessed state, not the user computation. Going
   from 3 k to 240 k steps costs +0.5 s; the 6-thread "phone-class" run is only ~20%
   slower than 36 threads. **Compute is not the mobile blocker — memory is.** The
   fixed ~2.7 GB working set alone disqualifies current phones for proving the *full*
   Cairo AIR (before adding the Starknet OS + verifier components), while any laptop
   from the last five years is comfortable.
2. **The pool's per-transfer crypto is negligible** relative to any OS/verifier
   wrapper: ~2.4 k steps, 6 EC-muls, 75 Poseidon. A Templar inner circuit (§5.1 of
   PLAN.md) that proves note ownership + nullifier + value conservation will be of
   this order — i.e., phone-provable with a ZK SNARK stack (Barretenberg-WASM class),
   and irrelevant as an added cost inside an operator-proved virtual block.
3. **Proof size is flat 2.6 MB** — fine for sequencer-side verification (the
   virtual-SNOS model) and for aggregation/recursion, but chunky if posted per-tx.
   Motivates aggregation for the clean-room option C.
4. Caveat printed by the prover itself: *“soundness of proof is not yet guaranteed by
   Stwo, use at your own risk”* — default `scarb prove` parameters are not yet the
   production 96-bit configuration. Treat wall-times as representative, parameters as
   provisional.

## Reproduce

```bash
cd bench
scarb execute --arguments-file <(echo '["0x64"]') --print-resource-usage   # 100 transfers
scarb prove --execute --arguments-file <(echo '["0x64"]')                  # prove it
RAYON_NUM_THREADS=6 scarb prove --execute --no-build --arguments-file <(echo '["0x64"]')
```
