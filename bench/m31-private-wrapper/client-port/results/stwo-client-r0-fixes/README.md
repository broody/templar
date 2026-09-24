# R0 after the review fixes

2026-09-23. The R0 payment route (lane-packed, `Tree::Compress`, blinding sized per H1) with the
non-design fixes from the four [reviews](../../reviews/). Everything before Sepolia submission
reran on the synthetic fixture; nothing was submitted.

| Stage | Before the fixes ([`../stwo-client-r0-blinding/`](../stwo-client-r0-blinding/README.md)) | **After** |
| --- | ---: | ---: |
| Client, 4 threads, normal / bounded | 0.58 / 0.30 GiB | 0.58 / **0.31 GiB**, 1.6–2.8 / 2.1–2.2 s |
| Account CASM (sequencer limit 81,920) | **82,828, over the limit** | **59,152** (Sierra 28,477) |
| Bridge, standalone | 3.33M steps, 15 checks | **1.99M steps, 16/16** |
| Virtual OS | 4.89M steps | **3.32M steps**, exact message; 3/3 negative captures rejected |
| PROOF2 | 115.1 s / 51.7 GiB | 113.1 s / 52.4 GiB, verified, 3/3 rejections |

PROOF2 hardly moves because its cost comes in tiers set by the largest Cairo component, not by
steps (Cairo performance review, Q3).

## Fixes

| Finding | Fix | Where |
| --- | --- | --- |
| Cairo Q5: account CASM over the sequencer limit | Scarb feature `arithmetic_profile` on `circuit_air` compiles out the nine absent components' evaluators (asserting their log size is 0); both arithmetic bridges enable it. `build_bridge_arith.py` now fails if CASM exceeds 80 × 1024 and records the sizes. | fork `7b2012c79`; `cairo-{arith,r0}/bridge/Scarb.toml`; `build_bridge_arith.py` |
| Cairo #1–3: bridge steps | Batch inversions in FRI line and circle folds and across `fri_answers` denominators; coset points by addition; skip empty degree bounds. The order of use is unchanged, and a zero divisor still panics. 73/73 verifier_core tests pass. | fork `7b2012c79` (`verifier_core/src/fri.cairo`, `pcs/quotients.cairo`) |
| Math M2: absent-sum check load-bearing but untested | `check_claims` (absent sums, then LogUp sum) and `verify_circuit_proof` in the fork, used by every Rust verifier. A fork test forges an output balanced on the absent `triple_xor` sum: it passes the STARK and the lookup sum, and is rejected only by the absent check. The same forgery runs as a native negative (`--forge-absent-sum`), a Cairo bridge case and a negative OS capture. It replaces the old claimed-sum shift, which the STARK alone rejected. | fork `147183528`; `examples/support/mod.rs` (`forge_absent_sum`, `forgery_negative`); `validate_bridge_r0.py` |
| Math M1: compressed-node domain separation ~62 bits | Fixed words moved to capacity positions: `node = P(left ‖ right ‖ [TAG, 1, NODE1, level, 0, 0])[..9]`. A later sponge block must now match six capacity words. | `src/payment.rs` |
| Binding L1: formats share tags | Statement tag per tree format (`R0V1` sponge, `R0C1` compressed), pinned by the bridge build from the manifest. | `src/payment.rs`, `build_bridge_arith.py`, `cairo-r0/bridge` |
| Binding L2: missing liveness checks | The bridge checks nonzero chain, pool and token; pool and token below 2^251; nonzero nullifier and commitment digests; nonzero delivery digests. | `cairo-r0/bridge/src/lib.cairo` |
| Binding M2: negatives only in the standalone harness | `capture_os.py --expect-reject`: negative captures through the real account in the virtual OS. The forgery is rejected with "absent component claims a nonzero sum", the flipped proof byte with a Merkle root mismatch, and the truncated proof with `INVALID_PROOF_ENCODING` (`os-negatives/`). | `capture_os.py` |
| Binding L3: empty vendor record | Path filter fixed; 110 fork files recorded. | `build_bridge_arith.py` (commit `0a7843f`) |
| PCS M1 and M2 | `stwo-examples` and the relation tracker build again; the equality test also compares `aux`. | fork `fb6c10df9` |

The forgery negative runs a second, unbounded prover, so it is opt-in (`--forge-absent-sum`, or
`TEMPLAR_FORGE_NEGATIVE` for the membership prover). The memory runs in `client/runs.json` exclude
it. Including it, the process peak was about 0.65 GiB.

## Still open

- **Tree strategy**, pending discussion: on-chain M31 appends cost about 92–181M L2 gas per
  spend (Cairo performance review, Q4).
- **PROOF2 Poseidon tier:** calldata packing (Cairo #7).
- **Hiding:** a simulation argument beyond the H1 count.
- **Compressed-node review:** with the fixed words moved, the round-number question remains
  (math review D).
- **Test depth:** the R0 tests still replay the honest witness generator (math review, low).
