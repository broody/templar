# Bridge baseline profile — pass 3 (top-20 function costs)

2026-09-22. K3 routine execution only. Built from the **saved pass-2 trace**
(no new Cairo execution, no Scarb/prover run). Profiler: official
cairo-profiler **v0.17.0** release asset, sha256-verified
(`9c52ea24cda77cfa3fd6a34f674394fea99f49144f8e190571fe68b88b87f2c9`)
before extraction to `target/m31-private-wrapper/profiler-0.17/`; binary
reports `cairo-profiler 0.17.0`. v0.17.0 succeeds where the asdf-installed
0.14.0 failed on the `local_into_box` libfunc (pass 2 report).

## Provenance chain

- Trace (unchanged from pass 2):
  `target/m31-private-wrapper/bridge-profile-cairo/target/execute/templar_server_hash_bridge/execution1/cairo_profiler_trace.json`,
  185 MiB, sha256 `cb6eb65cf5a7e6f4aa43629ea70ca6119c68d087fbb2557d050bf703ad18ce7b`.
- Executable sha256 `82ed0ac7…` (baseline-identical); execution already
  verified in pass 2: exact `expected_bridge_output` match, **5,018,523
  steps**.

## Commands

```
cairo-profiler build-profile <trace.json> -o pass3/profile.pb.gz   # exit 0
cairo-profiler view profile.pb.gz --list-samples
cairo-profiler view profile.pb.gz --sample steps --limit 20        # pass3/top20-steps.txt
```

Available samples: `steps`, `output builtin`, `range check builtin`,
`casm size`, `calls`, `memory holes`. Table below uses **steps**.

## Sample semantics

pprof convention as rendered by the tool: **flat = own cost** (steps executed
in the function body itself), **cum = inclusive cost** (function plus all
callees). Header: nodes shown account for 4,067,902 steps = 81.06% of
5,018,523 total; 184 nodes total. Names with `[a-b]` suffixes are Sierra
statement-range splits of one source function (generic splitting was not
enabled); combine or split is root's interpretation call.

## Top 20 by own steps (full text in `top20-steps.txt`)

| # | flat (own) | flat% | cum (incl.) | cum% | function |
| -- | --: | --: | --: | --: | --- |
| 1 | 941,668 | 18.76 | 941,668 | 18.76 | `stwo_verifier_core::fields::m31::naive::repeated_square` |
| 2 | 334,985 | 6.67 | 334,985 | 6.67 | `pcs::quotients::accumulate_row_quotients[1329-2042]` |
| 3 | 305,455 | 6.09 | 1,268,571 | 25.28 | `fri::fold_coset[832-1302]` |
| 4 | 297,297 | 5.92 | 600,325 | 11.96 | `core::array::deserialize_array_helper` |
| 5 | 272,090 | 5.42 | 1,379,378 | 27.49 | `fields::m31::naive::M31InvertibleImpl::inverse` |
| 6 | 241,809 | 4.82 | 241,809 | 4.82 | `circle::CirclePointIndexImpl::to_point` |
| 7 | 196,478 | 3.92 | 196,478 | 3.92 | `vcs::blake2s_hasher::Blake2sHashSerde::deserialize` |
| 8 | 193,346 | 3.85 | 297,107 | 5.92 | `vcs::verifier::MerkleVerifierImpl::verify[2471-4455]` |
| 9 | 159,111 | 3.17 | 159,111 | 3.17 | `fields::qm31::naive::QM31Mul::mul` |
| 10 | 154,350 | 3.08 | 283,640 | 5.65 | `pcs::quotients::tree_take_n[268-434]` |
| 11 | 149,538 | 2.98 | 149,538 | 2.98 | `utils::bit_reverse_index[284-457]` |
| 12 | 133,770 | 2.67 | 491,808 | 9.80 | `pcs::quotients::accumulate_row_quotients[806-2194]` |
| 13 | 129,376 | 2.58 | 129,376 | 2.58 | `core::array::ArrayImpl` |
| 14 | 106,920 | 2.13 | 106,920 | 2.13 | `fields::qm31::QM31Serde::deserialize` |
| 15 | 103,761 | 2.07 | 103,761 | 2.07 | `vcs::blake2s_hasher::Blake2sMerkleHasher::hash_node{...}` |
| 16 | 95,252 | 1.90 | 95,252 | 1.90 | `fri::compute_decommitment_positions_and_rebuild_evals[1062-1738]` |
| 17 | 66,248 | 1.32 | 624,624 | 12.45 | `fields::m31::naive::repeated_square{NotSpecialized, 8}` |
| 18 | 66,150 | 1.32 | 66,150 | 1.32 | `fri::build_merkle_verification_inputs[598-837]` |
| 19 | 63,735 | 1.27 | 1,160,000 | 23.11 | `pcs::quotients::fri_answers[4335-4838]` |
| 20 | 56,563 | 1.13 | 288,435 | 5.75 | `fri::SparseEvaluationImpl::fold_line[778-980]` |

## Artifacts (`pass3/`)

- `profile.pb.gz` sha256 `5a428d6f…` (built profile; reusable via
  `cairo-profiler view`).
- `top20-steps.txt` sha256 `f43ed35b…` (verbatim tool output).
- `build-profile.log` (empty, sha256 `e3b0c442…`); execution logs remain in
  `../pass2/`.

## Limitations

- Steps only; no wall-time attribution. `[a-b]` suffixes split some source
  functions; `--split-generics`/`--show-inlined-functions` were not used
  (latter needs a Scarb `[cairo]` debug-info flag — root's call).
- This profiles the public server hash-circuit bridge only; no privacy,
  proof-validity, or optimization conclusion is drawn here.
