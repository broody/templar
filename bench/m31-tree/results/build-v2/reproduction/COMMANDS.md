# Reproduction commands

All runs serial, one at a time, no overlapping builds or benchmarks. Pinned
tools: `/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb` (2.18.0) and
`/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin/snforge` (0.63.0);
PATH additionally includes `$HOME/.local/bin`. Frozen v2 binary and pkg paths
are in `../implementation-handoff.json`.

- Native proofs (8 runs): `run-native.sh` — wraps `bench/m31-tree/measure.py`
  with `--cpu-cores 1 --prover-workers 1`, caps 1/3/2 GiB per name.
- Browser proofs (4 runs): `run-browser.sh` — `measure.py --cpu-cores 4` around
  `/usr/bin/node bench/m31-tree/run-browser.mjs OUTPUT REPEATS target/m31-tree/pkg FIXTURE REFERENCE`.
- Cairo cost cells 1–14: `run-cairo.sh` — per cell:
  `systemd-run --user --wait --pipe --unit=<fresh> -p WorkingDirectory=bench/m31-tree/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p RuntimeMaxSec=300 -p CPUQuota=400% -p CPUAffinity="0 1 2 3" --setenv=PATH=$PATH <snforge> test --exact m31_tree_bench::tests::cost_TYPE_STATE_N --max-threads 1 --max-n-steps 80000000 --detailed-resources --gas-report --trace-components gas`
- Cairo batch-8 retries (authorized once per cell): identical, except
  `MemoryMax=16G`; outputs `results/cairo-final-m31-{cold,warm}-8-16g/`.
  Original 8 GiB OOM failures preserved in `results/cairo-final-m31-{cold,warm}-8/`.
- Native verify of browser exports:
  `systemd-run --user --wait --pipe -p MemoryMax=8G -p MemorySwapMax=0 -p RuntimeMaxSec=300 env RAYON_NUM_THREADS=1 taskset -c 0 <binary> --verify-tests PROOF_BIN results/native-verify-v2-{tree,mixed}`
- Cairo correctness (36 tests): same systemd template, `snforge test <filter>`
  with filters golden / packing_ / m31_reject_ / m31_history_eviction /
  snapshot_ (`--max-n-steps 30000000`); logs in `results/cairo-correctness/`.
- Per-selector trace extraction: same template with
  `--tracked-resource cairo-steps --save-trace-data` for cost_{felt,m31}_{cold,warm}_1;
  extracted into `results/cairo-final-*/per-selector-counters.json`; huge new
  M31 traces deleted after extraction, old trace restored.
- Docs validation (cwd `docs/guide`): `npm run typecheck`, `npm run build`;
  logs and exit codes in `results/docs-validation/`.
- Integrity: `python3 bench/m31-tree/check-integrity.py > results/integrity-final.json`.
- Archive manifest: `find . -type f` over `bench/m31-tree` excluding
  `SHA256SUMS`, `__pycache__`, `cairo/target`, `cairo/.snfoundry_cache`,
  `client/target`, piped to `sha256sum > SHA256SUMS`.

2026-09-21 doc corrections (unit standardization 19.75 MiB / 1.900 GiB, 118.2 ms
heartbeat, heading split, cap phrasing) are recorded in
`results/aggregate.json` under `doc_corrections_2026_09_21`.
