# Bridge baseline execution profile — pass 1 (historical; superseded)

2026-09-22. Worker: K3 routine execution only. **Historical status: this pass
verified execution but could not save profiler trace data. The profile DID
succeed later — see [pass 3](pass3/README.md) for the top-20 function costs;
pass 2 documents the intermediate trace capture. This document is kept as the
pass-1 record.**

## Exact command (final invocation)

```
cd target/m31-private-wrapper/server-cairo
systemd-run --user --wait --pipe \
  -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=400% \
  -p CPUAffinity="0 1 2 3" -p RuntimeMaxSec=180 \
  -p WorkingDirectory=/home/broody/development/templar/target/m31-private-wrapper/server-cairo \
  -- /usr/bin/time -v -o <profile>/time.log \
  env ASDF_SCARB_VERSION=2.18.0 \
  /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb execute \
  -p templar_server_hash_bridge --no-build --save-profiler-trace-data \
  --print-program-output --print-resource-usage --output standard \
  --arguments-file /home/broody/development/templar/bench/m31-private-wrapper/results/server-circuit/proof/cairo-arguments.json
```

(CLI repair note: the first attempt passed `--manifest-path` to
`scarb-execute`, which does not accept it, and `systemd-run` resets the
working directory; the invocation was corrected by dropping that flag and
adding `WorkingDirectory=`. No other invocation changes were made.)

## Execution results (verified)

- **Program output matches `expected_bridge_output` exactly** (8 values,
  first `16395037`, last `2643594634`; full list in `run.stdout.log`).
- **steps: 5,018,523** — consistent with the previous record
  (`results/server-circuit/summary.json` cairo.n_steps).
- Resources: max memory address 5,399,079; memory holes 341,779;
  range_check_builtin 669,669 cells; output_builtin 8; segments:
  execution 4,283,944 / range_check 669,669 / output 8.
- Process (`/usr/bin/time -v`): elapsed 3.71 s, max RSS 1,726,148 KB
  (~1.65 GiB), exit status **1** (execution succeeded; the exit-1 cause is
  the trace-save failure below).
- Output folder: `target/m31-private-wrapper/server-cairo/target/execute/templar_server_hash_bridge/execution9/`
  contains `prover_input.json` only (sha256
  `cf831d811cb228a2c9495499d6bf1fe69e88dc8bd17ebf8330f591c7ebcd97c3`); no
  trace data was written.

## Blocker — exact requirement (historical; resolved by root for pass 2/3)

`scarb execute` printed:

> Failed to write profiler trace data into a file — missing sierra code for
> target `templar_server_hash_bridge`. Set `sierra = true` under your
> `[executable]` target in the config and try again.

`--save-profiler-trace-data` required `sierra = true` under the
`[[target.executable]]` section of the bridge manifest
(`target/m31-private-wrapper/server-cairo/bridge/Scarb.toml` at pass-1 time).
Root later supplied an isolated build with exactly that addition
(`target/m31-private-wrapper/bridge-profile-cairo`), used in
[pass 2](pass2/README.md) (trace capture) and [pass 3](pass3/README.md)
(successful profile).

## Tool/artifact hashes

- Executable: `target/m31-private-wrapper/server-cairo/target/dev/templar_server_hash_bridge.executable.json`
  sha256 `82ed0ac7cc7e15074c7619d752cd442de7a9e14c06747516c5b58618920e6eab`
- Sierra: same dir, `templar_server_hash_bridge.sierra.json` (present,
  24,897,148 bytes — exists but not referenced by the executable target).
- cairo-profiler 0.14.0 (`/home/broody/.asdf/shims/cairo-profiler`).
- Logs (owned dir `bench/m31-private-wrapper/results/bridge-capacity/profile/`):
  `run.stdout.log` ada0379c…, `run.stderr.log` de1fa533…, `time.log`
  c4fc7686…, `run.exit` cf205dbb… (`exit=1`).

## Limitations (as of pass 1)

- Function-level costs are absent **in this pass-1 record**; see
  [pass 3](pass3/README.md) for the completed top-20 table.
- The 3.71 s / 1.65 GiB figures cover the scarb-execute process under the
  stated cgroup; exit status 1 reflects only the trace-save failure, not an
  execution error.
- Profiling required the `sierra = true` addition and rebuild; root supplied
  both in the isolated workspace used by pass 2/3.
