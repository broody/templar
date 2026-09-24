# Bridge baseline profile — pass 2 (trace captured; profiler tool incompatible)

2026-09-22. K3 routine execution only. Pass 1 preserved untouched in `../`.

## Execution (isolated profiling workspace, verified)

Workspace: `target/m31-private-wrapper/bridge-profile-cairo` (root's isolated
build; only change is `sierra = true` under `[[target.executable]]` in
`bridge/Scarb.toml`). Executable sha256
`82ed0ac7cc7e15074c7619d752cd442de7a9e14c06747516c5b58618920e6eab` — identical
to baseline. Sierra debug info:
`target/dev/templar_server_hash_bridge.executable.sierra.json` sha256
`7a65b3a98a491c8b52a8c749749829a9beffc7cd2d85fd1666bad98fa7d628e3`.

Command (cwd via systemd-run `WorkingDirectory=`):

```
systemd-run --user --wait --pipe -p MemoryMax=8G -p MemorySwapMax=0 \
  -p CPUQuota=400% -p CPUAffinity="0 1 2 3" -p RuntimeMaxSec=180 \
  -p WorkingDirectory=<repo>/target/m31-private-wrapper/bridge-profile-cairo \
  -- /usr/bin/time -v -o pass2/time.log \
  env ASDF_SCARB_VERSION=2.18.0 \
  /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb execute \
  -p templar_server_hash_bridge --no-build --save-profiler-trace-data \
  --print-program-output --print-resource-usage --output standard \
  --arguments-file <repo>/bench/m31-private-wrapper/results/server-circuit/proof/cairo-arguments.json
```

- Exit **0**; program output **matches expected_bridge_output exactly** (8 values).
- **steps: 5,018,523** — identical to baseline and pass 1. Resources identical
  to pass 1 (max mem addr 5,399,079; holes 341,779; range_check 669,669;
  output 8; segments 4,283,944/669,669/8).
- Process: elapsed 4.15 s, max RSS 1,729,124 KB (~1.65 GiB).
- Trace saved: `target/m31-private-wrapper/bridge-profile-cairo/target/execute/templar_server_hash_bridge/execution1/cairo_profiler_trace.json`
  (185 MiB, sha256 `cb6eb65cf5a7e6f4aa43629ea70ca6119c68d087fbb2557d050bf703ad18ce7b`).
  Tracked resource: cairo-steps.

## Profiler blocker — exact error and requirement

`cairo-profiler build-profile <trace> -o pass2/profile.pb.gz`
(cairo-profiler **0.14.0**, the only version installed — asdf; no network
install permitted) fails:

```
error from the program registry:
Error during libfunc specialization of local_into_box<Tuple<stwo_verifier_core::fields::qm31::naive::QM31>>:
Could not specialize libfunc `local_into_box` with generic_args: [...].
Error: Could not find the requested extension: local_into_box.
```

The sierra (scarb 2.18.0 compiler) uses the `local_into_box` libfunc, which
cairo-profiler 0.14.0's program registry does not know. **Requirement: a
newer cairo-profiler release whose registry covers `local_into_box`** (or a
profiler build against the matching cairo-lang version). Not fixable within
my ownership: no installs, no source/manifest edits, no rebuilds. No other
profiler binary exists on this machine (`snforge`/`sncast` installs carry no
profiler). Consequently **no top-20 function cost table exists**; inclusive
vs exclusive sample semantics were never instantiated (`--list-samples`
never reached).

## Artifacts (owned dir `bench/m31-private-wrapper/results/bridge-capacity/profile/pass2/`)

- `run.stdout.log` d3bef638…, `run.stderr.log` 1ce12725…, `time.log`
  d70b2f4b…, `run.exit` 19eaf438… (`exit=0`), `build-profile.log`
  402dc242… (profiler failure transcript).
- Trace stays under `target/` (185 MiB, path + hash above).

## Limitations

- Function-level costs absent; only whole-program resource counts and
  process-level time/RSS are measured.
- Steps/output/resource equality across baseline and this run confirms the
  isolated build reproduces the baseline bit-for-bit at the execution level;
  no proof, no private inputs involved.
