# M31-append Cairo correctness report

Status: **failed**.

Correctness-only execution. These results are not performance measurements and do not establish outer PROOF1 verification or full-node proof attachment.

## Bounds and environment

- Scarb: `/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb`; SHA256 `97eafe061de1e473e6649578e320225d41abaf708784db1858173132811f01d6`.
- Workspace: `bench/m31-append/cairo`.
- Per process: 8 GiB `MemoryMax`, zero swap, `CPUQuota=100%`, `CPUAffinity=0`, `RuntimeMaxSec=300`.
- Scarb exposes no explicit maximum-step flag. Cairo executions used the stated process bounds; no step cap is claimed.
- Runs were sequential and fresh. `/usr/bin/time -v`, stdout, stderr, exit status, and systemd properties are preserved per case.

## Results

| Case | Kind | Exit | Comparison | Cairo steps | Max RSS KiB |
|---|---|---:|---|---:|---:|
| `bridge-single` | full Cairo inner-proof verification | 1 | FAIL |  | 153544 |

## Counts

- `bridge_acceptances_expected`: `2`
- `bridge_acceptances_passed`: `0`
- `actual_proof_ood_baselines_expected`: `2`
- `actual_proof_ood_baselines_passed`: `0`
- `actual_proof_ood_mutations_expected`: `4`
- `actual_proof_ood_mutations_passed`: `0`
- `arbitrary_ood_baselines_expected`: `2`
- `arbitrary_ood_baselines_passed`: `0`
- `arbitrary_ood_mutations_expected`: `4`
- `arbitrary_ood_mutations_passed`: `0`
- `transcript_checkpoints_expected`: `8`
- `transcript_checkpoints_passed`: `0`
- `empty_tree_positive_tests_expected`: `1`
- `empty_tree_guarded_negative_tests_expected`: `5`
- `empty_tree_positive_tests_passed`: `0`
- `empty_tree_guarded_negative_tests_passed`: `0`
- `local_pool_integration_tests_compiled_but_not_run`: `14`
- `native_mutations_not_rerun`: `{"n1": 23, "n2": 24}`

## Evidence boundaries

- Successful bridge cases establish Cairo acceptance of the two frozen direct S-two proofs and exact returned public-field agreement with native statement/output fixtures.
- OOD mutation cases are differential comparisons, not proof-rejection tests.
- Five guarded empty-tree panic tests are Cairo negative tests. The 14 local-pool integration tests were deliberately not run because no authentic PROOF1 facts fixture exists.
- No outer PROOF1 prover, preserved outer verifier, local-node attachment, service, or chain interaction was run.

## Failure

Stopped at `bridge-single`: Cairo bridge panicked before producing program output: `Empty nodes are not supported`.

Exact stdout/stderr and the minimal reproduction command are retained in `report.json` and the case directory.

Exact stdout:

```text
   Executing templar_m31_append_bridge
error: Panicked with "Empty nodes are not supported".
```

Exact stderr:

```text
Running as unit: templar-m31-cc-bridge-single-1012137.service; invocation ID: 2dced453c2654e4084db7db957135b9b
Command exited with non-zero status 1
	Command being timed: "/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_bridge --arguments-file /home/broody/development/templar/target/m31-append/smoke-single/cairo-arguments.json --output none --print-program-output --print-resource-usage"
	User time (seconds): 0.25
	System time (seconds): 0.44
	Percent of CPU this job got: 95%
	Elapsed (wall clock) time (h:mm:ss or m:ss): 0:00.72
	Average shared text size (kbytes): 0
	Average unshared data size (kbytes): 0
	Average stack size (kbytes): 0
	Average total size (kbytes): 0
	Maximum resident set size (kbytes): 153544
	Average resident set size (kbytes): 0
	Major (requiring I/O) page faults: 0
	Minor (reclaiming a frame) page faults: 46675
	Voluntary context switches: 45
	Involuntary context switches: 564
	Swaps: 0
	File system inputs: 0
	File system outputs: 4128
	Socket messages sent: 0
	Socket messages received: 0
	Signals delivered: 0
	Page size (bytes): 4096
	Exit status: 1
Finished with result: exit-code
Main processes terminated with: code=exited/status=1
Service runtime: 728ms
CPU time consumed: 697ms
Memory peak: 512.0K
Memory swap peak: 0B
```

## Exact commands

### `bridge-single`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-bridge-single-1012137 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_bridge --arguments-file /home/broody/development/templar/target/m31-append/smoke-single/cairo-arguments.json --output none --print-program-output --print-resource-usage
```
