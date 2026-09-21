# M31-append Cairo correctness report

Status: **passed**.

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
| `bridge-single` | full Cairo inner-proof verification | 0 | pass | 6032137 | 903252 |
| `bridge-batch` | full Cairo inner-proof verification | 0 | pass | 8730032 | 1560452 |
| `ood-single-baseline` | actual-proof OOD differential | 0 | pass | 692334 | 137932 |
| `ood-single-base-mutation` | actual-proof OOD differential | 0 | pass | 692318 | 137452 |
| `ood-single-interaction-mutation` | actual-proof OOD differential | 0 | pass | 692334 | 137572 |
| `ood-batch-baseline` | actual-proof OOD differential | 0 | pass | 692311 | 137456 |
| `ood-batch-base-mutation` | actual-proof OOD differential | 0 | pass | 692279 | 137632 |
| `ood-batch-interaction-mutation` | actual-proof OOD differential | 0 | pass | 692310 | 137424 |
| `ood-arbitrary-0-baseline` | arbitrary OOD differential | 0 | pass | 691243 | 137548 |
| `ood-arbitrary-0-base-mutation` | arbitrary OOD differential | 0 | pass | 691271 | 137276 |
| `ood-arbitrary-0-interaction-mutation` | arbitrary OOD differential | 0 | pass | 691242 | 137848 |
| `ood-arbitrary-1-baseline` | arbitrary OOD differential | 0 | pass | 691282 | 137476 |
| `ood-arbitrary-1-base-mutation` | arbitrary OOD differential | 0 | pass | 691266 | 137592 |
| `ood-arbitrary-1-interaction-mutation` | arbitrary OOD differential | 0 | pass | 691282 | 137556 |
| `transcript-single-stage-0` | transcript checkpoint differential | 0 | pass | 792602 | 162296 |
| `transcript-single-stage-1` | transcript checkpoint differential | 0 | pass | 792785 | 161836 |
| `transcript-single-stage-2` | transcript checkpoint differential | 0 | pass | 792821 | 161732 |
| `transcript-single-stage-3` | transcript checkpoint differential | 0 | pass | 792852 | 161600 |
| `transcript-batch-stage-0` | transcript checkpoint differential | 0 | pass | 1579284 | 303260 |
| `transcript-batch-stage-1` | transcript checkpoint differential | 0 | pass | 1579467 | 303528 |
| `transcript-batch-stage-2` | transcript checkpoint differential | 0 | pass | 1579503 | 298500 |
| `transcript-batch-stage-3` | transcript checkpoint differential | 0 | pass | 1579534 | 303404 |
| `bridge-empty-tree-tests` | Cairo guarded empty-tree tests | 0 | pass |  | 811944 |

## Counts

- `actual_proof_ood_baselines_expected`: `2`
- `actual_proof_ood_baselines_passed`: `2`
- `actual_proof_ood_mutations_expected`: `4`
- `actual_proof_ood_mutations_passed`: `4`
- `arbitrary_ood_baselines_expected`: `2`
- `arbitrary_ood_baselines_passed`: `2`
- `arbitrary_ood_mutations_expected`: `4`
- `arbitrary_ood_mutations_passed`: `4`
- `bridge_acceptances_expected`: `2`
- `bridge_acceptances_passed`: `2`
- `empty_tree_guarded_negative_tests_expected`: `5`
- `empty_tree_guarded_negative_tests_passed`: `5`
- `empty_tree_positive_tests_expected`: `2`
- `empty_tree_positive_tests_passed`: `2`
- `local_pool_integration_tests_compiled_but_not_run`: `14`
- `native_mutations_not_rerun`: `{"n1": 23, "n2": 24}`
- `transcript_checkpoints_expected`: `8`
- `transcript_checkpoints_passed`: `8`

## Evidence boundaries

- Successful bridge cases establish Cairo acceptance of the two frozen direct S-two proofs and exact returned public-field agreement with native statement/output fixtures.
- OOD mutation cases are differential comparisons, not proof-rejection tests.
- Five guarded empty-tree panic tests are Cairo negative tests and two are positive tests. The 14 local-pool integration tests were deliberately not run because no authentic PROOF1 facts fixture exists.
- No outer PROOF1 prover, preserved outer verifier, local-node attachment, service, or chain interaction was run.

## Exact commands

### `bridge-single`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-bridge-single-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_bridge --arguments-file /home/broody/development/templar/target/m31-append/smoke-single/cairo-arguments.json --output none --print-program-output --print-resource-usage
```

### `bridge-batch`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-bridge-batch-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_bridge --arguments-file /home/broody/development/templar/target/m31-append/smoke-batch/cairo-arguments.json --output none --print-program-output --print-resource-usage
```

### `ood-single-baseline`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-ood-single-baseline-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_ood_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/ood-single-baseline.json --output none --print-program-output --print-resource-usage
```

### `ood-single-base-mutation`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-ood-single-base-mutation-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_ood_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/ood-single-base-mutation.json --output none --print-program-output --print-resource-usage
```

### `ood-single-interaction-mutation`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-ood-single-interaction-mutation-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_ood_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/ood-single-interaction-mutation.json --output none --print-program-output --print-resource-usage
```

### `ood-batch-baseline`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-ood-batch-baseline-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_ood_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/ood-batch-baseline.json --output none --print-program-output --print-resource-usage
```

### `ood-batch-base-mutation`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-ood-batch-base-mutation-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_ood_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/ood-batch-base-mutation.json --output none --print-program-output --print-resource-usage
```

### `ood-batch-interaction-mutation`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-ood-batch-interaction-mutation-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_ood_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/ood-batch-interaction-mutation.json --output none --print-program-output --print-resource-usage
```

### `ood-arbitrary-0-baseline`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-ood-arbitrary-0-baseline-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_ood_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/ood-arbitrary-0-baseline.json --output none --print-program-output --print-resource-usage
```

### `ood-arbitrary-0-base-mutation`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-ood-arbitrary-0-base-mutation-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_ood_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/ood-arbitrary-0-base-mutation.json --output none --print-program-output --print-resource-usage
```

### `ood-arbitrary-0-interaction-mutation`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-ood-arbitrary-0-interaction-mutation-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_ood_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/ood-arbitrary-0-interaction-mutation.json --output none --print-program-output --print-resource-usage
```

### `ood-arbitrary-1-baseline`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-ood-arbitrary-1-baseline-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_ood_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/ood-arbitrary-1-baseline.json --output none --print-program-output --print-resource-usage
```

### `ood-arbitrary-1-base-mutation`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-ood-arbitrary-1-base-mutation-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_ood_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/ood-arbitrary-1-base-mutation.json --output none --print-program-output --print-resource-usage
```

### `ood-arbitrary-1-interaction-mutation`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-ood-arbitrary-1-interaction-mutation-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_ood_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/ood-arbitrary-1-interaction-mutation.json --output none --print-program-output --print-resource-usage
```

### `transcript-single-stage-0`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-transcript-single-stage-0-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_transcript_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/transcript-single-stage-0.json --output none --print-program-output --print-resource-usage
```

### `transcript-single-stage-1`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-transcript-single-stage-1-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_transcript_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/transcript-single-stage-1.json --output none --print-program-output --print-resource-usage
```

### `transcript-single-stage-2`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-transcript-single-stage-2-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_transcript_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/transcript-single-stage-2.json --output none --print-program-output --print-resource-usage
```

### `transcript-single-stage-3`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-transcript-single-stage-3-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_transcript_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/transcript-single-stage-3.json --output none --print-program-output --print-resource-usage
```

### `transcript-batch-stage-0`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-transcript-batch-stage-0-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_transcript_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/transcript-batch-stage-0.json --output none --print-program-output --print-resource-usage
```

### `transcript-batch-stage-1`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-transcript-batch-stage-1-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_transcript_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/transcript-batch-stage-1.json --output none --print-program-output --print-resource-usage
```

### `transcript-batch-stage-2`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-transcript-batch-stage-2-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_transcript_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/transcript-batch-stage-2.json --output none --print-program-output --print-resource-usage
```

### `transcript-batch-stage-3`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-transcript-batch-stage-3-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml execute --no-build -p templar_m31_append_transcript_probe --arguments-file /home/broody/development/templar/bench/m31-append/results/cairo-correctness-v2/arguments/transcript-batch-stage-3.json --output none --print-program-output --print-resource-usage
```

### `bridge-empty-tree-tests`

```sh
systemd-run --user --wait --pipe --unit=templar-m31-cc-bridge-empty-tree-tests-1017829 -p WorkingDirectory=/home/broody/development/templar/bench/m31-append/cairo -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=100% -p CPUAffinity=0 -p RuntimeMaxSec=300 --setenv=PATH=/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin /usr/bin/time -v /home/broody/.asdf/installs/scarb/2.18.0/bin/scarb --manifest-path /home/broody/development/templar/bench/m31-append/cairo/Scarb.toml test -p templar_m31_append_bridge
```
