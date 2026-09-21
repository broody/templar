# M31-append native measurement summary

Status: **stopped on the first integration proof failure**.

Scope: public append arithmetic only; no private-payment or browser qualification.

## Six completed measurement runs

| Run | Proof bytes | Proof SHA256 | Complete s | Harness s | Command RSS GiB | Cgroup peak GiB | Verified |
|---|---:|---|---:|---:|---:|---:|---|
| `native-single-1` | 192143 | `955bfb38e456678966def815a9d1c3096c0f4258972006a4a2b1c5692d6f5615` | 4.085298 | 4.192708 | 0.017513 | 0.014297 | yes |
| `native-single-2` | 192143 | `955bfb38e456678966def815a9d1c3096c0f4258972006a4a2b1c5692d6f5615` | 4.073443 | 4.196974 | 0.017525 | 0.014542 | yes |
| `native-single-3` | 192143 | `955bfb38e456678966def815a9d1c3096c0f4258972006a4a2b1c5692d6f5615` | 4.063303 | 4.195489 | 0.017513 | 0.014755 | yes |
| `native-batch-1` | 223098 | `7ed80c51ad5a0fd05239675903b515d8b0c46d7e7cfb69ad5f2840902592646e` | 1.988121 | 2.135123 | 0.030315 | 0.027172 | yes |
| `native-batch-2` | 223098 | `7ed80c51ad5a0fd05239675903b515d8b0c46d7e7cfb69ad5f2840902592646e` | 2.102855 | 2.224527 | 0.030293 | 0.027416 | yes |
| `native-batch-3` | 223098 | `7ed80c51ad5a0fd05239675903b515d8b0c46d7e7cfb69ad5f2840902592646e` | 1.988242 | 2.131302 | 0.030289 | 0.031277 | yes |

All six used a 1 GiB cap, one pinned CPU, one prover worker, and zero swap; no OOM was observed. Full phase, sampling, cgroup, and `/usr/bin/time` data remain in each result directory.

The three single proofs are byte-identical, as are the three batch proofs. This fixed-fixture deterministic grinding/context result shows fixture stability, not a payment-latency distribution.

`native_verify_seconds` is only the verification phase inside each proving process; no separate verification-memory measurement is claimed.

## Blocker

`native-branch12` failed with `Error: wire query count` (exit 1). It used only ~0.0143 GiB effective cgroup peak, zero swap, and no OOM, so this is not a 1 GiB cap failure. The run was not retried and the cap was not increased.

Primary outer-ready proof directories available:

- `bench/m31-append/results/native-single-1/proof`
- `bench/m31-append/results/native-batch-1/proof`

The intended branch12, branch13, and refresh123 proof directories are unavailable. The sequence stopped before branch13/refresh123, both `--verify-tests` suites, and all state-fixture validation controls. Therefore positive fixture validation and rejected-control count are **not available**, rather than zero successes.

No outer service or prover was run.
