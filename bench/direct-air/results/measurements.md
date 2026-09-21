# Synthetic compact-proof pathfinding measurements

2026-09-21. Native i9-10980XE development host, approximately 128 GiB installed
RAM. Cgroup caps are not physical desktop qualification. No chain writes or
real wallet secrets were used. Further disclosure/recovery analysis is deferred.

## Client baseline already measured

| Run | Threads / cap | Result | Peak RSS | Time |
| --- | --- | --- | ---: | --- |
| `eq-one-thread` | 1 / 2 GiB, zero swap | OOM before completion | sampled 1.945 GiB; cgroup 2.000 GiB | service 3.38 s |
| `eq-one-thread-8g` | 1 / 8 GiB, zero swap | Two synthetic proofs completed | 2.605 GiB | 5.989 s and 5.672 s proving; 12.275 s whole diagnostic |

This is the pinned upstream circuit family with its fixed lookup tables and
baseline allocation behavior. It is not a purpose-built payment AIR or the
previous bounded-memory proving entry point. Preprocessing is included in the
whole diagnostic. The process also runs native verification and diagnostics;
its RSS is not an isolated application-proving phase measurement. Proof JSON
envelopes are 581,835 and 589,646 bytes; these are serialization sizes, not a
claim about an optimized binary transport. See the per-run JSON for source
configuration and the binary digest. No new client run was performed after the
user deferred disclosure diagnostics.

The client privacy prerequisite has not passed. These numbers therefore do not
establish a memory budget for a private wallet. No 4-thread client, 2-input /
2-output depth-32 payment, or WASM measurement is claimed.

## Cairo interoperability

Scarb 2.18.0, software QM31, ordinary Blake2s inner channel, trusted generated
topology/root/config. Executions used an 8 GiB cap, zero swap and CPU affinity
0–3. GNU time includes the Scarb executor subprocess; sampled RSS of the Scarb
parent alone is not used as the VM peak.

| Saved proof | Result | VM steps | Peak RSS | Command elapsed |
| --- | --- | ---: | ---: | ---: |
| 0 | Exact expected output | 4,846,314 | 0.769 GiB | 2.12 s |
| 1 | Exact expected output | 4,906,047 | 0.781 GiB | 2.03 s |

Four focused serialization/transcript tests pass. All nine altered-input cases
are rejected inside decoding or verification:

| Change | Rejection |
| --- | --- |
| PCS PoW setting | Unexpected proof PCS config |
| Lifting size | Unexpected proof PCS config |
| Preprocessed root | Fixed root mismatch |
| Public output count | Fixed output count mismatch |
| Public output value | Interaction PoW verification failed |
| OOD value | Invalid OODS evaluation |
| Queried value | Merkle root mismatch |
| Truncated input | Invalid proof encoding |
| Trailing input | Trailing proof data |

`cairo-bridge-validation.json` records executable, executor and fixture hashes
and individual outcomes. `cairo-valid-0/` records the first valid execution;
`bridge-check-*/` records the remaining ten cases and effective cgroup limits.
Final builds passed for both the executable and gas-enabled statement account.

These results demonstrate Rust-to-Cairo interoperability for this synthetic
topology. They do not measure the server's Cairo proving/recursive pipeline,
produce PROOF1, establish privacy, or qualify the payment protocol. The next
integration step requires the compiled synthetic account in authenticated state
supported by the pinned service; no state-override API is available.

## Sepolia declaration preflight

`sncast` 0.63.0 `declare --dry-run --detailed` accepts the final statement class
on Sepolia. Estimated declaration fee: 93.282573384211208384 test STRK, with
5,246,255,680 L2 gas and 192 L1 data gas. This is a one-time setup estimate at
the recorded RPC prices; deployment, virtual execution, wrapping and settlement
are not included. No declaration, deployment or payment was submitted.

The Vocs typecheck and 35-page build pass. SHA-256 verification confirms that
all 337 files in `prover-memory`, 195 in `cairo-memory`, and 180 in
`bounded-memory` remain unchanged against their archived manifests.
