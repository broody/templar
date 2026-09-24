# Optimized-cairo bridge validation (K3)

2026-09-22. Correctness-only validation of root's checked-M31-inversion
workspace `target/m31-private-wrapper/optimized-cairo` (read-only to me).
Baseline (`results/server-circuit`, profile pass1–3) untouched. Wall
time/RSS below are **not comparable** — a root Cargo build ran concurrently.

## Hashes

- Optimized executable: `7128fbe863320b13b2ccfeab10990efb49436b4e38b35295de1f493c52c0cda2`
  (baseline was `82ed0ac7…`).
- `vendor/verifier_core/src/fields/m31/naive.cairo`: `d8052bfa…ed48`;
  `bridge/src/lib.cairo`: `bb714d2b…f0b5`.
- Arguments: original proof args reused (`cairo-valid.json` sha256
  `60651c9a…`, identical content to baseline case input).

## scarb test

`ASDF_SCARB_VERSION=2.18.0 scarb test -p stwo_verifier_core -f inverse_regression`
(in the optimized-cairo workspace) — exit 0: **2 passed, 0 failed**
(`inverse_regression::zero_inverse_rejected`,
`inverse_regression::canonical_inverse_products`; 72 filtered out). Log:
`scarb-test.log`.

## Eight serialized-proof bridge cases

Adapted copy `validate_optimized_bridge.py` (same mutations as
`validate_server_bridge.py`; retargeted workspace, unique measure names
`optimized-cairo-*`). Full rows: `optimized-cairo-validation.json`.

| case | expected | result | rejection reason |
| --- | --- | --- | --- |
| valid | accept | exit 0, output == expected (8 felts), **4,247,207 steps** | — |
| output | reject | exit 1, panic | "Interaction Proof Of Work verification failed" |
| interaction-nonce | reject | exit 1, panic | "Interaction Proof Of Work verification failed" |
| config | reject | exit 1, panic | "unexpected proof pcs config" |
| trusted-root | reject | exit 1, panic | "assertion failed: `preprocessed_commitment == preprocessed_root()`" |
| trace-root | reject | exit 1, panic | "Interaction Proof Of Work verification failed" |
| trailing | reject | exit 1, panic | "trailing proof data" |
| truncated | reject | exit 1, panic | `INVALID_PROOF_ENCODING` |

All 8 passed their expectation; no OOM kills. Valid-case resources:
4,247,207 steps, holes 344,145, range_check 610,519, output 8, max mem addr
4,784,166 (baseline: 5,018,523 steps / 669,669 range_check). Timing/RSS
recorded in the JSON but incomparable (concurrent root build).

No architecture or math conclusions drawn; no new proving; no global tool
changes. Measure outputs: `results/server-circuit/optimized-cairo-*`.
