# R0 V2: withdrawals, up to submission

2026-09-23. R0 gains **withdrawals**. One circuit covers every shape: two inputs, up to two
output notes (each slot active or not), and at most one public withdrawal.

| Shape | New notes | Leaves the pool |
| --- | ---: | --- |
| Transfer | 2 | nothing |
| Partial withdrawal | 1 (change) | the withdrawal |
| Full withdrawal | 0 | everything |

The route runs locally, with single-permutation tree nodes, through the bridge, the virtual OS
and PROOF2; nothing was submitted. Pool costs are in [`bench/m31-pool`](../../../../m31-pool/README.md).

| Stage | Transfer | Partial withdrawal | Full withdrawal |
| --- | ---: | ---: | ---: |
| Client, 4 threads, normal / bounded | 0.59 / 0.31 GiB | 0.59 / 0.32 GiB | 0.57 / 0.31 GiB |
| Trace | 2¹⁸ (175,226 rows, one circuit for all shapes) | same | same |
| Bridge, standalone | 2.03M steps, 17/17 | 2.01M steps, 17/17 | 2.05M steps, 16/16 |
| Virtual OS | — | 3.36M steps, exact message | 3.41M steps, exact message |
| PROOF2 | — | — | 117.1 s / 50.9 GiB, verified, 3/3 rejections |

All three shapes share one circuit hash. The pool can't learn the shape from which verifier
accepted the proof; the statement itself shows it, through zero commitments and a nonzero
withdrawal, as the reference pool's public counts do. The account is 60,608 CASM felts, under
the 81,920 limit.

## The relation (`src/payment.rs`, V2)

- **Output slots.** Each slot has a private boolean `active`. An active slot needs a nonzero
  receiver, rho and amount (gated nonzero checks: `v · inv = active`). An inactive slot needs
  zero amount (`sum · (1 − active) = 0`), publishes a zero commitment (`cm · active`) and a
  zero delivery digest (`delivery · (1 − active) = 0`).
- **Withdrawal.** A public recipient (nine 28-bit felt limbs) and a public u128 amount (eight
  16-bit limbs, range-checked by bits).
- **Conservation.** `in₀ + in₁ = out₀ + out₁ + withdrawal` over the integers. Each limb
  difference lies in (−3·2^16, 2·2^16), so the signed carries are in {−2, −1, 0, 1}.
- **Statement.** 109 limbs, padded with zeros to 112, in 28 outputs. Tags `R0V2` (sponge nodes)
  and `R0C2` (single-permutation nodes).

**Public checks in the bridge:**
- the recipient and amount are both zero or both nonzero;
- the recipient is below 2^251;
- a slot is active exactly when its delivery digest is nonzero;
- something leaves the inputs;
- the padding is zero.

**Binding:** `TMR0_BIND_V2` extends V1 with the recipient and amount. The M31 pool computes the
same value, checked against the independent Python reference on this run's partial-withdrawal
statement (`bench/m31-pool`, `binding_matches_bridge`).

## Tests

**Relation** (`tests/payment_r0.rs`), for every shape and both tree formats:
- the statement matches the native reference;
- the topology is identical across shapes;
- broken witnesses are rejected: wrong sibling, position or secret; an inflated output; an
  inflated withdrawal; value in an inactive slot; a delivery digest for an inactive slot;
- the native rules hold, including a withdrawal without a recipient;
- finalization with the unused-variable lint.

**Bridge**, per shape:
- a wrong withdrawal recipient and a wrong withdrawal amount are rejected;
- all earlier cases still pass;
- the output-swap case is skipped for a full withdrawal, where both commitments are zero and
  swapping them is the same statement.

**Pool** (`bench/m31-pool`, 36/36): withdrawals pay out, inactive slots append nothing, and a
missing recipient, a redirected withdrawal and an empty spend are all rejected.
