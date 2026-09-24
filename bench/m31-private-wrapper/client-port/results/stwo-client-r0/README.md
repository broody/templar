# R0 payment through the split architecture, up to submission

> **Superseded by [`../stwo-client-r0-lanes/`](../stwo-client-r0-lanes/README.md)**: the same
> relation with lane-packed hashing (log19, half the memory). These log20 figures are from
> commit `f421cdd`.

2026-09-23. **An ordinary 2-in/2-out private payment (R0) is proved on the client as a blinded
arithmetic-only stwo-circuits proof, verified by the Cairo bridge inside the virtual OS, and
wrapped as a verified PROOF2.** Every stage before Sepolia submission ran locally against a
synthetic chain-state fixture. Nothing was submitted.

| Stage | Where | Time | Peak memory | Evidence |
| --- | --- | ---: | ---: | --- |
| Client proof, 4 threads | client | 2.5–3.8 s | 2.2 GiB | `client/runs.json` |
| Client proof, 4 threads, bounded-memory mode | client | 4.4–5.2 s | **1.1 GiB** | `client/runs.json` |
| Client proof, 1 thread (normal / bounded) | client | 9.5–23.5 s / 20.1–29.6 s | 2.2 / 1.1 GiB | `client/runs.json` |
| Bridge, standalone Cairo | server | — | — | 3.77M steps, 15/15 checks (`bridge-validation/`) |
| Virtual OS execution of the account | server | 10.0 s | 0.90 GiB | 5.42M steps, exact message (`os-capture/`) |
| PROOF2 large path | server | 139 s | 64.2 GiB | verified, 3/3 rejections (`proof2/`) |

## Compared with the original pipeline

The original pipeline proves the whole Cairo statement account and the recursive PROOF1 on
the client ([bounded-memory results](../../../../bounded-memory/README.md)). Its ordinary
payment used four cores of the same development host.

| | Original (client proves everything) | Split, R0 |
| --- | ---: | ---: |
| Client peak, 4 threads | 9.00 GiB normal / 6.12 GiB bounded | 2.2 GiB normal / **1.1 GiB** bounded |
| Client proving, 4 threads | 16.7 s normal / 22.7–23.1 s bounded | 2.5–3.8 s normal / 4.4–5.2 s bounded |
| Server | none | bridge + OS ~10 s, PROOF2 139 s / 64.2 GiB |
| What the server sees | nothing private | the client proof (hiding unproven, see below) |

The two payments are not the same format. The original uses the production felt252 Poseidon
note, nullifier and tree formats. R0 uses an experimental Poseidon2-M31 suite of
equivalent structure.

## What R0 proves (`src/payment.rs`)

These are the ordinary-note rules of `controlled-push-e2e/cairo/src/statement.cairo`, with
controller and policy fields zero, over framed Poseidon2-M31 sponges with 9-word digests:

- **Ownership.** `ak = H(AUTH, sk)`, `nk = H(NK, sk)` and `receiver = H(OWNER, ak‖nk)`;
  `sk` must be nonzero.
- **Input commitment.** `cm = H(NOTE, chain‖pool‖token‖amount₈‖H(INNER, receiver‖rho))`.
- **Membership.** Two independent depth-32 paths, with bits selecting left or right. Both
  must reach the same public root.
- **Nullifiers.** `nf = H(NF, nk‖cm‖pos_lo‖pos_hi)`. Duplicates are rejected publicly, by the
  bridge and by the pool when it marks nullifiers spent.
- **Outputs.** Commitments recomputed from their private openings; `receiver` and `rho`
  must be nonzero.
- **Amounts.** u128 as eight 16-bit limbs, each range-checked by 16 boolean bits, and
  nonzero. `in₀ + in₁ = out₀ + out₁` holds as integers, via a carry chain with carries in
  {-1, 0, 1}.
- **Public statement.** 92 limbs as 23 outputs: tag, chain, pool, token, root, both
  nullifiers, and both output commitments with their delivery digests. There is no in-circuit
  hash.

The circuit has 631,136 qm31_ops rows and 692 eq rows, so a log20 trace. Membership alone
was 253k rows.

Tests (`tests/payment_r0.rs`):
- the circuit statement equals the native reference;
- the topology is independent of the witness;
- five broken witnesses fail the circuit or change the statement: inflated output, wrong
  sibling, wrong position, wrong secret, wrong output rho;
- the native rules reject bad conservation, duplicate inputs and zero receivers.

## Server side

- **Bridge** (`cairo-r0/`, `build_bridge_arith.py`). The fork's `circuit_air` is vendored with
  the generated sections for this shape and `N_OUTPUTS = 23`, and the circuit hash is pinned.
  The bridge decodes the statement. It checks the tag, the canonical felt limbs and that the
  nullifiers are distinct. It computes
  `binding = Poseidon('TMR0_BIND_V1', chain, pool, token, root, nf₀, nf₁, cm₀, d₀, cm₁, d₁)`,
  which is what the pool recomputes from its spend data, as in the reference pool.
- **Account.** It checks the proof's chain against the transaction and emits
  `(class, 'TMPZR0_PAYMENT_V1', chain, pool, binding)`. It is 50,726 Sierra felts.
- **Checks.** The binding matches an independent Python Poseidon (`bench/adr8/ref_poseidon.py`)
  in the bridge run and in the OS capture's exact-message check. The bridge rejects 14 altered
  inputs:
  - tag, nullifier output, commitment output;
  - claimed sum moved to an absent component;
  - proof body;
  - wrong chain, pool, token or root;
  - wrong nullifier, swapped outputs, wrong delivery;
  - trailing and truncated data.

## Not measured here

- **The pool's on-chain transaction** (`apply_spend`): root lookup, nullifier writes,
  appending two commitments to an **M31** tree, and token movement. The accepted pool does
  this on chain after verifying the proof facts. With an M31 tree, the two appends need
  Poseidon2-M31 in Cairo. That is on-chain gas at submission, not proving work, and it is the
  next thing to measure.
- **Hiding** of the uploaded client proof (broody/templar#2), the production formats, WASM, and
  Sepolia gateway acceptance of PROOF2.

## Headroom on the client

- **Padding.** 631k rows are padded to 2²⁰, so about 40% of the trace is padding. Trimming
  rows, or splitting work so the trace fits log19, would roughly halve memory.
- **Unused lanes.** Every Poseidon2 row uses one of four QM31 lanes. Four permutations could
  share each row, since additions are lane-wise and `pointwise_mul` provides lane-wise
  multiplication. That would cut rows up to ~4× for the hashing that dominates this circuit.
