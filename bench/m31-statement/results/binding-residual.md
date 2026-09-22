# Felt252 binding residual — design note (step 3)

Recorded 2026-09-22. Companion to [../inventory.md](../inventory.md) §2
(component 2) and [measurements.md](measurements.md). Resolves what the
chain interface actually costs the M31 proof.

## The design finding: the residual can be ~zero

The inventory's "~30–60 MiB" estimate assumed the proof must ingest felt252
values as 28 nine-bit limbs with range checks (the Cairo-VM pattern). That
is only necessary if the proof must *compute* felt252 semantics. With a
**word-tuple facts convention** it must not:

- Every public value the proof binds to (root, nullifiers, leaves, chain,
  pool, version, amounts) is communicated as a tuple of M31 words
  (< 2³¹), each of which fits a felt252 trivially. The proof mixes the
  words; the contract receives them as proof facts (one felt per word) and
  compares against its own decomposition of the on-chain felt values.
- The on-chain decomposition/comparison is felt arithmetic *on-chain* —
  cheap, no hashing, no proof work.
- Tree nodes and nullifiers are M31-native in v2 (that is the point of the
  redesign), so no felt hashing exists anywhere in the statement.

**Result: the proof contains zero felt252 arithmetic.** The "binding
residual" as originally imagined (limb-equality + range-table ladder)
dissolves into a wire convention.

## What remains: amount semantics (measured)

The one piece with real proof-side semantics is the note amount. Measured
today (this step):

- **Amounts bound into leaf preimages**: `leaf = H(secret ++ amount)` —
  the amount enters the sponge payload (10 ≤ 15 words → still one sponge
  block per leaf). Measured: **identical cost to step 1** — 132 requests,
  256 rows, **~11 MiB RSS, 0.11 s**, proof ~171 KB, 16 mutations rejected.
  The amount is now private-inside-the-hash, bound to the note.
- **Amount bound**: < 2³⁰, host-checked in this measurement harness. An
  in-proof range check is required for the real statement (host checks are
  not verifier authority — the standing review rule). Estimated cost: a
  15-bit-pair decomposition with two lookups into a 2¹⁵-row table
  (~32k × 2 cols ≈ **~2 MiB LDE**) plus a few constraint columns — the
  v2 range component.
- **Value conservation**: with amounts < 2³⁰ each, two-input conservation
  (`in₀ + in₁ = out + fee`) is a **carry-free M31 equation** — a few
  linear constraint columns, ~zero cost — provided a no-carry bound is
  enforced. Wider amounts (62/124-bit, for tokens needing more resolution)
  can use QM31-represented addition where the 2¹²⁴ modulus kills the
  aliasing window; that variant is a v2 design option, not exercised.

## Where this leaves the client budget

| Piece | Cost |
| --- | --- |
| M31 statement (measured) | ~11 MiB |
| Amounts in preimages (measured) | +0 (same 132 requests) |
| In-proof range component (est.) | ~2 MiB |
| Conservation constraints (est.) | ~0 |
| Hiding pads at full coverage (measured extrapolation) | ~+70 MiB |
| **Client total with hiding** | **~0.1 GiB** |

The felt252 binding residual is no longer a cost line item at all — the
remaining client cost is the hiding pads and one small range component.

## Caveats

- The word-tuple facts convention is a protocol change (fact format,
  contract checks, indexer) — recorded as v2 integration work, gated as
  usual.
- The 2³⁰ amount bound and the conservation shape are measurement-grade
  choices, not format decisions; the real v2 amount design (width, fee
  model, conservation placement) is a format question for the gated design
  phase.
- Run recorded in `results/summary-amounts.json`; the negative battery
  (16 rejections + padding control) passes identically.
