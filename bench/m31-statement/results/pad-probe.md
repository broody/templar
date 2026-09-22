# M31 payment statement — pad-cost probe (step 2)

Recorded 2026-09-22. Measures the cost of hiding-style padding on the
payment-shaped M31 statement (step-1 harness, [measurements.md](measurements.md)):
B random valid permutation rows appended before power-of-two padding, driven
by deterministic `pad_seed`/`pad_count` statement fields.

**Scope caveat:** this probes COST only. The probe's pad values are
deterministic and carried in the statement — real hiding pads are
prover-private (only commitments appear in the proof). Proving cost is
identical either way; no hiding claim attaches to this run.

## Result

| B (pad rows) | total rows | log | Peak RSS | complete | proof bytes |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 256 | 8 | 11.6 MiB | 0.13 s | 170,478 |
| 380 | 512 | 9 | 24.1 MiB | 0.36 s | 175,950 |
| 892 | 1,024 | 10 | 48.1 MiB | 0.17 s | 179,886 |

All runs prove and natively verify. RSS fits
`machinery (~5 MiB) + rows × 1,172 cols × 32 B (LDE ×8)` — extrapolation to
log 11 (2,048 rows): **~80–85 MiB**, confirming the inventory's ~77 MiB
full-coverage-pad estimate. Wall time stays sub-second throughout; proof
size grows ~9 KB over the sweep (lifting-domain FRI growth).

## Findings

1. **The hiding premium on the thin M31 statement is measured, not
   estimated: ~+37 MiB at half coverage (B=892), ~+70 MiB extrapolated at
   full coverage (B≈1,700 against D_obs ≈ 40k functionals at ~24 free M31
   per pad).** Client total with hiding: **~80–90 MiB — two orders of
   magnitude below the felt statement's hiding-adjusted class** and
   browser/phone-trivial.
2. **The vendored AIR caps at 1,024 requests** (`padded()` sanity bound in
   the reviewed `m31.rs`). The full-coverage budget (total 2,048 rows)
   requires a cap raise in a v2 AIR — a reviewed-source change, recorded as
   gated work. At the current cap, B=892 (~21k free M31) is the measured
   maximum.
3. Pad rows participate in the lookup boundary identically to semantic rows
   (multiplicities), so the claimed-sum accounting absorbs them by
   construction — the same mechanism the real blinding entries would use.

## Reproduction

```bash
cd bench/m31-statement/client
PATH="/usr/bin:/home/broody/.cargo/bin:/bin" ./target/release/templar-m31-statement \
  --probe-pads /tmp/pads          # sweep + per-level fixture.json + summaries
# per-level RSS:
PATH="/usr/bin:/home/broody/.cargo/bin:/bin" /usr/bin/time -v \
  ./target/release/templar-m31-statement /tmp/pads/pad-892/fixture.json /tmp/run
```

Artifacts: `results/pad-probe/` (per-level summaries + fixtures copied).
Machine: i9-10980XE, 125 GB. Single-run class.
