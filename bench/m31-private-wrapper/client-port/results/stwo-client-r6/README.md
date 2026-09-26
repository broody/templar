# R0 V6 client relation (ADR-0027 phase C)

2026-09-26. The R0 V6 payment relation of
[`docs/pool-v3-spec.md`](../../../../../docs/pool-v3-spec.md) §4: R0 V5 with `m = 0` and
`account = 0`, so no bound notes, no `WAUTH` hashes and no account limbs. Code:
[`src/payment6.rs`](../../src/payment6.rs); tests:
[`tests/payment_r6.rs`](../../tests/payment_r6.rs) and
[`tests/payment_r6_malicious.rs`](../../tests/payment_r6_malicious.rs) (feature `tamper`); prover:
[`examples/prove_payment_r6.rs`](../../examples/prove_payment_r6.rs). The bridge and statement
account are in [`cairo-r6/`](../../cairo-r6), validated in [`../r6-bridge/`](../r6-bridge).

## Result

| | R0 V5 | **R0 V6** |
| --- | ---: | ---: |
| Statement | 138 limbs + 2 zero, 35 outputs | **129 limbs + 3 zero, 33 outputs** |
| `valid_until` limbs / padding | 136–137 / 138–139 | **127–128 / 129–131** |
| Tags (sponge / compress) | R0V5 / R0C5 | **R0V6 / R0C6** |
| Binding | `TMR0_BIND_V5` | `TMR0_BIND_V5`, unchanged (account 0) |
| Trace (every shape) | 2^18 | **2^18** (spec §4.5) |
| Proof, native, 36 threads | 0.57–0.75 s | 0.73–2.1 s (22 proofs, run beside builds) |
| Proof size | 29.5k–30.6k felts | 28.8k–30.9k felts |
| Blinding rows / revealed FRI values | 2,390 / 1,707–1,782 | 2,390 / 1,677–1,797 |

Circuit hash `[2010035999, 4123906337, 3936982050, 2269257694, 3115244238, 1536739351, 29337086,
2871661834]` ([`trusted-config.json`](trusted-config.json)), pinned by the F38 test
`pinned_circuit_hash_matches_the_code`. All 22 proofs in [`proofs/proofs.json`](proofs/proofs.json)
carry it: the eight shapes, `valid_until` 1 and 2^56 − 1, a repeat, and eleven forgeries the circuit
admits and the bridge must reject (`prove_r6_suite.py`). The debug records the wiring test reads
are written only under `tamper` and do not change the circuit: the hash stayed the same through
every wiring change below.

## Tests

`cargo +nightly-2026-01-15 test --release --test payment_r6` (19 tests) and
`cargo +nightly-2026-01-15 test --release --features tamper --test payment_r6_malicious` (14 tests).

- **Cross-version (MR-V6-6):** every V5-ordinary witness is a V6 witness under φ, and back; a single
  input with its stored companion; identity over `ak = H(AUTH, sk₀)`; the plant test; a bound V5
  note is not spendable under V6.
- **Boundaries:** `valid_until` 1 and 2^56 − 1, `valid_until = 0`, each `valid_until` limb at 2^28,
  each padding limb nonzero, the `R0C6` tag (`bridge_only_rules`); zero input key or randomness
  on a consistent tree; `WAUTH = 16` stays reserved (`wauth_kind_stays_reserved`).
- **F09 and the V4 carry-overs,** each isolated as in V5.
- **The wiring test (§4.4, MR-V6-1, MR-V6C-1),** `wiring_uses_the_same_variables`, compares
  variable ids through `debug_info`. Every consumer records what it receives inside its helper, so
  a guessed copy anywhere on the way is seen. Beyond V5's edges it asserts:
  - `identity.ak == owner₀.ak == auth₀.out`, `authᵢ.in == nkᵢ.in == skᵢ`;
  - every membership hop for both paths: level 0 reads `noteᵢ.out`, level `l + 1` reads level `l`'s
    output, `pathᵢ.root` is level 31's output;
  - the enabled-input gap reads `path₀.root` and `path₁.root`; the idle rule reads the `sum₁` input
    1's amount limbs make;
  - the published `token_out` and `identity` are the outputs of the `x` gate and of the mask.
- **Recorded where produced (NF-M1, NF-M2).** Every wire in `build()` is recorded inside the helper
  that makes it: each guess before its nonzero guard reads it, each amount's limbs and sum where
  `amount_from_bits` returns them, each membership level's request, the payload its hash reads and
  the exact words the hash is handed, and each output's four limbs as they are handed to the gate.
  So no line of `build()` sits between a wire and its record. The published tag limbs and the
  compress tree's `[TAG, 1, NODE1, level]` are asserted to be the circuit's constants.
- **A limit of the wiring test (MR-V6C-8).** It sees `build()`'s wiring, not the inside of its
  helpers. A change inside the shared `hash_batch`, `sponge_lanes` or `amount_from_bits` code, or a
  copy placed inside a recording helper between its record and its return, is not seen by it, nor
  by the value tests; only the F38 pinned-hash test notices, and that test does not count as a
  kill. §4.4's optional check, that each recorded output is an `unpack` lane tied by its repack
  check to a permutation output, is not implemented.

## Mutation table

[`mutants.json`](mutants.json), from [`../../mutate_r6.py`](../../mutate_r6.py): 89 mutants, each
applied to a copy of the crate, both suites run with `--no-fail-fast`, the F38 test skipped.

- **0 survivors, 0 unbuilt.**
- **1 equivalent:** `e1` booleanity deleted. With `e1 ∉ {0, 1}`, the idle rule forces `sum₁ = 0` and
  the root gap forces input 1 onto the published root: an enabled zero-value input, which `e1 = 1`
  already admits. `e1` is not published, so the accepted set is unchanged.
- **Every guessed-copy row (65) is killed by the wiring test itself**; the driver fails otherwise.
  The rows cover the P2 table without its mode and account rows, V6's key rows (a guessed `ak`,
  `nk` into OWNER and NF, AUTH and NK over guessed `sk` copies), the mirror's `R0C6` check, and one
  row per fan-out wire, including the reviews' edges: input 1's root into the gap, `sum₁` into idle,
  the published `token_out` and `identity`, path nodes between levels and into the root, the
  `NODE` request into its hash, copies inside `publish()` and `level_hash()` after their records,
  the published limbs into the outputs, the statement tag and the compress tree's domain constants
  guessed.

## Hiding regression (F27, ADR-0024 gate 4)

[`hiding/`](hiding), from [`../../hiding_r6.py`](../../hiding_r6.py), equal to V5:

| Test | Result |
| --- | --- |
| Unblinded column combinations, all 8 shapes, base + interaction | 0 |
| Seed-invariant combinations of revealed values (single, transfer) | 0 (rank 336 / 336) |
| Per-point rank, `qm31_ops` base columns (single, transfer) | full: 468 / 468 and 6,768 / 6,768 |

F27's structural fixes remain open, as they are for V4 and V5.

## Bridge and pool

- **Bridge** ([`../r6-bridge/`](../r6-bridge)): `validate_bridge_r6.py` runs the built bridge on the
  real proofs, 88 of 88 cases pass: every shape accepted with its binding recomputed, and the
  forgeries, `valid_until = 0`, each `valid_until` limb at 2^28 and each nonzero padding limb
  rejected.
- **Statement account** (`cairo-r6/account_tests`, `snforge test --profile contract`): 10 of 10.
- **Pool end to end** (`bench/m31-pool/v6_pool_e2e.py`,
  [`e2e-v6.json`](../../../../m31-pool/results/pool-v3/e2e-v6.json)): 11 of 11. Real V6 proofs
  through the statement account and the routing adapter into pool V3: a withdrawal, a transfer on a
  replaced root, a two-input spend (input 1 enabled on its own path), and the refusals.
