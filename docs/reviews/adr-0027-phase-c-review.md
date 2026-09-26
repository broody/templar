# ADR-0027 phase C: implementation review (R0 V6, routing adapter, r6)

2026-09-26/27. The phase C implementation of [`docs/pool-v3-spec.md`](../pool-v3-spec.md): the R0 V6
relation (`client-port/src/payment6.rs`), the V6 bridge and statement account (`cairo-r6/`), the
routing adapter (`bench/m31-pool/cairo/src/routing_adapter.cairo`), and r6 in the prover server,
the relayer and the SDK. Three independent reviewers (Math, Protocol, attacker), each with an
adversarial verification of every finding, then a targeted re-check by fresh reviewers. None of
the reviewers wrote the change.

## First review: CONDITIONAL GO from all three

No soundness defect in the relation, the bridge, the statement account or the adapter. V6 accepts
exactly what V5 accepts with `m = 0` and `account = 0`, under φ, in both directions; the Rust mirror
accepts exactly what the Cairo bridge accepts; `TMR0_BIND_V5` is byte-identical to the pool's
`compute_binding`; all eight KAT bindings recompute independently. The findings were gaps in test
evidence that §4.4 and §6.3 make normative.

| Finding | Severity (after verification) | Resolution |
| --- | --- | --- |
| MR-V6C-1 / ADV-V6-1: the wiring test missed five edges (input 1's root in the gap, the published identity and `token_out`, interior Merkle nodes, `sum₁` into idle) | high / medium | every membership hop and the gate outputs recorded and asserted (§4.4 amended: `NODE` outputs) |
| MR-V6C-2 / ADV-V6-2: the mutation table was invalid (helper panic), with a no-op row, fail-fast, no equivalence notes | medium / low | driver fixed (`--no-fail-fast`, edits must change the source, every copy row must be killed by the wiring test); table regenerated |
| MR-V6C-3: `e1` booleanity survives, undocumented | low | recorded as equivalent, with the argument |
| MR-V6C-4: the V6 KAT vectors not tested outside Cairo | low | server `r6_binding_matches_starknet_js` (all eight); the SDK already checked them |
| MR-V6C-5: the hiding regression not recorded | info | `results/stwo-client-r6/README.md` |
| MR-V6C-6: `prove_r6_suite.py` masked its trace assertion | low | fixed |
| MR-V6C-7: no V6 test of the `WAUTH = 16` reservation | info | `wauth_kind_stays_reserved` |
| MR-V6C-8: the wiring test does not see inside shared hash code | info | stated in the README |
| PV6-C1: no positive P1 activation-gate test | low | `p1_activation_gate` |
| PV6-C2: removal effects and same-key replacement values untested | low | `apply_window_and_effects`, `same_key_replacement_takes_the_new_value` |
| PV6-C3: `verify` did not re-check the statement's class | info | adopted as defence in depth (`ROUTE_CLASS`); §6.2 and §6.5 state its limit |
| PV6-C4: no routed P1 test through the pool | low | `policy_spends_through_a_p1_routing_adapter` |
| PV6-C5: route vectors copied as literals | low | `sdk/vectors/routing.json` from `gen_routing_vectors.py`, read by Cairo, server and SDK |
| ADV-V6-3: a removed key could be re-added with other fields | info | retired keys (`ROUTE_RETIRED`), §6.1 and §6.3 amended |
| ADV-V6-4: no pending-route rejection test; single-input e2e only | info | `verify_follows_route_changes` checks `NO_ROUTE` before apply; the e2e adds a two-input spend |
| PV6-C6, PV6-C7, PV6-C8 | info | phase D and E items (below) |

Each adapter fix is pinned by a mutant it kills (`bench/m31-pool/mutate_routing.py`,
`results/pool-v3/routing-mutants.json`).

## Re-check

- **Math: CONDITIONAL GO**, nothing blocking the deploy. MR-V6C-3 to -9 closed; MR-V6C-1 and -2
  partially: its own mutants showed four more windows where a guessed copy could sit between where
  a wire is made and where it is recorded (NF-M1, medium: `sum₁` and `amt₁` before their records,
  the `NODE` payload, the published limbs before the outputs), plus guard-then-record windows and
  an unasserted tag (NF-M2, low); and two missing rows (sk₁ into NK₁, pack hi).
  - Resolution: every wire in `build()` is now recorded inside the helper that makes it (guesses
    before their guards, amounts where `amount_from_bits` returns them, each level's request and
    the payload its hash reads, the published limbs where they become outputs); the published tag
    limbs are asserted to be the circuit's constants; the rows are added. The circuit hash is
    unchanged. Helper-internal windows are the MR-V6C-8 class, stated in the README.
- **Protocol: GO.** Every condition closed; PV6-C3 adopted and closed. Non-blocking:
  - PR-RC-1 (info): no test showed that a class change bricks only its own route →
    `class_change_bricks_only_its_route`, and mutants B18 and B24 added to `mutate_routing.py`. The
    reviewer's other survivors (B6, B7, B8, B17, B19, B25) are equivalent: unreachable defensive
    checks or state no view shows.
  - PR-RC-2 (low): a routed P1 served through its legacy adapter used its own route's values →
    `check_relation` requires them to equal the legacy adapter's while `legacy_adapter` is set.
  - PR-RC-3 (info): `ROUTE_CLASS` precedes the age bound (noted in §6.2); the admission tests'
    scratch directory follows `TEMPLAR_TEST_DIR`.
  - PV6-C8: the relayer no longer denies notes after a verifier or route revert (§7.3;
    `isVerifierRejection`).
- **Attacker: CONDITIONAL GO**, nothing blocking the deploy. ADV-V6-2 and ADV-V6-3 closed; its
  own adapter mutants (a broken swap-remove, a clear without the swap, skipping `ROUTE_EXISTS`,
  matching on `facts[8]` alone) all killed. ADV-V6-1 and ADV-V6-4 partially closed because of:
  - ADV-RC-1 (low): copies inside `publish()` and `level_hash()` after their records survived, and
    a forge demo turned them into valid circuits publishing a swapped asset, a forged identity, an
    inflated withdrawal or a fake membership → each output's four limbs and each hash's exact input
    words are now recorded next to the gate call and asserted (`publish.chunk{k}`,
    `path{p}.level{l}.state`); rows A3b and A10b added.
  - ADV-RC-2 (low): six rows of the updated driver did not compile, and `mutants.json` was stale
    → each copy is bound before `publish()`; the table is regenerated on the final `payment6.rs`.
  - ADV-RC-3 (info): the compress tree's domain constants were unguarded → asserted to be the
    circuit's constants `[TAG, 1, NODE1, level]`; row A8 added.
  - ADV-RC-4 (info): the SDK's route decoders threw raw errors on hostile RPC text, read a negative
    count as zero, and could display two tag felts alike → typed refusals, bounded counts, and a
    non-printable tag shown as hex. The pinned decision already compared raw felts.

## Phase D and E items carried

- PV6-C7: the V6 virtual-OS run on live Sepolia state, checking the facts against the adapter's
  formula (`bench/adr27-d/measure_v6.py`).
- PV6-C8: pin the new `RoutingAdapter` class hash in the release.
- PV6-C6: the §11.4 drill simulates a real V5 proof against the routing adapter.

## The bucket check (added after the re-check started)

The PROOF2 bucket check (§9.3): `templar-prove bucket`, the server's pre-proving and post-proving
checks, and the startup reference job. A separate reviewer, who did not write it, confirmed in the
pinned fork that the header maps one-to-one to the leaf trace log size, that `bucket` replicates the
leaf run exactly, that the header decoding is right, and that griefing is not practical (the fixed
statement class, the bridge, the OS caps and per-note back-off; the P6 job's largest
data-dependent component is 2^21 against 2^25). **CONDITIONAL GO:**

| Finding | Severity | Resolution |
| --- | --- | --- |
| F1: the largest size was taken by zipping enabled-only sizes with all enable bits, which dropped four components | high | the size is `claim.log_sizes()`'s maximum, as the prover computes it; the flat claim is checked against it |
| F2: an unset `bucket_reference` only warned | medium/low | required to serve a routed relation |
| F3: spec wording | low | §9.3 and the server spec aligned; a bucket miss is always the server's fault |
| F4: the bucket sandbox used the proving timeout | low | the OS timeout |
| F5: `bucket_log_size` unvalidated | low | 25 to 29, published in `/v1/info` |
| F6, F7, F8: P1's leaf size, the V6 margin across shapes, builtin caps | info | measured in phase D (`bench/adr27-d/measure_v6.py`); P1 before routing it |
| F9: the admission test covered only the pass path | info | a bucket miss fails at the `bucket` stage and backs the note off |
