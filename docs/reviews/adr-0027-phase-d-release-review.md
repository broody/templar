# ADR-0027 phases D and E: deployment verification and release review

2026-09-27. The Sepolia deployment of [`docs/pool-v3-spec.md`](../pool-v3-spec.md) §11.1 and the
dual-version release before the swap (§11.2). Records: `bench/adr27-d/results/`.

## Deployment verification (a separate agent, read-only): MATCHES

Every deployed class equals the committed phase C build: the routing adapter's Sierra and CASM,
and the statement account's CASM, which equals the audited V6 bridge build whose record pins the V6
circuit hash. Both adapters' views equal the plan in all eight route fields, with no proposals; the
P1 statement account has only `__validate__` and `__execute__`; pool V3 was unchanged; all six
transactions succeeded from `account-1` (97.98 STRK); the addresses follow sncast's UDC derivation.

## Measurements (cross-checked against the raw artifacts): consistent

V6 through the deployed statement account in the pinned virtual OS on live state, 10 cases: one
message each with the binding recomputed by starknet.js; OS steps at most 3,418,981; bucket 25 with
the largest component 2^23; the virtual transaction's L2 gas 272.5M–274.2M by bisection; a PROOF2
verified with the facts equal to the routing adapter's formula, `facts[5]` the base block's hash and
`facts[6]` the pinned configuration hash (closes PV6-C7).

## Release review (Protocol and attacker, each finding adversarially checked): CONDITIONAL GO

Both reviewers found the pins, the server and relayer configuration and the swap's calldata correct
against the chain, and nothing that would make the apply or the V6 spend fail. The propose was sent
while the review ran (its values checked equal to the plan, both pinned in the SDK). None of the 19
findings blocks the apply; one was refuted as overstated.

| Finding | Severity (after check) | Resolution |
| --- | --- | --- |
| ADV-1: `deposit()` did not re-check the P1 kind in a connected session, so an unpinned P1 change applied after connect went unnoticed | medium | `deposit()` checks the P1 generation too (not withdrawals: §10.3 keeps an exit); test for an unpinned P1 verifier and an unpinned P1 route |
| ADV-2, F3, ADV-5: `cutover.py`'s applies did not check the pending value or each proposal's own window; a lapse could not be re-proposed without replaying checkpoints; drill steps did not require the swap | low | each apply checks its pending value (all eight route fields for the planned route) and its own window with a 300 s margin; `--attempt N` re-sends under new step names and asserts a fresh proposal; drill steps require the R0 swap; the removal refuses to remove the last route |
| F2, ADV-3: the drill's dummy route was the retired V5 statement account, one mistaken apply from live | low | an inert dummy: the test token (deployed, so it passes `check_route`, but it emits no message) with a drill tag |
| F1, ADV-4: the planned route's removal was not pinned, and the SDK matched only the first planned change per key | low | the removal is pinned; `routeProposals` matches any planned change with the same key and value; tests for both orders and for a changed field |
| F4, ADV-6: after the swap, `wrap()` could send a V5 record to a server that refuses it as dormant | low | `prove()` and `wrap()` refuse a record whose generation is no longer the pool's R0 verifier (re-plan) before anything leaves; test |
| ADV-8: §11.4 step 1 (a V5 proof against the routing adapter) not implemented | low | `drill_v5.py`: a fresh spend whose facts carry the retired V5 statement account's message, simulated against the pool. Before the swap the V5 adapter accepted it (the pool then reverted at `UNKNOWN_ROOT`); after the swap it must get `NO_ROUTE` |
| F6, ADV-11: `operator_node` left in the generated config; the e2e summary read a field `/v1/info` lacks | info | removed; the summary reads the relations |
| F7, ADV-7: the relayer not running and no start command | info | the relayer runs on the v6 config (`templar-relayer-v6`); the runbook has absolute paths |
| ADV-10: duplicate-note locks across the swap are unreachable only because of the block-time margin | info | kept: at 1.7 s blocks every V5 deadline passes about 70 minutes before eta |
| F5, ADV-9 | info | the propose was sent during the review; recorded here |

## Check of the fixes (two separate agents, before the apply)

- **The running apply:** exactly two transactions, `pool.apply('R0')` then `pool.apply('P1')`, each
  only if its pending value is the routing adapter, and after its own eta; no path applies anything
  else. **The inert dummy** passes `check_route`, and the token's CASM has no `SendMessageToL1`,
  `ReplaceClass`, `LibraryCall` or `CallContract` syscall, so nothing can match it. **The V5 drill**
  is valid up to the verifier and its facts equal what a V5 PROOF2 carries (compared with a real P6
  V5 job).
- Fixed before the drill: `remove-planned` found the applied block only under the same `--attempt`
  (medium; now from whichever attempt succeeded); drill steps did not assert their post-states
  (now each asserts the proposal or route it produced); drill applies re-read their proposal after
  waiting; the V5 drill gained a positive control (the same spend with the V6 route's message must
  pass the adapter), and it asserts which adapter is the verifier.
- SDK follow-ups: `prove()`'s refusal is tested; a removal counts as usable only if the primary
  route stays active (a future pinned removal of the primary would otherwise be a notice); the
  code `verifier_changed` covering both the cutover re-plan and the alarm is kept for now.
- Before the swap the drill behaves as predicted: the V5 message passes the V5 adapter (the pool
  then reverts at `UNKNOWN_ROOT`), and the V6 control is refused by it (`PROOF_BINDING`).
