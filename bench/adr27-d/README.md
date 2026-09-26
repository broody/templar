# ADR-0027 phase D: R0 V6 and the routing adapters on Sepolia

[`docs/pool-v3-spec.md`](../../docs/pool-v3-spec.md) §11.1. **Status (2026-09-27):** deployed by the owner (05:51–05:52) and independently verified; V6
measured on live state; the dual-version server running. Pool V3 still has its V5 adapters until
phase E. Records: [`results/deployment.json`](results/deployment.json),
[`results/measure-v6.json`](results/measure-v6.json).

| Contract | Address | Class |
| --- | --- | --- |
| V6 statement account | `0x13f79bef808bc5e20c7542ea41bd649ab012c4224c95c1a165ab29a86ad5ce7` | `0x03be56fa…9a4b` (61,893 CASM felts) |
| V6 statement, planned route (§11.4 drill) | `0x61b33150738c10d59615372b2424cf0011afbfb79a24e51fb042eb5fb2825f2` | the same |
| R0 routing adapter | `0x6a4b3e9ff38df6d9f2e3218fff0f3c1d2ea0ef9878231a6b154b754dfba879c` | `0x046104020e01c065bb55e262c1c3b7dbf4bca22448bcfbd411d5bcbec58d490b` (12,367 CASM felts) |
| P1 routing adapter | `0x3b33e246397f4542792d55d22455097616c6379e86ed38b7462f70430b81348` | the same |

Cost: 97.98 test STRK (declarations 81.95 and 15.59; the four deploys 0.43).

**Verification** (a separate agent, read-only): every class on chain equals the committed build (the
adapter's Sierra and CASM; the statement's CASM equals the audited phase C bridge build, whose
record pins the V6 circuit hash); both adapters' views equal the plan in all eight route fields,
with no proposals; the P1 statement has only `__validate__` and `__execute__`; pool V3 unchanged
(verifiers, proposals, owner, parameters); all six transactions succeeded from `account-1`; the
addresses follow sncast's UDC derivation from the recorded salts.

**V6 on live state** (`measure_v6.py`, cross-checked against the raw artifacts by another agent):

| | Result |
| --- | --- |
| Virtual OS, the 8 shapes and `valid_until` 1 and 2^56 − 1 | all run; one message each, `[class, 'TMPZR0_PAYMENT_V6', chain, pool, binding]` with the binding recomputed by starknet.js |
| OS steps | 3,350,679–3,418,981 (the cap stays 4M) |
| Builtins, maximum | Poseidon 15,359, range check 345,580, Pedersen 50, output 6 (within the P5 caps) |
| L2 gas of the virtual transaction (bisected, `full`) | 272.5M–274.2M (the server's bound stays 450M; the node refuses estimates above 10,000 calldata felts) |
| PROOF2 bucket | 25 for every case; largest component 2^23; the check takes ~10 s and ~16 GiB |
| PROOF2 (`transfer`) | 64 s, 29.7 GiB, 255 KB, verified; header bucket 25; facts `[PROOF2, VIRTUAL_SNOS, os_program, VIRTUAL_SNOS0, base block, its hash, config hash, 1, message hash]` with the message hash equal to the routing adapter's formula (PV6-C7) |

The proofs measured are phase C test witnesses (their `pool` is a test id), so they measure the
statement account's resources and message, not spends pool V3 accepts; §11.3's end to end spends a
real note.

**The release** (§11.1 step 3): the SDK's SEPOLIA constant pins both routing generations and P1's
pre-cutover adapter; the server runs `prover-v6.toml` (`r5` serving, `r6` dormant until the swap,
`p1` through its legacy adapter, the bucket reference `measure/full`); the relayer config carries
the same pins. The SDK's pre-swap check (`sdk/ts/bench/sepolia-v6-e2e.mjs check`) sees R0 on the V5
generation, P1 on its legacy adapter, no proposals, and deposits allowed.

`deploy.py` declares and deploys, from
`account-1` through sncast, the phase C builds:

| Step | Contract | Notes |
| --- | --- | --- |
| 1 | declare the V6 statement account `PaymentVerifierAccount` | the phase C bridge build (`runs/r6-p1/bridge`, circuit hash `[2010035999, …, 2871661834]`, tag `TMPZR0_PAYMENT_V6`); the declaration copy enables gas and must give the audited `contract`-profile CASM (61,893 felts) |
| 2 | deploy it twice | the V6 route's statement, and a second instance (another salt) for the §11.4 drill's planned route |
| 3 | declare `RoutingAdapter` | bench/m31-pool/cairo |
| 4 | deploy the R0 routing adapter | pool V3, kind `R0`, the V6 route |
| 5 | deploy the P1 routing adapter | pool V3, kind `P1`, the P1 route below |

Then it reads both adapters back (§11.1 step 2). Pool V3 keeps its V5 adapters until phase E.
`python3 deploy.py --check` is read-only (classes, balance, declaration estimates); without flags it
prints the plan; `--i-approve-onchain-transactions` sends. Steps are checkpointed in
`~/.local/share/templar/runs/adr27-d/sepolia/steps`; the record goes to `results/deployment.json`.

Every route: `os_program` 0x53f6…daa1, `PROOF2` / `VIRTUAL_SNOS` / `VIRTUAL_SNOS0`,
`max_proof_age` 1,024 (§6.4).

## The P1 route's statement account against §6.5

The P1 route pins the statement account P6's P1 adapter already pins:
`0x052828eb…2d70a`, class `0x032e05ae…6a882` (pool V2's P1 statement account, with the H2 circuit
fix; circuit hash `[1116583792, …, 1128236499]`).

| §6.5 rule | Evidence |
| --- | --- |
| No constructor arguments, no storage reads, no external calls | the deployed class has no constructor entry point; the source (`client-port/cairo-p1/account/src/lib.cairo`) has empty storage and calls only syscalls (execution info, its own class hash, the L2→L1 message) and the bridge's pure verifier |
| No `replace_class`, no `library_call` into mutable code | none in the account or the bridge (`grep` over `cairo-p1/`) |
| One message, only from `__execute__` behind the caller-0 guard, payload `[runtime class, tag, chain, pool, binding]` | `__execute__` asserts `OS_ONLY` and emits `[class_hash, 'TMPZP1_POLICY_V1', chain, pool, binding]`; the pool's `policy_binding` settles it (pool V2 and the routed P1 test in `test_pool_v3`) |
| `__validate__` is `PROVE_ONLY` | tip 0 and every resource bound's price 0 |
| No `is_valid_signature` | the deployed class's external entry points are `__validate__` and `__execute__` only |

## Estimates (2026-09-26, `--check`)

| | L2 gas | Fee at the block price | Bound |
| --- | ---: | ---: | ---: |
| declare the statement account | 4,137M | ~84 STRK | 141 STRK |
| declare `RoutingAdapter` (12,367 CASM, 4,918 Sierra felts) | 787M | ~16 STRK | 36 STRK |
| four deploys | ≤ 60M each | < 1.5 STRK each | 2.4 STRK each |

The sum of the bounds, about 187 STRK, is within the owner's 1,000 STRK preapproval for phases D
and E, which applies only after a GO review.

## Runbook (phases D and E)

Every sending step takes `--i-approve-onchain-transactions`; without it a script prints its plan
and sends nothing. All transactions come from `account-1` through sncast, which reads the key.
Steps are checkpointed, so a rerun resumes and never resends a recorded transaction.

```bash
# Phase D (§11.1)
python3 bench/adr27-d/deploy.py --check                                  # read-only
python3 bench/adr27-d/deploy.py --i-approve-onchain-transactions         # declare, deploy, read back
python3 bench/adr27-d/measure_v6.py os                                   # V6 in the virtual OS on live state (nothing sent)
python3 bench/adr27-d/measure_v6.py bucket
python3 bench/adr27-d/measure_v6.py l2 full                              # L2 gas by bisection (the node refuses the estimate)
python3 bench/adr27-d/measure_v6.py prove transfer                       # PROOF2, ~30 GiB; checks the facts (PV6-C7)
python3 bench/adr27-d/measure_v6.py report                               # results/measure-v6.json
python3 bench/adr27-d/configs.py --bucket-reference ~/.local/share/templar/runs/adr27-d/measure/full
systemd-run --user --unit=templar-prover-v6 -p Delegate=yes server/prover/target/release/templar-prover serve RUN/prover-v6.toml
node sdk/ts/bench/sepolia-v6-e2e.mjs ~/.local/share/templar/runs/account-bound-p6 check      # read-only
systemd-run --user --unit=templar-relayer-v6 --working-directory=$PWD/server/relayer /usr/bin/node $PWD/server/relayer/relayer.mjs RUN/relayer-config-v6.json

# Phase E (§11.2-§11.4)
python3 bench/adr27-d/cutover.py status
python3 bench/adr27-d/drill_v5.py                                         # before the swap: the V5 adapter accepts the V5 message (UNKNOWN_ROOT later)
python3 bench/adr27-d/cutover.py propose --i-approve-onchain-transactions
node sdk/ts/bench/sepolia-v6-e2e.mjs ~/.local/share/templar/runs/account-bound-p6 check      # two pinned verifier proposals: notices
node sdk/ts/bench/sepolia-v6-e2e.mjs ~/.local/share/templar/runs/account-bound-p6 deposits   # allowed (pinned, §10.3)
python3 bench/adr27-d/cutover.py apply --i-approve-onchain-transactions  # waits for eta (T = 7,200 s)
python3 bench/adr27-d/drill_v5.py                                         # §11.4 step 1: the V5 message gets NO_ROUTE, the V6 control passes the adapter
node sdk/ts/bench/sepolia-v6-e2e.mjs ~/.local/share/templar/runs/account-bound-p6 withdraw   # §11.3, up to the gateway
python3 bench/adr27-d/cutover.py dummy --i-approve-onchain-transactions  # SDK alarm, server keeps serving
node sdk/ts/bench/sepolia-v6-e2e.mjs ~/.local/share/templar/runs/account-bound-p6 deposits   # refused: an unpinned route change
python3 bench/adr27-d/cutover.py cancel-dummy --i-approve-onchain-transactions
python3 bench/adr27-d/cutover.py planned --i-approve-onchain-transactions
node sdk/ts/bench/sepolia-v6-e2e.mjs ~/.local/share/templar/runs/account-bound-p6 deposits   # allowed: the planned route is pinned
python3 bench/adr27-d/cutover.py apply-planned --i-approve-onchain-transactions
python3 bench/adr27-d/cutover.py remove-planned --i-approve-onchain-transactions   # ≥ 1,024 blocks after apply-planned
python3 bench/adr27-d/cutover.py apply-removal --i-approve-onchain-transactions
```

`RUN` is `~/.local/share/templar/runs/adr27-d` (`TEMPLAR_ADR27_RUN`).
