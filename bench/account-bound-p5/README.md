# P5: account-bound spends in the pinned virtual OS on live Sepolia

`docs/account-bound-note-spec.md` §15 P5. Real Ready and Braavos accounts authorize R0 V5 spends
inside the server's pinned virtual OS, run against live Sepolia state, and the PROOF2 of each run is
measured for the server's caps and the uniformity gate (§12).

**Status (2026-09-26):** measured. Every real-wallet spend runs and proves, and tampered signatures
are refused. PROOF2's public shape is the same in every mode (spec §12, revised gate). The Cairo
trace inside differs in four components, hidden by the leaf circuit's blinding. Summary:
[`results/summary.json`](results/summary.json).

## What ran

- **The statement account** (`deploy_statement.py`) is the audited P3 build, declared and deployed
  on Sepolia (user-approved):
  - class `0x06a2bd80203760b1eb0aee384ae835300c66a24f327b038315d628fbd92b830a`, declared in block
    15,650,601 for 83.57 test STRK;
  - address `0x07748e3ba3fca5228625cf754c0d0e7dd7e7bf3e9c426c5c7bc8dc08d88b6a81`, deployed in
    block 15,650,607 for 0.03 test STRK.

  A first declaration attempt was refused by the node at validation (a stale L1-data-gas price
  bound in the shared helper). Nothing was sent; the script now sets its own bounds.
- **Client proofs** (`prove_payment_r5 --compress-nodes`): ordinary, Ready-bound and Braavos-bound
  spends, each an in-pool transfer and an invoke. The bound proofs name the wallets' real Sepolia
  accounts. P3's signed bound withdrawals from both wallets are reused.
- **Signatures** (`gen_sign_requests.cjs`, the signing page in `cairo-r5/sign`, which now signs a
  list of requests per account). Ready X 5.33.11 and Braavos 4.19.6 each signed the V5 transfer
  and invoke (`VALID` on Sepolia); their P3 withdrawal signatures are reused too.
- **Runs** (`run_p5.py`): each spend's job is built exactly as the prover server builds it, run by
  the server's `templar-os-runner` at the latest block, checked for exactly the expected message,
  proved by `templar-prove` (bounded, 16 columns, 16 threads), and analyzed with the capacity trace
  and `blake_sites` tools.

## Results

**Virtual OS and PROOF2.** Base blocks 15,650,622–15,650,935; `templar-prove` bounded (16 columns,
16 threads). Every OS run emits exactly `[statement class, 'TMPZR0_PAYMENT_V5', chain, pool,
binding]`, and every PROOF2 verifies.

| Spend | Wallet | OS steps | PROOF2 | Peak RSS | Blake | `memory_address_to_id` | `partial_ec_mul_window_bits_9` | Pedersen (both) |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| transfer | ordinary | 3,341,550 | 67.1 s | 30.2 GiB | 13,840 | 18 | 12 | 6 |
| invoke | ordinary | 3,449,147 | 64.6 s | 29.6 GiB | 14,038 | 18 | 12 | 6 |
| transfer | Ready X 5.33.11 (Argent 0.5.0) | 3,554,086 | 63.8 s | 29.7 GiB | 15,046 | 19 | 13 | 7 |
| invoke | Ready | 3,552,516 | 64.3 s | 29.5 GiB | 15,048 | 19 | 13 | 7 |
| withdrawal (P3 signature) | Ready | 3,558,384 | 64.0 s | 29.6 GiB | 15,027 | 19 | 13 | 7 |
| transfer | Braavos 4.19.6 (1.2.0) | 3,606,742 | 66.6 s | 29.1 GiB | 15,097 | 19 | 13 | 7 |
| invoke | Braavos | 3,556,404 | 67.4 s | 29.3 GiB | 14,990 | 18 | 13 | 7 |
| withdrawal (P3 signature) | Braavos | 3,550,233 | 64.1 s | 29.1 GiB | 14,970 | 18 | 13 | 7 |

- **Tampered signatures** (the last felt's low bit flipped), Ready and Braavos: the virtual OS
  refuses the transaction ("Reverted transactions are not supported"), which the server counts as
  the client's fault.
- **Signatures:** Ready signs `[r, s]` and Braavos `[1, r, s]`; all six are `VALID` on Sepolia and
  inside the virtual OS.
- **The account call** costs 105–265k OS steps, about 1.0–1.3k more Blake (OS class hashing), 3 EC
  ops and about 57 more Pedersen instances (the Stark ECDSA check).

**Uniformity gate (§12, revised): holds on PROOF2's public shape.** The gateway receives the
large-proof path's leaf-verifier circuit proof:
- all eight proofs share one header, version `0x0204` and bucket 25's root `daaf3bd0…`;
- the circuit's own sizes are fixed by the registry;
- the proofs are 243–256 KB compressed, overlapping across modes.

The Cairo trace is that circuit's witness, blinded (`zk_blinding: true`). Every spend has the same
largest Cairo component (log 21: `blake_g`, `cube_252`, `range_check_252_width_27`). But four Cairo
component log sizes differ:
- `partial_ec_mul_window_bits_9` (12 → 13), `pedersen_builtin_narrow_windows` and
  `pedersen_aggregator_window_bits_9` (6 → 7) tell a bound spend from an ordinary one;
- `memory_address_to_id` (18 or 19) sits near a threshold and varies with the vendor and the shape.

Ready and Braavos are not told apart by the first three. These sizes are visible only if PROOF2's
blinding leaks structure, so hiding the mode rests on PROOF2's hiding (the ADR-0024 gate), like the
rest of the trace. Padding every mode to `memory_address_to_id` 19, `partial_ec_mul_window_bits_9`
13 and both Pedersen components 7 is written but paused, on a local proving-fork branch
(`templar/uniform-padding`), as defence in depth.

**Caps for the server.** OS steps at most 3.61M (the 4M default leaves 11%). Builtin instances at
most:
- `range_check` 357,590;
- `poseidon` 15,610;
- `pedersen` 109;
- `ec_op` 3;
- `output` 6;
- none of the others.

The example configuration caps them at about +25%. P1 was not measured, so a server that serves p1
should measure it before capping builtins.

**WASM proof time** (headless Chrome 153, three runs each, seeded):

| Relation | Prove | Linear memory |
| --- | ---: | ---: |
| R0 V4 (determinism vector, identical) | 5.5–5.7 s | 257 MiB |
| R0 V5 bound withdrawal | 4.8–7.8 s (median 6.2 s) | 257 MiB |

**Expiry against `E`.** Sepolia's block time is 1.69 s (over 2,000 blocks), so `E` = 1,500 blocks
is about 42 minutes. A spend's `valid_until` is 1,500–1,600 blocks after planning. The pipeline
takes about 70–110 blocks without a queue:
- the WASM proof, a few seconds;
- the bridge pre-check;
- the virtual OS, about 18 s;
- PROOF2, about 65 s;
- `submit_after`, 11 blocks;
- inclusion.

The server admits a job while `valid_until ≥ latest + (jobs ahead + 1)·60 + 71`, so about 22 jobs
ahead still fit. A spend therefore expires only behind a queue that long, or after more than about
40 minutes of signing delay.

**Small path.** Three components are at log 21 in every mode, ordinary spends included (and R0 V4's,
per P0b), so no spend fits the log-20 small path (ADR-0024's fallback). V5 does not change that.

## Commands

```bash
python3 bench/account-bound-p5/deploy_statement.py --check     # read-only
python3 bench/account-bound-p5/run_p5.py cases
python3 bench/account-bound-p5/run_p5.py os CASE [--tamper]
python3 bench/account-bound-p5/run_p5.py prove CASE
python3 bench/account-bound-p5/run_p5.py analyze CASE
python3 bench/account-bound-p5/run_p5.py report
```

The run directory is `~/.local/share/templar/runs/account-bound-p5` (`TEMPLAR_P5_RUN`).
