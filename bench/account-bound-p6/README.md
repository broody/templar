# P6: pool V3 on Sepolia, and the end to end with a real Braavos account

`docs/account-bound-note-spec.md` §15 P6. Pool V3 and its adapters are deployed on Sepolia. The SDK,
the prover server and the relayer then carried a bound and an ordinary spend, for a real Braavos
account, up to the gateway.

**Status (2026-09-26):** deployed. Everything runs end to end up to the gateway, including the wallet's
fallback submission. The gateway refuses large proofs (`Proof version … (PROOF2) is not accepted by this gateway`). Records:
[`results/deployment.json`](results/deployment.json), [`results/e2e.json`](results/e2e.json)
(public data only).

## Deployment (`deploy.py`, user-approved)

| Contract | Address | Class |
| --- | --- | --- |
| M31 pool V3 | `0x03463a80930b97683671b68c6a34feb3ae2ed494bd8cd477cd602dd4ef6a8aa6` | `0x013168df…cfdf` (80,052 CASM felts; source unchanged since the reviewed P3b commit) |
| R0 V5 adapter | `0x0078469651c628d0aa30a3bb3d6f762ecfe89308b62c9db4eec8f6a0232c2e7d` | the declared `Proof2Adapter` (`0x064148ae…6ddb`) |
| P1 adapter | `0x05681433cadd7f40e7fc62fa8bca9a1ca21ed7dcb4a8f09a5f526c83bd82f8d0` | the same class |

Reused, not redeployed:
- the R0 V5 statement account from P5 (`0x07748e3b…6a81`);
- pool V2's P1 statement account (`0x052828eb…d70a`), whose circuit carries the H2 fix;
- the virtual OS program `0x53f6c9fc…daa1`.

**Parameters, against §8.4's floors:**

| Constant | Value | Floor |
| --- | --- | --- |
| `E` | 1,500 blocks (about 42 min) | from P5's pipeline |
| `Q` | 100 blocks | — |
| `W` | 4,096 blocks | ≥ `E` + `Q` = 1,600 ✓ |
| `T` | 7,200 s | Sepolia; above `E` + `Q` (about 45 min). Mainnet needs at least 7 days. |

The adapters use `max_proof_age` 1,024. `initialize` set both verifiers and an empty shadow-class
allowlist, so there is no `COMPUTE` route until a class is reviewed and proposed through the
timelock. The owner is `account-1`.

The script read back `get_verifier` (R0, P1), `get_parameters`, `get_owner` and the pool's class.

Cost: declaration 104.8 test STRK; the pool, the adapters and `initialize` 0.37 in total.

## End to end (`relayer_account.py`, `configs.py`, `sdk/ts/bench/sepolia-v3-e2e.mjs`)

Setup:
- **Relayer account.** A fresh key generated in the run directory; `account-1`'s key stays with
  sncast. `account-1` sent it 40 STRK and 3,000 token A, and it deployed itself: 0.14 STRK in
  fees.
- **Prover server.** Pool V3, relations r5 and p1, bound mode on the local node for Argent 0.5.0
  and Braavos 1.2.0, the P5 caps, the relay handoff, no payment. Its startup checks pass against
  the chain.
- **Relayer.** `server/relayer` with that account.
- **Signing.** The local signing page (`cairo-r5/sign`) connects the user's Braavos 4.19.6 account
  `0x665f820f…58db`.

| Stage | Result |
| --- | --- |
| Bound setup check | Braavos 1.2.0 passes; the setup message is `VALID` |
| Deposits of 1,000 token A (ordinary wallet; bound wallet) | landed: 4.07 and 3.48 STRK |
| Sync | both complete, 1,000 spendable each |
| Bound transfer: 400 inside the pool, change to the bound wallet | WASM proof 8.4 s; the Braavos spend signature is `VALID`; the server's admission, virtual OS and large proof take 101 s |
| Ordinary full withdrawal: 1,000 to the relayer | WASM proof 12.2 s; server 101 s |
| Relayer, both spends | claims the job, simulates the exact transaction with validation, sends it, and answers with the signed hash (`submitted`) |
| Gateway, both spends | `Proof version 88314448135730 (PROOF2) is not accepted by this gateway` |
| Wallet fallback, withdrawal | waits until block 15,657,508 (the window opens 40 blocks before the deadline, 15,657,546; the relayer's hash was unknown to the node, so it could not count as failed). Then the fee estimate (maximum 14.1 STRK, expected 4.7), the exact transaction simulated with validation, and the send: refused with the same gateway error code (63) as the relayer's sends |

**Deposit fees.** sncast's default OpenZeppelin account class is Sierra 1.6.0. Below Sierra 1.7,
Starknet bills the pool's hashing by Cairo steps, hence 3.5–4.1 STRK against 2.07 from an Argent
0.5.0 account on pool V2. A production relayer should use a Sierra 1.7+ account class.

## Commands

```bash
python3 bench/account-bound-p6/deploy.py --check                 # read-only
python3 bench/account-bound-p6/relayer_account.py --check        # read-only
python3 bench/account-bound-p6/configs.py                        # writes the server and relayer configs
systemd-run --user --unit=templar-prover-p6 -p Delegate=yes server/prover/target/release/templar-prover serve RUN/prover-v3.toml
systemd-run --user --unit=templar-relayer-p6 node server/relayer/relayer.mjs RUN/relayer-config.json
systemd-run --user --unit=templar-sign-p6 --working-directory=bench/m31-private-wrapper/client-port/cairo-r5/sign \
  python3 serve.py RUN/sign/requests.json RUN/sign/results 8766
node sdk/ts/bench/sepolia-v3-e2e.mjs RUN                         # one stage per run; CONFIRM_DEPOSITS=yes, FALLBACK=yes
python3 bench/account-bound-p6/collect.py                        # results/e2e.json
```

`RUN` is `~/.local/share/templar/runs/account-bound-p6` (`TEMPLAR_P6_RUN`).
