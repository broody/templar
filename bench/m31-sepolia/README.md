# Sepolia run: option-A pool with R0 client proofs wrapped in PROOF2

## Outcome (2026-09-23): the Sepolia gateway rejects PROOF2

Everything up to submission ran live on Sepolia. The gateway then refused the transaction on
its version alone:

> `StarknetErrorCode.PROOF_VERSION_NOT_ALLOWED`: Proof version 88314448135730 (PROOF2) is not
> accepted by this gateway.

The rejection is stateless: no fee was charged and no nonce was used. The OS-level versioned
constants (0.14.4) list PROOF2 as allowed, so the gate is the gateway's own configuration.

| Stage | Result |
| --- | --- |
| Declare and deploy 4 classes, configure | done, 158.6 test STRK (declarations 158.3) |
| 4 deposits, commitments equal the wallet's | done, 3.96 / 3.40 / 3.40 / 3.41 STRK |
| Wallet proof from on-chain events, 4 threads, bounded | log18, 4.7 s, 0.30 GiB peak RSS |
| Virtual OS on live Sepolia state (base block 15,514,024) | 11.8 s, exact message |
| PROOF2 | 118.8 s, 52.5 GiB peak RSS, 250,814 bytes, verified; 9 facts checked |
| Signed transfer (relayer `apply_spend`), simulated on the local node | **SUCCEEDED** with validation: 220.6M L2 gas, ~4.64 STRK |
| Gateway | **PROOF_VERSION_NOT_ALLOWED** |

In the simulation, the adapter checked the real facts (OS program, base-block age, message
hash) and the pool applied the spend against the live root. The proof itself is only verified
by the gateway and sequencer, so here it was checked locally (`prove_large`).

**Gas finding: our relayer account made Sepolia bill 2.7× the snforge figure.**
- `account-1` is a Sierra 1.4 class. Sierra-gas accounting needs Sierra 1.7 or later
  (`min_sierra_version_for_sierra_gas`). Once a call runs in Cairo-steps mode, every call beneath
  it does too (blockifier `contract_class.rs`: "Once we ran with CairoSteps, we will continue to
  run using it for all nested calls").
- So the pool, itself Sierra 1.8, was billed by Cairo steps: 155.5M per deposit, against 57.7M
  in snforge.
- snforge's `--tracked-resource cairo-steps` reproduces the on-chain numbers. Each test minus
  the base test: a deposit is 157.8M, a transfer's spend 141.9M.
- The same signed transfer, re-simulated with a Sierra 1.7 account as sender
  (`results/transfer-simulation-modern-accounts.json`): `apply_spend` is 52.2M, against 51.8M in
  snforge. The whole transaction is 134.5M, about 3.09 STRK, of which ~75M is `gas_per_proof`.
- **Consequence: fees depend on the caller's account class.** Users and relayers on accounts
  older than Sierra 1.7 pay about 2.7× for the pool's hashing.

Total spent: 176.0 test STRK. That includes one deposit reverted on a 150M gas bound (3.16
STRK). Evidence: `results/` (`outcome.json`, receipts, gateway response, facts, benchmarks).
The flow is checkpointed at the transfer: `flow.py` resumes if PROOF2 is enabled later, but
the proof's base block must then be within the adapter's 4,096-block window, or be re-proved.

Tooling for a live Sepolia lifecycle on the M31 pool (`bench/m31-pool`, frontier storage,
single-permutation nodes). Each spend is proved on the client (`client-port` `wallet` example,
R0 V2), then wrapped on the server. The server runs the statement account's `__execute__` in
the pinned virtual OS against real Sepolia state and proves the PIE through the PROOF2 large
path. The pool's relayer (`account-1`) submits `apply_spend` with the proof attached. The
`Proof2Adapter` then checks the facts and binds their single message to the spend.

| Step | Script | Network |
| --- | --- | --- |
| Local rehearsal: wallet proof, circuit-hash pin, bridge acceptance | `rehearse.py BRIDGE_BUILD` | none |
| Private runtime, wallet secrets | `init.py` | none |
| Class hashes and declaration fee estimates | `deploy.py --check` | reads only |
| Declare and deploy token, pool, adapter, statement account; attach adapter; approve | `deploy.py` | **transactions** |
| Deposits, transfer, partial and full withdrawal, two negatives | `flow.py` | **transactions** |
| Public evidence into `results/` | `report.py` | none |

Lifecycle (`flow.py`): deposits alice 600, 400, 100 and bob 200. Then:
- **transfer:** alice (600 + 400) → bob 700, alice 300;
- **partial withdrawal:** bob (700 + 200) → bob 500, plus 400 to `0xb0b`;
- **full withdrawal:** alice (300 + 100) → 400 to `0xa11ce`.

Negatives reuse a valid proof: the transfer replayed (`NULLIFIER_USED`) and the partial
withdrawal redirected in calldata (`BAD_BINDING`). Wallets rebuild the tree from the pool's
`NotePublished` events.

## Transport notes

- **RPC v0.10 throughout.** sncast needs it for proof fields, and the pinned runner needs its
  block headers (`state_diff_commitment`).
- **Proof transactions** are signed by sncast against a local capture server, checked, then
  posted to the gateway. They are never re-signed automatically.
- **Declarations go through the public endpoint.** The local node fails to simulate them, with
  an internal error on Sierra 1.8 classes. The gateway allows up to Sierra 1.9.0 and exempts
  declarations from its 1.21B L2 gas cap.
- **Declaration cost** is 40,960 L2 gas per class felt (Sierra + CASM):

  | Class | L2 gas | Test STRK at 20.7 gwei-fri |
  | --- | ---: | ---: |
  | Pool | 3.47B | ~72 |
  | Statement account | 3.69B | ~76 |
  | Token | 0.23B | ~4.7 |
  | Adapter | 0.15B | ~3.0 |

- **Statement account build.** It is declared from a copy of the `target/bridge-r0w` workspace
  with gas enabled at the root, because sncast builds with the release profile. Its CASM must
  equal the audited `contract`-profile build; `deploy.py` asserts this.
