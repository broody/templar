# Sepolia run: option-A pool with R0 client proofs wrapped in PROOF2

## Hidden assets and NFTs on Sepolia (2026-09-24, R0 V4, M31 pool V2)

**All four proof-carrying spends succeed in simulation against live state; the deposits,
including ERC721 and ERC1155 push deposits through the pool's receiver hooks, are on chain.**
The gateway still rejects large proofs (`PROOF_VERSION_NOT_ALLOWED`), so nothing proof-carrying
was included. Flow: [`hidden_asset_flow.py`](hidden_asset_flow.py) (`docs/hidden-asset-spec.md`).

Deployment (declarations 312.8 test STRK: pool V2 105.9, R4 account 83.9, P1 account 85.8,
test ERC721 15.5, test ERC1155 13.9, escrow 3.9, adapter 3.4, recipient 0.6): pool V2
`0x02da001…37b9`, R4 statement account `0x0349eba…9ee4` and adapter `0x031ca0a…85fd`, P1 statement
account `0x052828e…d70a` and adapter `0x021c760…4409`, escrow `0x05a2cdb…6c5a`, test ERC721
`0x0535ca4…de0f`, test ERC1155 `0x0445558…b32a`, account-like recipient `0x02ec1c3…1a25`; token A
reused.

| On chain | Result |
| --- | --- |
| ERC20 deposit, 1000 A (pull, exact balance delta) | 2.07 STRK; commitment equals the wallet's |
| ERC721 deposit, NFT #2 (safe transfer, `on_erc721_received`) | 1.52 STRK; asset registered, the undeployed-identifier check passes on Sepolia |
| ERC1155 deposit, 300 of id 7 as an escrow policy note (`on_erc1155_received`) | 1.52 STRK; asset registered, `held` = 300 |
| Arbiter (the relayer) approves the release | 0.04 STRK |

| Spend (proved from the pool's events; OS on live state) | Client proof | OS capture | Large proof | Simulation (with validation) |
| --- | ---: | ---: | ---: | --- |
| S1 ERC20 payment, asset hidden (one input + dummy) | 0.80 s | 11.1 s | 126 s, 28.6 GiB | succeeds: 138.3M L2 gas, pool 55.4M, 3.41 STRK |
| S2 NFT transfer, asset hidden (one input + dummy, dummy output) | 0.55 s | 11.4 s | 138 s, 28.7 GiB | succeeds: 138.3M L2 gas, pool 55.4M, 3.41 STRK |
| S3 ERC1155 escrow release (P1), paid by safe transfer | 0.97 s | 12.0 s | 133 s, 28.3 GiB | succeeds: 81.6M L2 gas, pool 3.6M, 2.01 STRK |
| S4 NFT withdrawal, asset published (two dummy outputs) | 0.75 s | 12.4 s | 148 s, 28.6 GiB | succeeds: 140.2M L2 gas, pool 56.6M, 3.46 STRK |

S1 and S2, an ERC20 payment and an NFT transfer from the same tree state, cost exactly the same
gas: the asset changes nothing an observer can measure. S2 and S4 each spend NFT #2 and were
simulated independently. Evidence: [`results/v4-hidden-asset/`](results/v4-hidden-asset/)
(deployment, classes, every receipt and gateway response, each case's public statement, client
report, server benchmark and proof facts, and the simulations).

## Open notes on Sepolia (2026-09-24, R0 V3)

**The V3 relayer transaction swaps through live Ekubo into an open note; it succeeds in
simulation.** The gateway still rejects PROOF2, so nothing proof-carrying was included.

Deployment ([`open_note_flow.py`](open_note_flow.py), [`deploy.py`](deploy.py)):
- the V3 pool (`0x0063357…d786`), V3 statement account (`0x0355de6…a22e`) and V3 Proof2Adapter
  (`0x0176012…4d07`); declarations cost 177.2 test STRK (pool 88.2, statement 85.6, adapter 3.3);
- reused from the return-note run: synthetic token A (the pool token) and token B, upstream's
  unchanged `EkuboSwapAnonymizer`, and the Ekubo pair.

| Stage | Result |
| --- | --- |
| 2 deposits of A (on chain, relayer Argent 0.5.0) | 2.08 and 1.47 STRK; commitments equal the wallet's |
| Wallet proof from the pool's events: 700 A change, plus 300 A budget and an Ekubo intent into an open note of B (minimum 280) | R0 V3, bounded |
| Virtual OS on live state, base block 15,538,430 | 11.8 s, exact message |
| PROOF2 | 116.1 s, 253,592 bytes, verified |
| Gateway | `PROOF_VERSION_NOT_ALLOWED` |
| Exact signed relayer transaction, simulated with validation at the latest block | **succeeds**: 300 A through the live Ekubo router gives **299 B**, funding the open note at index 3 (`OpenNoteFunded`); the change is published |
| Cost (simulated) | 150.3M L2 gas in total, of which `apply_spend_with_invoke` is 68.6M including the swap; 3.80 STRK |

Evidence is under [`results/v3-open-note/`](results/v3-open-note/): `swap-outcome.json`,
`swap-simulation.json`, `cases/swap/` (client report, server benchmark, PROOF2 log and facts), the
deployment, and every receipt and gateway response. `results/` top level is the 2026-09-23 V2 run. Recovery and spending of
the funded note need inclusion. The math review and adversarial tests are pending
([ADR-0023 amendment](../../docs/adr/0023-return-notes-and-adapter-compatibility.md)).

## Earlier run (2026-09-23, R0 V2 transfer)

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
- **Relayer upgraded (2026-09-23).** `account-1` went from Argent 0.3.1 to Argent 0.5.0
  (Sierra 1.7, class `0x0734…b2c2`) with `upgrade.py`, for 0.079 STRK, tx `0x1b00…c5fe`. The
  script first simulated the upgrade together with a normally signed follow-up transaction; the
  owner key is unchanged. From the upgraded relayer:

  | Transaction | Before (Argent 0.3.1) | After (Argent 0.5.0) |
  | --- | ---: | ---: |
  | Deposit (dry run) | 188.1M L2 gas, 3.96 STRK | 70.4M L2 gas, **1.48 STRK** |
  | PROOF2 transfer (`simulate_spend.py`) | 220.6M, 4.64 STRK | 134.9M, **3.12 STRK** |

  The transfer is `apply_spend` 52.2M, validation 0.3M, and the rest transaction-level,
  including ~75M `gas_per_proof`.
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
