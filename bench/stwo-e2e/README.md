# S-two PROOF1: actual pool lifecycle on Sepolia

**PASS — September 20, 2026, Starknet Sepolia 0.14.4.** This harness exercised a
funded deposit, payment, recipient respend and withdrawal through an isolated
deployment of the existing Templar pool with a real native PROOF1 adapter.

The copied `pool.cairo`, `spend.cairo`, `tree.cairo` and `hashes.cairo` are
byte-identical to `packages/pool`; [source-snapshot.json](source-snapshot.json)
records their hashes. The pool's existing `IVerifier` interface worked without
changing `apply_spend`. The adapter and virtual statement account live here;
the primary `packages/pool` package has not been migrated or edited.

## What ran

| Step | Result |
|---|---|
| Funded deposit | Alice deposits 1,000 test-token units; on-chain commitment and depth-32 root match the reference |
| Payment, 1 input / 2 outputs | Alice creates Bob's 600-unit note and her 400-unit change note; Alice's input nullifier becomes spent |
| Recipient respend, 1 / 1 / 1 | Bob proves ownership of the received note, withdraws 100 and creates a fresh 500-unit note |
| Final withdrawal, 1 / 0 / 1 | Bob spends the fresh note and withdraws its remaining 500 units |

Each successful spend pays a five-unit pool fee from the transaction sender,
outside the private balance. Final test-token balances are: sender **8,985**,
pool **400**, Bob **600**, fee collector **15**, totaling the initial **10,000**.
Alice's change note remains unspent. Every root, leaf count, nullifier flag,
commitment event and withdrawal event was checked. Membership paths were read
from the deployed pool and compared with an independent reference tree.

The paying witness receives recipient invoices (`inner`, amount, commitment
and discovery ID), not recipient spend keys. The harness holds both roles'
synthetic keys separately so Bob can later spend his note. A single existing
Sepolia account relays all public transactions; this is not a wallet UI,
encrypted-invoice delivery or note-discovery test.

- [Payment transaction](https://sepolia.voyager.online/tx/0x76cab9a760fb1b53f334596673bb309e30a0d0b8f368d254710da55d6456c8c)
- [Recipient respend](https://sepolia.voyager.online/tx/0x4f53a550701b01eeff2bee369aa3db68f1a96d4844cc3d9ba4b3365d7f83a88)
- [Final withdrawal](https://sepolia.voyager.online/tx/0x4b79421c71c30c3969ca9156cd1dd1dabaea1e43e2a0d308aa8c7118469237d)

All three have finalized L2 receipts with `SUCCEEDED`.
[Deployment addresses and class hashes](results/deployment.json),
[complete summary](results/summary.json), and
[final state](results/state-withdrawal.json) are archived.

## Resource measurements

Four physical i9-10980XE cores, 16 GiB prover cgroup cap, no swap, unchanged
upstream proving allocations. Fresh prover process for each case.

| Step | Prover request | Peak RSS | Proof bytes | L2 gas | Actual test-STRK fee |
|---|---:|---:|---:|---:|---:|
| Payment | 19.217 s | 13.92 GiB | 230,822 | 92,130,320 | 1.779501 |
| Recipient respend | 18.939 s | 13.96 GiB | 236,389 | 86,422,800 | 1.669240 |
| Withdrawal | 20.535 s | 14.02 GiB | 237,098 | 79,203,600 | 1.528831 |

These are complete pool-spend transaction fees, including native verification,
pool work, account execution and data gas. The five-unit pool fee above is in
the synthetic test token and is separate from network STRK fees. The funded
deposit cost about 0.437663 test-STRK. Declaration/deployment costs are recorded
separately and excluded from these per-spend figures.

Prover request timing includes virtual OS execution and its RPC reads, but
excludes service startup, off-chain witness/path preparation, signing, submission
and receipt latency. Startup was about 1.9–2.4 s; recursive proving took
12.1–12.7 s inside the successful requests. RSS excludes the Python harness and
separate verifier process. These remain single runs on a larger host, not a
physical 16 GiB desktop qualification or a latency distribution. No optimization
was applied. [Machine-readable measurements](results/measurements.md).

## Rejection and rollback checks

Four proof-bearing transactions reached the actual contracts and reverted:

| Case | Expected error | Checked afterward |
|---|---|---|
| Change server actions without changing the proven statement | `BAD_BINDING` | Pool state and test-token balances unchanged |
| Recompute the public binding for changed actions, reuse the original proof | `PROOF_BINDING` | Same; the real adapter rejected the mismatched proven message |
| Replay the successful payment | `NULLIFIER_USED` | Same, including rollback of pool fee collection |
| Prove a withdrawal to address zero | `ZERO_RECIPIENT` | Nullifier and pool-fee writes roll back; the note remains spendable |

The successful final withdrawal spends the very note used by the rejected
zero-recipient attempt. These rollback checks exclude the normal network gas
charged for reverted transactions.

The local prover separately rejected an incorrect owner (`BAD_MEMBERSHIP`) and
an amount-conservation violation (`NOT_CONSERVED`). Every valid generated proof
passed the pinned native cryptographic verifier, which also rejected modified
message digests, program hashes and corrupted proof bytes.

The [local suite](results/pool-and-adapter-tests.log) passed **68 tests**: the
existing 57 pool/hash/tree tests plus 11 adapter guards. Existing pool tests
still use their original mock verifier/signature fixtures. Adapter unit tests
inject proof facts to exercise guard logic; the Sepolia transactions above
provide the real cryptographic integration checks.

## Configuration and transport findings

- **Default fee-token address:** the pool's built-in address
  `0x04718f5a0fc34cc1af16a70cde8ff893b576ca30423eca852ce4ab014b6b52ac`
  returned `Contract not found` on Sepolia. The STRK contract at
  `0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d`
  exists and reports symbol `STRK`, decimals 18. This test explicitly called
  `set_fee` with the deployed test token. Correct the default or explicitly
  configure the intended token for deployment; this harness did not modify the
  original constant. [Recorded check](results/fee-token-address-check.json).
- **Build alignment:** copied pool sources passed with Cairo/Scarb 2.18.0 and
  Foundry 0.63.0. The original package's dependency strings still say 2.17.0.
- **Submission:** local signing captures the full proof-bearing transaction,
  then submits directly to the official Sepolia gateway. The earlier V1
  estimator incompatibility is not solved by this harness. Network fee bounds
  are explicit; each proof transaction is capped below four test-STRK.
- **RPC reliability:** one state read timed out before signing, and another
  failed during virtual execution. No transaction was published for either
  failed attempt. Read-only transport retries were added; the virtual execution
  was rerun locally against a fresh block and reached the expected statement
  rejection. [Recovered prover failure](results/transient-state-read-failure.json).
- **CPU portability:** this reuses the pinned host-native source build. The
  earlier prebuilt-image CPU failure and portable build qualification remain.

## Architecture and scope

`StatementAccount` privately executes the Cairo statement in the approved
virtual OS. Its public message contains its class hash and the eight statement
scalars. `NativeProofVerifier` implements the pool's existing verifier interface,
requires the proof itself to be attached to the transaction, checks the native
facts and binds the message to the configured statement and pool. Starknet
performs cryptographic proof verification before contract execution.

The adapter pins PROOF1, the V1 virtual OS hash, statement address/class, pool,
chain and message layout. The experimental proof-age limit is 4,096 blocks;
it remains a parameter to qualify, not a production policy. The existing pool
retains its independent root-history, nullifier, action-binding, token and fee
checks. No verifier or controller-signature mock authorizes the live ordinary
spends. The signature-verifier address is zero because ordinary spends do not
use it; controlled spends have not been integrated here.

Still required for wider readiness: real controller signatures and destination
binding, controlled maximum 4/4/2 coverage, repeated/worst-case resource tests,
proof-aware estimation and intended wallet transport, encrypted-note/discovery
integration, governance/security review, actual desktop and mainnet qualification.
The test token is a minimal faucet ERC20 fixture with no real value; production
token behavior and adversarial token callbacks require separate coverage.

## Reproduction

`source-snapshot.json` pins the pool core and native prover binary. Prover source
is sequencer `e6b6fd2e9932909107833579e5b6efd6c75fa0af`
(`PRIVACY-0.14.3-RC.2`), proving-utils
`3035dd00421daa541894297bd754db6e2787807b`. Reuse or build the matching prover and
native verifier; this repository does not vendor that toolchain.

The harness uses the already configured `account-1` sncast account and local
tool paths in `common.py`. Account keys stay in the existing account file; they
are not copied into this directory. `deploy.py` and `flow.py` submit testnet
transactions and spend test STRK. Review those settings before running elsewhere.

```bash
# From bench/stwo-e2e, using the pinned existing artifacts:
python3 init.py \
  --prover /tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/rust-target/release/starknet_transaction_prover \
  --verifier /tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/local-verifier \
  --upstream /tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/upstream/sequencer-e6b6fd2e9932909107833579e5b6efd6c75fa0af
python3 deploy.py
python3 flow.py
python3 report.py
```

`init.py` creates an isolated run with new deployment salts. Declarations are
reused when the exact class already exists. `flow.py` checkpoints completed
steps. Ambiguous signing/submission failures require inspecting saved receipts
before rerunning; the harness never blindly resubmits an uncertain transaction.
A [resume check](results/resume-check.json) disabled the signing/submission function and confirmed that existing declarations and deployment receipts were reused without changing the account nonce. All prover services stop after each case, including on errors. The current run
is `/tmp/templar-stwo-e2e-j3q1xnvq`; private synthetic note material and signed
requests remain there with directory permissions 0700.

The results archive deliberately includes only public records, proof binaries,
facts, receipts and measurement logs. It excludes private witnesses, note keys
and signed requests. [SHA256SUMS](results/SHA256SUMS) identifies every archived
record. Use [source-files-SHA256SUMS](source-files-SHA256SUMS) for the harness sources. The original
pool package and previous ADR evidence archives remain unchanged.
