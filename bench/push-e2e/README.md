# Push payments, full viewing and cold recovery on Sepolia

**PASS — September 20, 2026, Starknet Sepolia 0.14.4.** Four native PROOF1 spends,
two funded deposits, full viewing and fresh-process seed recovery succeeded.
Three adversarial proof-bearing transactions reverted with the expected errors.

An isolated integration of the [POC2 key/recovery design](../view-recovery/README.md)
with the existing pinned V1 Stwo privacy service and native PROOF1 transport.
This is an ordinary-note test pool with a synthetic faucet token. Production
packages and the earlier Sepolia deployment are unchanged. The implementation
[self-review](REVIEW.md) records its assumptions and remaining security work.

## Completed lifecycle

1. Fund Alice with a 1,000-unit private note and Carol with a 500-unit note.
2. Alice sends 600 to Bob and keeps 400 change. Carol independently sends Bob
   250 and keeps 250. Both pay using Bob's published receiving address while
   his wallet is offline; neither sender receives Bob's spending/viewing keys.
3. A fresh process holding only Bob's full viewing export and public deployment
   metadata downloads history and reports 850. A separate fresh process restores
   from his seed and obtains the same spendable notes and tree.
4. Bob spends those recovered notes: 500 to Dave, 310 change and 40 withdrawal.
   The full viewer sees receipt totals of 1,160 but an unspent balance of 310.
5. Delete Bob's restored local wallet cache. Restore again in a fresh process
   from seed and chain history, then prove and submit a withdrawal of the 310.
   The full viewer subsequently reports a complete zero balance.

Verified final synthetic-token balances: relayer 8,480; pool 1,150; Bob's public
withdrawal address 350; fee collector 20. The pool holds Alice 400, Carol 250
and Dave 500. Four five-unit pool fees are paid by the relayer outside the private
accounting. Network test-STRK fees are separate.

All four remaining private balances were independently reconciled from the
downloaded ciphertexts and pinned spent flags, totaling the pool's 1,150 units.
See [summary.json](results/summary.json), [measurements](results/measurements.md)
and [evidence.json](results/evidence.json). Transaction receipts, proofs, local
verifier results and wallet checkpoint summaries are archived alongside them.

- [Alice's offline push payment](https://sepolia.voyager.online/tx/0x79fe01826e7e90c4fd39dffeb9a1e5410d1408f3fae618c01383556e19064a3)
- [Carol's independent push payment](https://sepolia.voyager.online/tx/0x6e53c7ac62a6ec0eff8c7a40b545792a44e2e931c79c38aab2c1f5f508dec79)
- [Bob spends recovered receipts](https://sepolia.voyager.online/tx/0x73f3a1846e8651680bcbda39a333754b7d0766fdf52fed4113517a5bde6c0d5)
- [Withdrawal after deleting and restoring the wallet cache](https://sepolia.voyager.online/tx/0x3434957edfad12d00dd7216da4cb2298449a6fc705540ac9162f51d94679a28)

All payment roles use distinct note keys; the existing account relays every
public transaction. This is not a multi-device wallet UX demonstration.

## Measurements

| Native V1 workload | Prover request | Peak prover RSS | Proof bytes | Full-spend test-STRK fee |
|---|---:|---:|---:|---:|
| Alice, 1 input / 2 outputs | 19.189 s | 13.88 GiB | 230,242 | 1.794466 |
| Carol, 1 input / 2 outputs | 18.900 s | 13.91 GiB | 237,556 | 1.794468 |
| Bob, 2 inputs / 2 outputs / 1 withdrawal | 19.225 s | 13.91 GiB | 236,197 | 1.789871 |
| Restored owner, 1 input / 1 withdrawal | 19.855 s | 14.01 GiB | 236,471 | 1.487785 |

There was no swap. Service startup added roughly two seconds per process.
The one-input/two-output payment used 93,607,920 L2 gas and 3,616 L1 data gas.
The earlier invoice payment used 92,130,320 L2 gas: a **1.6% net increase** for
the full transaction in this experiment. This is not a controlled estimate of
ciphertext-only overhead: pool ABI, ordinary-only control flow, binding and the
key construction also differ. Network fee prices vary, so compare gas separately
from the test-STRK totals. Deployment/declaration and reverted-transaction fees
are excluded from the table and preserved in their own receipts.

Five fresh-process watch/restore runs took **16.46, 31.54, 17.62, 18.28 and
18.60 seconds** with only six to eight outputs (1,824–2,432 ciphertext bytes).
These include RPC reads, tree rebuild, integrity checks, decryption and spent
checks, not proving. The current per-position RPC design is too slow to extrapolate
to a large pool; these results motivate authenticated bulk history and private
spent-state synchronization. The feature did not solve the approximately 14 GiB
prover footprint. Actual 16 GiB desktop qualification remains necessary.

## Delivery and recovery guarantees

The public spend binding includes token, nullifiers, ordered output commitments
and ciphertext digests, and withdrawal recipients/amounts. The pool recomputes
each digest from the actual ciphertext. It publishes all ciphertexts atomically
with insertion and writes an immutable delivery digest under the leaf index.
The note tree alone cannot authenticate ciphertext; this additional map makes
payload integrity directly checkable against contract state. Its storage cost
is a measured implementation choice, not a finalized format recommendation.

Each output has 304 ciphertext bytes, encoded as nine 31-byte felts and one
25-byte felt. Canonical word bounds and exact length are checked. A publication
event contains index, commitment, digest, the span length and ten words. There
is no public stable recipient identifier. Token identity is public in this
single-token spend ABI. Correct encryption is not proved: recipients only credit
notes after successful decryption and commitment matching.

Cold recovery pins one accepted block hash, verifies the configured pool class,
and requires agreement between Zan and Cartridge RPC reads for root, leaf count,
all indexed commitments/delivery digests and candidate spent-nullifier flags.
Events are fetched with continuation-token pagination from the deployment block.
The wallet rebuilds the tree and verifies all supplied payloads against state.
Missing data makes the result incomplete, including when known unspent value is
zero. The canonical block identity is rechecked after the scan.

**Both RPC providers are trusted.** This is not a consensus light client or
cryptographic state-proof verifier. Provider agreement and state checks prevent
an independent archive from silently substituting data under that trust model;
colluding providers could still lie. L2 acceptance is not irreversible L1
finality. The wallet's balance is explicitly as of its checkpoint. Reorg rebuilds
and mid-scan reorg rejection are tested with fixtures, not by forcing Sepolia
to reorganize.

Candidate-nullifier reads disclose access patterns to RPC operators. A complete
public-nullifier sync or another private-query design remains necessary before
making stronger network-privacy claims. This scanner fetches per-position state
and is for a small isolated pool; its measured cold-sync time does not establish
large-history scalability or historical availability guarantees.

## Validation and proof scope

**59 Python tests and 59 Cairo tests passed.** The Python suite covers key/address consistency, incoming/full viewing separation,
canonical payload encoding, omission/tampering, cross-provider disagreement,
unexpected contract class, stale checkpoints and reorg handling. The Cairo suite
includes the preserved POC2 valid/invalid witness vectors, tree tests, adapter
guards and pool delivery/context/replay checks. Local pool guard tests use mock
proof verdicts; the separate Sepolia flow uses real native proofs.

The live adversarial cases submit altered ciphertext, a rebound altered payload
with the original proof, and a replay. Each must revert at the intended guard,
with pool state, nullifier flags and synthetic-token balances unchanged. Network
gas remains payable for reverted transactions. The local V1 prover must also
reject substituting the full viewing nullifier key for Bob's spending secret.
Read-only failure drills mutate actual downloaded chain history to check missing
payload handling, tampering rejection and successful retry.
They passed, including distinguishing incoming receipts totaling 1,160 from Bob's
final zero balance. [recovery-drills.json](results/recovery-drills.json) records
the pinned block, missing-data result, rejection reasons and all private balances.

The exact V1 virtual OS, prover, verifier and message layout from the earlier
[pool lifecycle](../stwo-e2e/README.md) are retained. The new statement class and
POC2 version are pinned by the adapter. These are genuine native PROOF1 proofs,
not the earlier standalone staged-allocation experiment. Four physical host
cores, a 16 GiB cgroup cap and zero swap constrain each fresh prover process.
Prover request time includes virtual execution and RPC state reads; startup,
wallet synchronization, signing and receipt latency are separate. A single run
per workload is not a latency distribution or a physical desktop qualification.

No old leaves are reinterpreted with new nullifiers. Controlled notes, legacy
migration, production token behavior, governance, address/backup standards,
secure key-export UX, independent cryptographic review and desktop RAM
qualification remain outside this experiment.

## Reproduce or resume

The existing run pointer is [run-location.json](run-location.json); its temporary
runtime is mode 0700. Keys, plaintext notes, private witnesses, recovered wallet
caches and signed transactions stay there. `report.py` copies an explicit public
allowlist. Do not archive the runtime wholesale.

```bash
# In bench/push-e2e, with Scarb 2.18.0 and Foundry 0.63.0 selected:
python3 -m unittest -v test_protocol test_recovery test_sync > results/python-tests.log 2>&1
cd cairo
snforge test > ../results/cairo-tests.log 2>&1
cd ..
# init.py is for a NEW experiment only; it refuses to replace an existing pointer.
# It locates and checks the pinned prover/verifier through the earlier run manifest.
python3 deploy.py
python3 flow.py
python3 recovery_drills.py
python3 report.py
```

Deployment and flow use the configured `account-1` **sncast** account and spend
test-STRK. Account keys remain in the existing sncast account file. Ordinary
transactions use the RPC; native proof transactions are signed with sncast and
submitted to the official Sepolia gateway, preserving attached proof/facts.
Each proof-bearing transaction has resource bounds below four test-STRK.
Declaration/deployment fees are recorded separately from payment costs.

Completed transactions are resumed from saved responses/receipts. Ambiguous
submission failures stop rather than automatically resubmitting. A preserved
deployment failure occurred on sncast's initial `spec_version` RPC read, before
transaction construction; it was inspected before retrying. The known RPC fee
estimator limitation for PROOF1 remains; bounded direct submission is still used.
Controller CLI is not used.

The [resume check](results/resume-check.json) reruns deployment and the completed
flow with signing/submission disabled and verifies that the account nonce is
unchanged. [SHA256SUMS](results/SHA256SUMS) identifies archived evidence;
[evidence.json](results/evidence.json) identifies the final source files.
