# Return notes and unchanged upstream adapters

An isolated `TEMPLAR_RETURN_POC1` reference for
[ADR-0023](../../docs/adr/0023-return-notes-and-adapter-compatibility.md).
`ReturnNote` is the internal transaction-local destination; `OpenNoteDeposit`
is the upstream adapter response. Verified funding creates an ordinary `Note`.
Primary packages and earlier experiments retain their original semantics.

## Result

**PASS on Sepolia, 2026-09-21.** The unchanged upstream Ekubo adapter converted
1,000 synthetic token-A units into **999 token-B units**. A fresh seed restore
and full viewer recovered the return. The restored wallet paid Bob 900 privately,
and Bob's fresh wallet recovered that payment. Both native proofs verified
locally and were accepted onchain: [swap](https://sepolia.voyager.online/tx/0x40506b834bcfaad59274f242d26d9717597358ba8fa76244978a0d01973172) and [recovered-note payment](https://sepolia.voyager.online/tx/0x58bb385bd744e6ac1960f6f43a40b6ce08208545954c1d80bbec8402efcbbda).

Six on-chain rejection checks passed with unchanged pool/token state: standalone
withdrawal, stripped intent with reused proof, redirected return, changed external
call, changed return identifier, and replay. Native execution also rejected a
tampered intent. Final pool holdings are **4,000 A and 999 B**: Alice owns 4,000 A
and 99 B, and Bob owns 900 B. The adapter retains neither token.

Proof requests took **19.11 and 19.69 seconds**, with **13.81 and 13.88 GiB** peak
RSS under four cores and a 16 GiB process cap on the larger host. No swap was used.
These single runs do not qualify a physical 16 GiB desktop. The swap used
**103,155,120 L2 gas** and cost **1.813773 test STRK** at this run's prices.
See [measurements](results/measurements.md) and [public evidence](results/evidence.json).

## Implementation

`execute_returns` verifies an owner-authorized execution intent, funds the adapter,
calls `privacy_invoke`, validates the response and pulls the actual proceeds.
Missing, extra, duplicate, malformed, wrong-token or insufficient returns revert
the entire transaction. Only final funded commitments enter the tree. The exact
adapter, complete calldata, expiry, input budget and ordered return destinations,
including ciphertext, enter the proof binding.

The input spend covers one token and one adapter funding withdrawal. Return assets
can differ. One to four returns and private change share a four-output cap.
The pool grants no external allowances. Per-pull balance checks support repeated
output tokens and same-token refunds mechanically; qualified routes are narrower.

The Scarb manifest imports Ekubo and Vesu adapters directly from upstream commit
`b40bf109c8e5b97d9d6e8ec6db48b16b9d10a106`. No adapter source is forked or edited.
The ABI-compatible `OpenNoteDeposit` decoding type lives at the pool boundary.
The upstream adapter does not pin its caller or Ekubo router: the owner must bind
the intended call, and funding/invocation/collection must remain atomic.

## Validation

Local validation passes **11 Python tests and 24 Cairo tests**. Python covers
return receipt authentication, receiving authority, seed/view recovery, ordinary
receipt regression and full intent binding. Cairo includes real ownership
statement vectors, mock-verifier settlement/rollback tests, repeated output-token
funding, a same-token refund, and the unchanged Vesu adapter supplying and redeeming
against upstream's mock vault. Vesu is not qualified against a live deployment.

The live harness deploys a fresh pool and the unchanged upstream Ekubo adapter.
It reuses the synthetic pair seeded by `../defi-return-e2e/` in Ekubo's deployed
Sepolia Core/Router. It exercises native authorization, actual return funding,
fresh seed and full-view recovery, a private payment from the recovered note,
and proof/intent/replay rejection. The completed results are recorded in
`results/evidence.json` and `results/measurements.md`.

## Reproduce

Use Scarb 2.18.0, **snforge/sncast 0.63.0**, Python with PyNaCl and the pinned
native prover/verifier inherited by `init.py`. Ensure these versions precede
older executables in PATH; `/usr/bin` must precede any compiler shim.

```sh
python3 -m unittest -v test_returns
python3 generate_vectors.py
(cd cairo && snforge test)
python3 init.py
python3 inspect_ekubo.py
python3 deploy.py
python3 flow.py
python3 finalize.py
python3 report.py
```

`init.py` refuses to replace an existing run pointer. Secrets and signed requests
stay in a mode-0700 private runtime. Live transactions use the explicit Sepolia
sncast account and fee bounds in `common.py`; proof-bearing submissions retain
the existing sncast-signing/official-gateway transport. Ambiguous submissions
must be reconciled before retrying. Only explicitly allowlisted public evidence
is exported, after scanning for fixture secrets.

The reproduction currently depends on the preceding synthetic pair deployment
and native prover setup. It is an integration harness, not a standalone SDK.

## Scope and trust

The imported Ekubo adapter handles an exact-input single hop. This run uses a
route without extensions, synthetic ERC20s and existing deployed Ekubo contracts.
It does not qualify production tokens, arbitrary routes, partial fills, borrowing,
asynchronous positions or controlled-note execution.

Receipt construction is local; the proof does not prove decryptability. Recovery
still uses two trusted RPCs and candidate-nullifier queries. The transaction
sender pays gas publicly. The external call, amounts and return-deposit linkage
are public. Return notes do not establish stronger anonymity, private AMM trades,
or improved prover memory.

The owner can change the experimental pool's verifier and fee settings. Token
behavior, supported routes, private submission, bulk history, independent review,
production package integration and physical-desktop qualification remain open.
The [specification](../../docs/return-note-spec.md) defines the accepted boundaries.
