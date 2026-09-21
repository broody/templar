# Ordinary-note DeFi return pathfinding

An isolated `TEMPLAR_DEFI_POC1` experiment: owner proof → atomic adapter swap →
funded return note → fresh seed recovery → spend. No controller is deployed or
required. The pool and private statement reject controlled inputs. Existing
experiments and production packages retain their original behavior.

## Result

**PASS on Sepolia, 2026-09-21.** Four native PROOF1 spends succeeded, ten
adversarial transactions reverted without changing pool/token state, and the
native statement rejected a tampered intent. All four proofs were also verified
locally. Local checks passed 10 Python and 16 Cairo tests.

The mock fill changed from 950 to 977 after proving; the original proof settled
the actual 977-unit return. A fresh wallet recovered it, and spent it in a private
payment to Bob. The real Ekubo swap then converted 1,000 synthetic token-A units
into 999 token-B units. Fresh seed recovery found that note, and a subsequent
native withdrawal spent it successfully. Final private balances reconcile to
3,000 A plus 77 B for Alice and 900 B for Bob.

[Real Ekubo swap](https://sepolia.voyager.online/tx/0x71829fd5ff736a1dce94e695df408d242108ec1af22ade7a860dcd0fea4c7be)
and [recovered-proceeds withdrawal](https://sepolia.voyager.online/tx/0x423d877971b55ee64f4ab2c78816bc905b20980985a71c8841a149f865a4749).

Prover requests took 20.0–21.7 seconds and 13.79–13.99 GiB peak RSS. The real
Ekubo transaction used 102,381,920 L2 gas and cost 1.835414 test STRK in this run.
These are single measurements, not latency distributions or mainnet estimates.
See [measurements](results/measurements.md), [public evidence](results/evidence.json),
[receipts and outcomes](results/public/results/summary.json), and
[review boundaries](REVIEW.md). The evidence export passed a fixture-secret scan
and has SHA-256 checksums. A completed-run resume performed no external work.

## Design under test

The proof binds a swap-intent hash in addition to the spend. The pool recomputes
that hash from the actual adapter, token pair, input budget, minimum output,
expiry, opaque return ownership commitment, recovery payload, and route. A spend
with an intent must use `execute_swap`; `apply_spend` rejects it. The swap and
return transfer happen under one pool reentrancy lock and revert together.

The adapter has an immutable pool caller and, for Ekubo, an immutable router.
Only the authorized input amount is transferred out; the pool grants no external
token allowance. It pulls the measured output and checks the increase in its own
balance before publishing a return leaf. The initial Ekubo adapter supports a
single exact-input hop, requires a full fill, and permits no extensions.

The return receipt seals ownership and randomness before the amount is known.
Its version-3 plaintext uses a zero amount placeholder; settlement publishes the
actual public amount and binds it with the ciphertext digest. The wallet combines
the two, verifies the final funded commitment, and recovers a normal spendable
note. No unfunded leaf enters the tree. Ordinary version-2 receipts remain valid
within this experiment's separate key/domain context.

Controller-related fields inherited from the baseline are reserved zero here.
Their presence in the experimental encoding is not controller support. The
return amount and swap activity are public; owner identity and earlier note
membership are private within the existing trust model. Public relayer/gas
identity and amount/timing correlation remain visible.

## Reproduce

Use Scarb 2.18.0, snforge/sncast 0.63.0, Python with PyNaCl, and the pinned native
PROOF1 prover/verifier recorded by `init.py`. From this directory:

```sh
python3 -m unittest -v test_returns
python3 generate_vectors.py
(cd cairo && snforge test)
python3 init.py
python3 inspect_ekubo.py
python3 deploy.py
python3 flow.py
python3 report.py
```

`init.py` creates a mode-0700 private runtime and refuses to replace an existing
run pointer. Secrets and signed requests stay there. Live transactions use the
explicit Sepolia sncast account configured in `common.py`, bounded fees, and
synthetic tokens. Declaration fees are separate from spend fees. Ambiguous
captures/submissions require receipt/nonce reconciliation before retrying.

The real integration creates a dedicated synthetic pair with liquidity in
Ekubo's existing Sepolia Core/Positions contracts and uses its published router.
This tests deployed protocol interoperability, not production-token behavior or
an existing liquid market. Deployment addresses and class hashes are recorded.

## Qualification boundary

Wallet/reference tests and Cairo settlement tests are separate from live native
proof acceptance. Cairo settlement tests use an explicit mock verifier and assert
specific rejection reasons plus unchanged state. Cross-language vectors exercise
the real private statement. Live receipts and prover measurements belong in
`results/` only after the explicit public-evidence export.

The prover uses four cores, a 16 GiB process cap, and no swap on the larger host.
This is not qualification of a physical desktop with 16 GiB total RAM. Recovery
uses two trusted RPC providers, not a consensus light client, and the current
small-pool scanner exposes candidate-nullifier queries. The fixture token has an
unrestricted test faucet. Native proof transport follows the existing sncast
signing and gateway route. Production wallet integration, independent review,
token compatibility, general routing, refunds/partial fills, and mainnet remain
outside this experiment.
