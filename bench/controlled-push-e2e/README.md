# Controlled push payments on native Stwo

This isolated experiment integrates owner-controlled push payments with an
additional controller approval. A controlled note requires both its owner's
private proof and a valid controller signature. Receiving, viewing and seed
recovery use the same encrypted delivery mechanism as ordinary push payments.

The protocol is `TEMPLAR_CONTROL_POC1` in a fresh pool. It does not reinterpret
existing notes. See [REVIEW.md](REVIEW.md) for the encoding, disclosure, trust and
production boundaries. The primary packages are not migrated by this experiment.

## Reproduce

Use Scarb 2.18.0, snforge/sncast 0.63.0, universal-sierra-compiler 2.10.0,
Python 3 with PyNaCl and `starknet-py==0.28.1`, and the pinned native prover and
local verifier recorded by `init.py`. The prover runs under systemd with four
cores, a 16 GiB process limit, and no swap. Secrets belong only in the private
runtime created by `init.py`; never commit its contents.

```sh
python -m unittest discover -v
python generate_vectors.py
(cd cairo && snforge test)
```

For a new live run, run `init.py` to initialize a private runtime and controller key, configure the explicitly selected Sepolia sncast account, then
run `deploy.py`, `flow.py`, and `report.py` in order. Transactions have bounded
fees and use a synthetic token. A partially captured or submitted transaction
requires receipt/nonce reconciliation before retry. `flow.py` checkpoints the
lifecycle; it does not blindly retry ambiguous transactions.

## Live scenarios

1. Deposit Alice's 1,000 controlled units and Carol's 300 ordinary units.
2. Alice pays offline Bob 600 and retains 400, with a real controller signature.
3. A viewer discovers Bob's receipt; a fresh process restores his wallet from seed.
4. Bob pays Dave 500, retains 60, and withdraws 40 to the approved destination.
5. Delete Bob's recovered cache; restore again and withdraw the remaining 60.
6. Carol makes an ordinary payment of 100 to Dave without controller approval.

The run submits real native proofs for missing approval, wrong signer, expired
approval, replay, and a changed withdrawal destination. The last case creates a
valid new ownership proof but keeps the original controller signature. The native
prover separately rejects using the controller's private key as the note owner's
key and attempting to strip the controller from an existing controlled input.
Every on-chain rejection must leave pool state and synthetic token balances
unchanged; network gas is still charged.

The fixture controller can approve policy-compliant requests without seeing the
owner's spending key, receiving identity or Merkle paths. It sees scoped amounts,
policies, nullifiers, output commitments and withdrawal destinations. It has no
unilateral spending authority, but withholding approval can freeze funds. There
is no escape or revocation mechanism in this experiment.

## Evidence

`results/` contains local test logs. After a successful live run, `report.py`
archives receipts, proof verification, measurements and source hashes through an
explicit allowlist. `results/summary.json` is the authoritative live run outcome;
`results/measurements.md` records its resource and fee measurements.

The Sepolia run **passed** with four successful native spends, two deposits, five
adversarial on-chain rejections, and two rejected native statement executions.
Six distinct proofs were locally verified. Local validation passed 55 Python
and 68 Cairo tests. Final private balances reconcile to 1,200 pool units with
controller and policy conditions preserved.

[controlled payment](https://sepolia.voyager.online/tx/0x493cb458f647e8db63315023791eefe256efa17ddcb420fb6519fe420dde484), [controlled recovered-note spend](https://sepolia.voyager.online/tx/0x799cd54914feee7f6d05ea54db83411b5fc12b67b5c38adc7fbcb30613f2a62), [controlled restored withdrawal](https://sepolia.voyager.online/tx/0x333ec85e15371ad83d799ef0e5542f33183742454d297ced883cf41f492e443), [ordinary regression](https://sepolia.voyager.online/tx/0x58318f7eb7d0ffb5abf63c804e269a122065f21b0e6aa27cd24242dfb3bb785).

See [measurements](results/measurements.md), [receipts and outcomes](results/summary.json),
and [validation evidence](results/evidence.json). This qualifies the isolated
fixture integration, not production policy operation or desktop RAM suitability.
