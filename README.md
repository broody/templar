# Templar

A private token pool for Starknet with push payments to reusable cloaked receiving
addresses, derived from
[`starkware-libs/starknet-privacy`](https://github.com/starkware-libs/starknet-privacy).

**Architecture guide: [Vocs source and local preview](docs/guide/README.md)**  
**Current specification: [push payments](docs/push-payment-spec.md)**  
**Architecture decisions: [docs/adr/](docs/adr/README.md)**  
**Current priorities: [TODO.md](TODO.md)**  
**Live evidence: [push-payment and recovery lifecycle](bench/push-e2e/README.md)**

**Go-to-market: [internal strategy draft](docs/gtm-strategy.md)**

## Architecture

Recipients share an address once and can receive while offline. Payers create
fresh recipient-owned notes and publish their encrypted contents with the funded
commitments. Wallets discover payments and restore from seed plus public encrypted
history. Optional incoming and full viewing capabilities disclose information
without granting spending authority.

The holder proves spends locally using the S-two recursive zero-knowledge privacy
pipeline. Starknet verifies native PROOF1 proofs; the pool binds their results to
exact nullifiers, encrypted outputs, and withdrawals. No global auditor,
deposit screener, or proving operator needs access to the private witness.

The payment model supports ordinary push payments and optional controlled notes.
Controlled value requires both an ownership proof and policy approval. [Return notes](docs/return-note-spec.md) support proof-authorized external
operations and atomic return to ordinary notes. Persistent delivery channels and
asynchronous external positions are outside the initial scope. Pool configuration authority, RPC trust, compatible token
behavior, and historical data availability remain explicit dependencies.

## Status

As of 2026-09-21, [ADR-0018](docs/adr/0018-stwo-private-proving.md) selects native
S-two proving and [ADR-0021](docs/adr/0021-push-only-payments.md) accepts the
push-only architecture. The ordinary-note experiment in `bench/push-e2e/`
demonstrates two offline payments to one address, full viewing, seed recovery,
recovered-note spending, and withdrawals on Sepolia. It records four successful
native spends, two funded deposits, three rejected adversarial transactions,
and 59 Python plus 59 Cairo tests.

[ADR-0022](docs/adr/0022-controlled-push-payments.md) defines optional controlled
push payments. The [controlled experiment](bench/controlled-push-e2e/README.md)
completes the same offline receiving and recovery flow with real controller
signatures and native proofs. It records four successful spends, five adversarial
on-chain rejections, two rejected native statement executions, and 55 Python plus
68 Cairo tests. Approval binds actual withdrawal destinations and ciphertext
digests; a controller signature cannot replace the owner’s spending key.

Measured prover requests took 18.9–19.9 seconds and 13.9–14.0 GiB peak RSS on
four physical cores of a larger host with a 16 GiB process cap. This does not
qualify a normal desktop with 16 GiB total RAM. The guide's
[status source](docs/guide/src/pages/status.mdx) records the measurement scope,
RPC-based recovery limits, and outstanding work.

[Native shape pathfinding](docs/native-shape-review.md) verifies larger synthetic
statements and compares padding with counted active entries. The live pool remains
at 4/4/2 while settlement and desktop limits are qualified.

An isolated [ordinary-note DeFi experiment](bench/defi-return-e2e/README.md)
demonstrates atomic swaps through Ekubo's deployed Sepolia contracts, recoverable
returns with amounts determined at settlement, and subsequent native spending.
It uses synthetic tokens and requires no controller. The
[reassessment](docs/defi-return-review.md) records the evidence and remaining
integration work. [ADR-0023](docs/adr/0023-return-notes-and-adapter-compatibility.md)
accepts return notes and the upstream-compatible adapter interface, implemented
in the separate [return-note reference](bench/return-note-e2e/README.md). It passes
two native spends through unchanged upstream Ekubo integration and a recovered-note
private payment on Sepolia, plus six adversarial transaction rejections.

Production packages are not yet integrated with the push format. Independent
cryptographic review, wallet/backup standards, scalable private synchronization,
desktop qualification, governance, and production token validation remain open.
Existing package semantics are preserved in
[the package-format specification](docs/pool-v2-spec.md); the
[development plan](PLAN.md) and benchmark directories retain engineering records.

## License

Derived code in `bench/` is Apache-2.0, from starkware-libs/starknet-privacy.
