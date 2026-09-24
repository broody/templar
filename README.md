# Templar

Templar is a private token pool for Starknet. Users hold tokens as private **notes**. They pay
each other by pushing notes to reusable receiving addresses, recover everything from a seed, and
can use public DeFi without revealing which notes they spend. Spending is proved on the user's
device, so no operator, auditor or screening service ever sees private data.

Templar is derived from StarkWare's
[`starkware-libs/starknet-privacy`](https://github.com/starkware-libs/starknet-privacy) and stays
compatible with its adapter interface. It makes different choices about privacy boundaries and
proving ([below](#relation-to-starknet-privacy)).

> **Status: experimental.** Everything here runs locally and, where noted, on Sepolia with
> synthetic tokens. Nothing has had an independent security audit. Do not use it with real
> value.

## What Templar offers

- **Push payments to reusable addresses.** A recipient shares one *cloaked receiving address*,
  derived locally, with no on-chain registration. Payers create notes for it and publish them
  encrypted. The recipient can be offline.
- **Private spending.** A spend proves that its notes exist in the pool's commitment tree and
  belong to the spender, without revealing which notes. Nullifiers stop double spends.
- **Seed recovery and viewing.** A wallet rebuilds its notes from its seed plus public encrypted
  history. It can grant an *incoming* viewing key (sees received notes) or a *full* viewing key
  (also sees which are spent). Neither can spend.
- **DeFi composability.** Open notes route private funds through public contracts (swaps,
  vaults) and return the proceeds as private notes in the same transaction. Shadow accounts
  hold persistent positions under a pseudonym.
- **Rule-governed assets.** Policy notes hold funds that can only move into outcomes committed in
  advance, approved by an on-chain controller, with a guaranteed refund after a deadline. They
  cover escrow, vesting and conditional payments.
- **No privileged roles.** There is no global auditor, deposit screener or proving operator.

## Note types

| Note | What it is | Spent by | Typical use |
|---|---|---|---|
| **Ordinary note** | A private claim on an amount of one token, owned by a receiving key | The owner's spending key | Payments, change, withdrawals |
| **Open note** | A destination for the proceeds of an external call, funded in the same transaction; becomes an ordinary note | (becomes ordinary once funded) | Swaps and other DeFi, returned privately |
| **Policy note** | A note spent with a per-note *capability*, only into one of up to four outcomes committed at creation | Anyone holding the capability, only as the policy allows | Escrow, vesting tranches, conditional payments, arbitration |

**Ordinary notes.** Every note is a leaf in a depth-32 append-only commitment tree:

```text
receiver   = H(OWNER, H(AUTH, sk) ‖ H(NK, sk))       // the owner's receiving identity
inner      = H(INNER, receiver ‖ rho)                // rho: fresh randomness
commitment = H(NOTE, chain ‖ pool ‖ token ‖ amount ‖ inner)
nullifier  = H(NF, nk ‖ commitment ‖ leaf position)
```

A spend proves membership of its inputs under a known root, derives their nullifiers, and
creates outputs whose values balance the inputs, as exact integers. Each output carries a
304-byte encrypted payload that its recipient decrypts.

**Open notes.** The spend's proof binds an *execution intent*: the adapter, the exact call, the
input budget, an expiry and each destination's owner and minimum amount. The pool pays the budget
and calls the adapter. It then pulls the proceeds, checks its actual balance increase, and
appends each funded note, with its commitment computed on chain from the real amount. Adapters
use upstream's interface (`privacy_invoke` returning `OpenNoteDeposit`), so upstream's Ekubo and
Vesu anonymizers work unchanged.

*Shadow accounts* reuse upstream's shadow-account anonymizer. The spender proves a pseudonymous
identity handle that only they can produce, and the anonymizer runs calls through an account
keyed by it. That account can hold a lending position or an LP share across transactions.
[Guide: open notes](docs/guide/src/pages/architecture/open-notes.mdx).

**Policy notes.** A policy note's receiver commits to a capability and a *policy*: a controller
contract (with its class hash pinned), a deadline, and up to four outcomes. An outcome is a fixed
set of outputs and a withdrawal, or a split whose amount is chosen at settlement. Settlement
proves one committed outcome. Before the deadline the controller must approve it; after the
deadline only the refund settles, with no controller involved. The depositor can hand the note's
opening to an executor, go offline, and still refund from their seed alone. A reference escrow
controller is included. [Guide: policy notes](docs/guide/src/pages/architecture/policy-notes.mdx).

## Two proving architectures

Every spend needs a zero-knowledge proof that Starknet can verify natively. Templar has built
two ways to produce one.

### 1. Full client-side proving (PROOF1)

```text
wallet: witness ─► Cairo statement ─► virtual OS run ─► S-two recursive ZK prover ─► PROOF1
                                                                                         │
Starknet: native proof verification ─► pool checks the proven result ◄───────────────────┘
```

The wallet runs the whole Cairo pipeline locally and produces a Starknet-native PROOF1, so
nothing else is involved. This path has run full lifecycles on Sepolia: offline payments,
viewing, seed recovery, recovered-note spends, withdrawals, and an Ekubo swap into a private
note. The price is weight: a prover request takes about 19–20 s and 14 GiB, or 23 s under an
8 GiB cap with bounded-memory proving. That is too heavy for a phone or a browser.

### 2. Split: compact client proof + server wrapping (PROOF2), the direction

```text
wallet (browser-class)                   wrapping server (no private data)          Starknet
──────────────────────                   ─────────────────────────────────          ────────
notes, keys, paths
     │
purpose-built M31 relation
(stwo-circuits, blinded) ──client proof──► bridge: verify it in Cairo,
public statement ─────────────────────────►  check the pinned circuit, emit a digest
                                           virtual OS ─► PROOF2 (large path) ───────► native verify
                                                                                       pool: rebuild the
                                                                                       statement, compare
```

The wallet proves only the payment rules, in a small arithmetic circuit: 2 to 5 s and about
0.3 GiB natively. A related membership proof ran in Chrome/WASM in about 2 s. The proof is
zero-knowledge before it leaves the device.

A server then verifies it inside a Cairo account and wraps that execution as a PROOF2 through
Starknet's large-proof path, which takes about 2 minutes and 28 GiB with bounded-memory storage.
The server never sees keys, notes or amounts. It can refuse or delay service, but it cannot
forge a spend or learn the witness. Anyone can run one.

| Relation | Proves |
|---|---|
| **R0** | Ordinary spends: 2 inputs, up to 2 outputs, one withdrawal, plus an open-note intent and a shadow-account handle |
| **P1** | Policy-note settlement: one committed outcome of one policy note |

Status of the split path:
- It runs end to end locally with real client proofs and real PROOF2: ordinary spends, open-note
  swaps, and policy-note release and seed-only refund.
- On Sepolia, deposits are on chain, and a proof-carrying swap through live Ekubo succeeds in
  simulation. The public gateway does not accept PROOF2 transactions yet.
- The zero-knowledge argument for the compact proof is under review. One hiding issue was found
  and fixed.

## Repository map

| Path | What is there |
|---|---|
| [`docs/guide/`](docs/guide/README.md) | **Developer guide** (Vocs site): architecture, note types, receiving and recovery, privacy, status, code map |
| [`docs/zk-guide/`](docs/zk-guide/README.md) | ZK fundamentals course: fields to STARKs to client-proof wrapping, with runnable checks |
| `docs/*-spec.md` | Specifications: [push payments](docs/push-payment-spec.md), [open notes](docs/open-note-spec.md), [policy notes](docs/policy-note-spec.md) |
| `bench/m31-private-wrapper/client-port/` | Split path, client side: the R0 and P1 relations (Rust), the Cairo bridges and statement accounts, the wallet CLI |
| `bench/m31-pool/` | Split path, pool: M31 commitment tree, spends, open notes, policy notes, escrow, wallet helpers, end-to-end drivers |
| `bench/m31-private-wrapper/proof2-large/` | Split path, server: PROOF2 wrapping, bounded-memory server build, memory profiler |
| `bench/m31-sepolia/` | Split path on Sepolia: deploy and flow scripts, archived evidence |
| `bench/push-e2e/`, `bench/controlled-push-e2e/`, `bench/return-note-e2e/` | Full client-side path: Sepolia lifecycles with native PROOF1 |
| `bench/bounded-memory/` | Coefficient-backed proving memory mode (client and server) |
| `packages/` | Earlier package implementation; not yet integrated with the current formats |
| [`TODO.md`](TODO.md) | Current priorities and open items |

Most other `bench/` directories are measurement and pathfinding records; each has a README.

## Getting started

**Toolchain.** Scarb 2.18.0 and Starknet Foundry 0.63.0 (`.tool-versions`), and Rust
`nightly-2026-01-15`. The split path's Rust crates build against a local fork of
`starkware-libs/proving` under `target/`.

```bash
# Pool contracts: spends, open notes, policy notes, escrow (snforge)
cd bench/m31-pool/cairo && snforge test

# Client relations: R0 and P1 against their native references, plus malicious witnesses
cd bench/m31-private-wrapper/client-port
RUSTUP_TOOLCHAIN=nightly-2026-01-15 cargo test --release --test payment_r0 --test policy_p1
RUSTUP_TOOLCHAIN=nightly-2026-01-15 cargo test --release --features tamper --test policy_p1_malicious

# Wallet encodings for policy notes (known-answer vectors, recovery, discovery)
cd bench/m31-pool && python3 test_policy_wallet.py

# Developer guide, locally
cd docs/guide && npm ci && npm run dev
```

**End to end with real proofs.** `bench/m31-pool/open_note_e2e.py` and
`bench/m31-pool/policy_e2e.py` run wallet → client proof → bridge → virtual OS → PROOF2 →
settlement. They need a large machine: about 28 GiB per PROOF2 in the default bounded mode.
Build the PROOF2 prover with `RUSTFLAGS="-C target-cpu=native"`; without it proving is about 1.7x
slower ([build notes](bench/m31-private-wrapper/proof2-large/README.md#build)). Run artifacts and
wallet secrets go to `~/.local/share/templar/runs`, never into the repository.

## Relation to Starknet Privacy

| | Starknet Privacy (upstream) | Templar |
|---|---|---|
| Receiving | Registered viewing keys, sender/recipient channels | Cloaked receiving addresses, no registration; payer pushes encrypted notes |
| Note storage | Notes in a contract map, read during proving | Commitments in a depth-32 tree; private membership proofs |
| Oversight | Auditor viewing-key path; deposit screening options | None; voluntary viewing keys only |
| Proving | User or proving service runs the client actions | Client proves privately; optional server only wraps an already-private proof |
| DeFi | Open notes, external invokes, `ComputeAndInvoke` / `privacy_compute` | Open notes and shadow accounts through the same adapter interface; no general `privacy_compute` |
| Governed assets | No equivalent | Policy notes with an on-chain controller and deadline refund |

The [comparison page](docs/guide/src/pages/comparison.mdx) in the guide goes into detail.

## Security and limitations

- **No audit.** The relations, contracts and wallet encodings have had internal reviews, not an
  external audit.
- **Hiding of the compact client proof** is still being qualified.
- **Wallet keys** in the split-path demos use fixture derivations, not a production key and
  backup standard.
- **PROOF2** is not yet accepted by the public Sepolia gateway, and not enabled on mainnet.
- **Public metadata:** submission, gas funding, RPC access and timing can still correlate
  activity. An open note makes funding private; it does not make the swap itself private.
- **Operator trust:** pool owners can currently change verifiers and allowlists.

## License

Derived code in `bench/` is Apache-2.0, from `starkware-libs/starknet-privacy`.
