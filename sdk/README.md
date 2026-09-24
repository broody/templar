# Templar client SDK

The client side of Templar's compact client-proof path: a Rust core compiled to WebAssembly
(`core/`, `wasm/`) and a TypeScript package over starknet.js (`ts/`, `@templar/sdk`). Design:
[`docs/sdk-spec.md`](../docs/sdk-spec.md), reviewed in
[`docs/reviews/sdk-design-math-review.md`](../docs/reviews/sdk-design-math-review.md) and
[`docs/reviews/sdk-design-protocol-review.md`](../docs/reviews/sdk-design-protocol-review.md).

**Private and unreleased.** The client proof is built from the arithmetic-profile fork of
`proving` (private `broody/proving-private`, `templar/arithmetic-profile`), which carries an
unreleased prover fix; releasing the package is gated on it (spec §13). Nothing is published.

## What it does

- **Keys.** A 32-byte seed with a 24-word backup; per pool and account, spending, incoming and
  store keys (spec §3). Keys stay inside the core; JavaScript holds only the seed.
- **Addresses.** `templarsep1…` receiving addresses and viewing keys (F4Jumble and Bech32m, typed),
  with a fingerprint for out-of-band checks (spec §4).
- **Receiving.** Bulk pool events only, trial decryption with every rule checked before hashing,
  completeness against the pool's leaf count and root, checkpoints and reorg rollback (spec §6).
- **Deposits** of ERC20, ERC721 and ERC1155 assets as notes for any address (spec §7.1).
- **Spends.** Hidden-asset transfers, withdrawals and consolidations, proved in a worker (a fresh
  WASM instance each), wrapped by a [prover server](../server/README.md) directly or through an
  OHTTP relay, and sent as the exact simulated transaction (spec §7–§9).
- **In-flight records.** Once a spend's statement leaves the wallet its notes stay bound to it
  until its root is evicted; re-plans reuse the same inputs and dummy, so at most one attempt can
  settle (spec §9.1).
- **Storage** encrypted at rest under a seed-derived key (spec §10.3).

```ts
import { RpcProvider, Account } from 'starknet';
import { Templar, SEPOLIA, FileKV } from '@templar/sdk';

const tpl = await Templar.connect({ provider: new RpcProvider({ nodeUrl }), network: SEPOLIA, kv: new FileKV(dir) });
const wallet = await tpl.wallet(Templar.seedFromMnemonic(words));
const { address, fingerprint } = await wallet.address(0);
await wallet.sync();                                   // { complete, block, balances, problems }
await wallet.deposit(account, { asset: { standard: 20, contract: token }, amount: 1000n });
const spend = await wallet.transfer(token, 600n, bobAddress);
await spend.prove();                                   // client proof in a worker (~20 s in WASM)
await spend.wrap(tpl.prover({ url }), { url });        // the server's large proof and facts, checked
const { transactionHash, linkable } = await spend.submit(relayerAccount);
```

Submission uses a signer-backed starknet.js `Account`; its address is public and linked to the
spend (`linkable: true` in v1: use a relayer's account for unlinkability). Browser-extension
wallets are not supported as submitters in v1.

## Status (2026-09-24)

| | Result |
| --- | --- |
| WASM build | 48 s release build, 7.8 MB `.wasm` (circuit prover without `stwo_cairo_prover`, fork `250cc9c`) |
| Client proof in WASM | Byte-identical to native (`vectors/determinism.json`); Node 20.3 s / 332 MiB RSS; Chrome 153 18.1 s / 257 MiB linear memory, three runs ([`results/milestone-0.json`](results/milestone-0.json)) |
| Deployed bridge | WASM- and core-made proofs pass `templar-prover check` against the deployed R4 bridge build |
| Sepolia S1 known answers | Binding, all 90 calldata felts, message hash and facts reproduce the real S1 spend (`vectors/sepolia-s1.json`) |
| Independent reference | `vectors/check_keys.py` recomputes every key, address, viewing key, fingerprint, store key and sealed box (libsodium) |
| Sepolia, read-only | Pins verified on chain; full sync of pool V2 complete (local root equals the pool's), one bulk `getEvents` |
| Tests | 16 core tests (unit, S1, determinism, spend flow, key vectors); 8 TypeScript tests against a mock pool (receive, hidden transfer in a worker, network trace, reorgs, conflicts, record locking and eviction) |

Not yet done: a funded end-to-end run on Sepolia with the SDK alone (needs a live deposit, and the
gateway still rejects large proofs, so the spend is simulated); a mobile-browser measurement;
`wasm-opt`.

## Build and test

```bash
sdk/scripts/check-pins.sh                    # the fork checkout, relation sources, toolchain, wasm-bindgen
sdk/scripts/build-wasm.sh                    # ts/wasm (release) and ts/wasm-test (seeded exports, tests only)
cd sdk && cargo test --release -p templar-core
python3 sdk/vectors/check_keys.py            # independent reference
cd sdk/ts && npm ci && npx tsc -p tsconfig.json && npx vitest run
node sdk/ts/bench/browser.mjs OUT.json 3     # Chrome measurement (system Chrome)
node sdk/ts/bench/sepolia-readonly.mjs       # read-only Sepolia check (STARKNET_RPC)
```

The fork must be checked out at `target/proving-arith`
(`git clone -b templar/arithmetic-profile https://github.com/broody/proving-private.git target/proving-arith`).
The toolchain is `nightly-2026-01-15` with the `wasm32-unknown-unknown` target; `wasm-bindgen`
CLI 0.2.128.
