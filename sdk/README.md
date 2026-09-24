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
await spend.prove();                                   // client proof in a worker (~6 s in WASM)
await spend.wrap(tpl.prover({ url }), { url });        // the server's large proof and facts, checked
const { transactionHash, linkable } = await spend.submit(relayerAccount);
```

The core needs WebAssembly with 128-bit SIMD (Chrome and Edge 91+, Firefox 89+, Safari 16.4+, Node);
`loadCore()` refuses other runtimes with `unsupported_browser`. There is no scalar fallback build.

Submission uses a signer-backed starknet.js `Account`; its address is public and linked to the
spend (`linkable: true` in v1: use a relayer's account for unlinkability). Browser-extension
wallets are not supported as submitters in v1.

## Status (2026-09-24)

| | Result |
| --- | --- |
| WASM build | 48 s release build, 7.8 MB `.wasm` (circuit prover without `stwo_cairo_prover`, fork `250cc9c`) |
| Client proof in WASM | Byte-identical to native (`vectors/determinism.json`); with 128-bit SIMD (the default build): Node 6.1 s, Chrome 153 6.1 s / 256 MiB linear memory, three runs; without SIMD it was 19–20 s. Native: 5.3 s on one thread, 1.0 s on 36 ([`results/milestone-0.json`](results/milestone-0.json)) |
| Deployed bridge | WASM- and core-made proofs pass `templar-prover check` against the deployed R4 bridge build |
| Sepolia S1 known answers | Binding, all 90 calldata felts, message hash and facts reproduce the real S1 spend (`vectors/sepolia-s1.json`) |
| Independent reference | `vectors/check_keys.py` recomputes every key, address, viewing key, fingerprint, store key and sealed box (libsodium) |
| Sepolia, read-only | Pins verified on chain; full sync of pool V2 complete (local root equals the pool's), one bulk `getEvents` |
| Sepolia, funded (2026-09-25) | With the SDK alone ([`results/sepolia-e2e.json`](results/sepolia-e2e.json)): a live deposit; sync and seed-only recovery complete; a hidden transfer proved in WASM (31 s, Node) and wrapped through OHTTP (100 s), then a re-plan of the same note as a withdrawal. Both exact signed transactions pass simulation with validation (135.1M and 136.1M L2 gas, 3.36 and 3.39 STRK); the real account accepts the query-version estimate; the gateway refuses both because it does not accept PROOF2 |
| Tests | 20 core tests (unit, rejection sweeps, every scan rule, spend rules, S1, determinism, key vectors) and a WASM serialization test; 17 TypeScript tests against a mock pool, prover and account (receive, hidden transfer proved in a worker, wrap and re-wrap, re-plan, submit sequence, settlement by an earlier attempt, network trace, reorgs, dropped and tampered leaves, record locking, eviction and resume, deposits and recipients, OHTTP, gap recovery, stores, a malformed-input sweep of every WASM export) |
| Reviews | Design: math GO, protocol GO (three rounds). Implementation: math GO, protocol GO ([`docs/reviews/sdk-impl-*`](../docs/reviews/)) |

Not yet done: inclusion of a spend (the Sepolia gateway does not accept large proofs yet); an OHTTP
run through a third-party relay; a mobile-browser measurement; `wasm-opt`.

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
